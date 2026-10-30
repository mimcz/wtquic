/*
 * Environment keepalive: the QUIC_SETTINGS that reach the real
 * ConfigurationOpen of a client connect and of a listener start, for every
 * way an environment config can carry keep_alive_interval_ms, and the exact
 * bytes the environment config initialisers write.
 *
 * The environment borrows a fake API table, so wtquic's own client and
 * listener code makes the ConfigurationOpen call recorded here. The fake then
 * refuses the credential, so each attempt ends synchronously before any
 * connection or listener exists. Only the public API is used.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <wtquic/wtquic_msquic.h>

#include "test_support.h"

/* The environment config exactly as it stood before keep_alive_interval_ms:
 * what an older caller allocates and passes. */
typedef struct legacy_env_cfg {
    uint32_t struct_size;
    const wtq_alloc_t *alloc;
    const QUIC_API_TABLE *existing_api;
    HQUIC existing_registration;
    const char *app_name;
    wtq_msquic_tuning_t tuning;
} legacy_env_cfg_t;

_Static_assert(offsetof(wtq_msquic_env_cfg_t, keep_alive_interval_ms) >=
                   sizeof(legacy_env_cfg_t),
               "keep_alive_interval_ms must lie past the legacy sizeof");

#define KA_OFF offsetof(wtq_msquic_env_cfg_t, keep_alive_interval_ms)
#define CANARY 0xEEu
#define CANARY_LEN 32u

static QUIC_SETTINGS g_settings;
static uint32_t g_settings_size;
static unsigned g_opens;
static unsigned g_closes;

static QUIC_STATUS QUIC_API cap_config_open(HQUIC reg, const QUIC_BUFFER *alpn,
    uint32_t alpn_count, const QUIC_SETTINGS *settings, uint32_t size,
    void *ctx, HQUIC *out)
{
    (void)reg; (void)alpn; (void)alpn_count; (void)ctx;
    g_opens++;
    memset(&g_settings, 0, sizeof(g_settings));
    g_settings_size = size;
    if (settings != NULL && size >= sizeof(g_settings))
        memcpy(&g_settings, settings, sizeof(g_settings));
    *out = (HQUIC)0x21;
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS QUIC_API cap_load_credential(HQUIC config,
    const QUIC_CREDENTIAL_CONFIG *cred)
{
    (void)config; (void)cred;
    return QUIC_STATUS_INVALID_PARAMETER;
}

static void QUIC_API cap_config_close(HQUIC config)
{
    (void)config;
    g_closes++;
}

static QUIC_API_TABLE g_api;

static void fake_api_init(void)
{
    memset(&g_api, 0, sizeof(g_api));
    g_api.ConfigurationOpen = cap_config_open;
    g_api.ConfigurationLoadCredential = cap_load_credential;
    g_api.ConfigurationClose = cap_config_close;
}

/* The settings each path passed to ConfigurationOpen. */
struct capture {
    QUIC_SETTINGS client;
    QUIC_SETTINGS listener;
};

/* Open an environment from `cfg` (any caller size), then drive one client
 * connect and one listener start into ConfigurationOpen. Both attempts are
 * expected to stop at the refused credential. */
static int capture_paths(const wtq_msquic_env_cfg_t *cfg, struct capture *out)
{
    int failures = 0;
    wtq_msquic_env_t *env = NULL;

    memset(out, 0, sizeof(*out));
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(cfg, &env), WTQ_OK);
    if (env == NULL)
        return failures + 1;

    wtq_session_events_t ev;
    wtq_session_events_init(&ev);
    wtq_connect_config_t cc = WTQ_CONNECT_CONFIG_INIT;
    cc.authority = "localhost";
    cc.path = "/ka";
    wtq_msquic_client_cfg_t ccfg;
    wtq_msquic_client_cfg_init(&ccfg);
    ccfg.server_name = "127.0.0.1";
    ccfg.port = 443;
    ccfg.insecure_skip_verify = true;
    ccfg.connect = &cc;
    ccfg.events = &ev;

    unsigned opens = g_opens, closes = g_closes;
    wtq_session_t *session = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_client_connect(env, &ccfg, &session),
                          WTQ_ERR_BACKEND);
    WTQ_TEST_CHECK(session == NULL);
    WTQ_TEST_CHECK_EQ_INT(g_opens, opens + 1);
    WTQ_TEST_CHECK_EQ_INT(g_closes, closes + 1);
    WTQ_TEST_CHECK_EQ_INT(g_settings_size, sizeof(QUIC_SETTINGS));
    out->client = g_settings;

    static const char *const protos[] = { "wtq-test" };
    wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
    serve.path = "/ka";
    serve.subprotocols = protos;
    serve.subprotocol_count = 1;
    wtq_msquic_listener_cfg_t lcfg;
    wtq_msquic_listener_cfg_init(&lcfg);
    lcfg.bind_address = "127.0.0.1";
    lcfg.cert_file = "unused-cert.pem";
    lcfg.key_file = "unused-key.pem";
    lcfg.paths = &serve;
    lcfg.path_count = 1;
    lcfg.events = &ev;

    opens = g_opens;
    closes = g_closes;
    wtq_msquic_listener_t *listener = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_listener_start(env, &lcfg, &listener),
                          WTQ_ERR_BACKEND);
    WTQ_TEST_CHECK(listener == NULL);
    WTQ_TEST_CHECK_EQ_INT(g_opens, opens + 1);
    WTQ_TEST_CHECK_EQ_INT(g_closes, closes + 1);
    WTQ_TEST_CHECK_EQ_INT(g_settings_size, sizeof(QUIC_SETTINGS));
    out->listener = g_settings;

    wtq_msquic_env_close(env);
    return failures;
}

/* Both paths carry the same keepalive outcome: set to `value`, or unset. */
static int check_keep_alive(const struct capture *c, bool set, uint32_t value)
{
    int failures = 0;
    const QUIC_SETTINGS *paths[2] = { &c->client, &c->listener };

    for (size_t i = 0; i < 2; ++i) {
        WTQ_TEST_CHECK_EQ_INT((int)paths[i]->IsSet.KeepAliveIntervalMs,
                              set ? 1 : 0);
        WTQ_TEST_CHECK_EQ_U64(paths[i]->KeepAliveIntervalMs, set ? value : 0);
    }
    return failures;
}

/* Everything but keepalive is identical to `base`, on both paths. */
static int check_rest_equal(const struct capture *c, const struct capture *base)
{
    int failures = 0;
    struct capture a = *c, b = *base;
    QUIC_SETTINGS *s[4] = { &a.client, &a.listener, &b.client, &b.listener };

    for (size_t i = 0; i < 4; ++i) {
        s[i]->IsSet.KeepAliveIntervalMs = FALSE;
        s[i]->KeepAliveIntervalMs = 0;
    }
    WTQ_TEST_CHECK(memcmp(&a.client, &b.client, sizeof(a.client)) == 0);
    WTQ_TEST_CHECK(memcmp(&a.listener, &b.listener, sizeof(a.listener)) == 0);
    return failures;
}

/* A posture with every tuning field away from its default. */
static void nondefault_tuning(wtq_msquic_tuning_t *t)
{
    wtq_msquic_tuning_init(t);
    t->send_buffering = true;
    t->peer_unidi_stream_count = 20;
    t->peer_bidi_stream_count = 9;
    t->stream_recv_window = 1u << 20;
    t->conn_flow_control_window = 2u << 20;
    t->datagram_receive_enabled = false;
    t->idle_timeout_ms = 12345;
}

/* The nondefault posture reached ConfigurationOpen on both paths. */
static int check_nondefault_tuning(const struct capture *c)
{
    int failures = 0;
    const QUIC_SETTINGS *paths[2] = { &c->client, &c->listener };

    for (size_t i = 0; i < 2; ++i) {
        const QUIC_SETTINGS *s = paths[i];
        WTQ_TEST_CHECK(s->IsSet.SendBufferingEnabled && s->SendBufferingEnabled);
        WTQ_TEST_CHECK(s->IsSet.PeerUnidiStreamCount);
        WTQ_TEST_CHECK_EQ_INT(s->PeerUnidiStreamCount, 20);
        WTQ_TEST_CHECK(s->IsSet.PeerBidiStreamCount);
        WTQ_TEST_CHECK_EQ_INT(s->PeerBidiStreamCount, 9);
        WTQ_TEST_CHECK(s->IsSet.StreamRecvWindowDefault);
        WTQ_TEST_CHECK_EQ_U64(s->StreamRecvWindowDefault, 1u << 20);
        WTQ_TEST_CHECK(s->IsSet.ConnFlowControlWindow);
        WTQ_TEST_CHECK_EQ_U64(s->ConnFlowControlWindow, 2u << 20);
        WTQ_TEST_CHECK(s->IsSet.DatagramReceiveEnabled &&
                       !s->DatagramReceiveEnabled);
        WTQ_TEST_CHECK(s->IsSet.IdleTimeoutMs);
        WTQ_TEST_CHECK_EQ_U64(s->IdleTimeoutMs, 12345);
    }
    return failures;
}

static void borrow_fake(wtq_msquic_env_cfg_t *cfg)
{
    cfg->existing_api = &g_api;
    cfg->existing_registration = (HQUIC)0x10;
}

/* The full-size config from the macro, the compound literal and _ex all
 * cover the field: its default 0 is passed as set (explicitly disabled). */
static int test_current_initializers_disable_explicitly(struct capture *base)
{
    int failures = 0;
    struct capture c;

    wtq_msquic_env_cfg_t a;
    memset(&a, 0xA5, sizeof(a));
    wtq_msquic_env_cfg_init(&a);
    WTQ_TEST_CHECK_EQ_SIZE(a.struct_size, sizeof(a));
    WTQ_TEST_CHECK_EQ_U64(a.keep_alive_interval_ms, 0);
    borrow_fake(&a);
    failures += capture_paths(&a, &c);
    failures += check_keep_alive(&c, true, 0);
    *base = c;

    wtq_msquic_env_cfg_t b = WTQ_MSQUIC_ENV_CFG_INIT;
    WTQ_TEST_CHECK_EQ_SIZE(b.struct_size, sizeof(b));
    borrow_fake(&b);
    failures += capture_paths(&b, &c);
    failures += check_keep_alive(&c, true, 0);
    failures += check_rest_equal(&c, base);

    wtq_msquic_env_cfg_t e;
    memset(&e, 0xA5, sizeof(e));
    wtq_msquic_env_cfg_init_ex(&e, sizeof(e));
    WTQ_TEST_CHECK_EQ_SIZE(e.struct_size, sizeof(e));
    borrow_fake(&e);
    failures += capture_paths(&e, &c);
    failures += check_keep_alive(&c, true, 0);
    failures += check_rest_equal(&c, base);
    return failures;
}

/* Covered nonzero values pass through unchanged, across the full range, and
 * touch no other setting. The reserved slot is never read. */
static int test_covered_values(const struct capture *base)
{
    int failures = 0;
    static const uint32_t values[] = { 1u, 15000u, UINT32_MAX };

    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        wtq_msquic_env_cfg_t cfg;
        struct capture c;
        wtq_msquic_env_cfg_init(&cfg);
        borrow_fake(&cfg);
        cfg._reserved_keep_alive = 0xDEADBEEFu;
        cfg.keep_alive_interval_ms = values[i];
        failures += capture_paths(&cfg, &c);
        failures += check_keep_alive(&c, true, values[i]);
        failures += check_rest_equal(&c, base);
    }
    return failures;
}

/* An older caller's object followed by a suffix canary, filled by the frozen
 * bare initialiser (called directly and through its address), with
 * nondefault tuning and poisoned tail padding: keepalive stays unset, the
 * tuning arrives intact, and nothing past the object is written. The canary
 * detects writes only; test_exact_legacy_object bounds the reads. */
static int test_legacy_object(void)
{
    int failures = 0;
    void (*bare)(wtq_msquic_env_cfg_t *) = wtq_msquic_env_cfg_init;

    for (int via_pointer = 0; via_pointer < 2; ++via_pointer) {
        const size_t sz = sizeof(legacy_env_cfg_t);
        unsigned char *buf = malloc(sz + CANARY_LEN);
        WTQ_TEST_CHECK(buf != NULL);
        if (buf == NULL)
            return failures;
        memset(buf, CANARY, sz + CANARY_LEN);
        wtq_msquic_env_cfg_t *cfg = (wtq_msquic_env_cfg_t *)(void *)buf;
        if (via_pointer)
            bare(cfg);
        else
            (wtq_msquic_env_cfg_init)(cfg);
        WTQ_TEST_CHECK_EQ_SIZE(cfg->struct_size, sz);
        for (size_t i = sz; i < sz + CANARY_LEN; ++i)
            WTQ_TEST_CHECK_EQ_INT(buf[i], CANARY);

        legacy_env_cfg_t *legacy = (legacy_env_cfg_t *)(void *)buf;
        legacy->existing_api = &g_api;
        legacy->existing_registration = (HQUIC)0x10;
        nondefault_tuning(&legacy->tuning);
        /* Whatever an old caller left in its trailing padding. */
        size_t tail = offsetof(legacy_env_cfg_t, tuning) +
                      sizeof(wtq_msquic_tuning_t);
        memset(buf + tail, 0xA5, sz - tail);

        struct capture c;
        failures += capture_paths(cfg, &c);
        failures += check_keep_alive(&c, false, 0);
        failures += check_nondefault_tuning(&c);
        for (size_t i = sz; i < sz + CANARY_LEN; ++i)
            WTQ_TEST_CHECK_EQ_INT(buf[i], CANARY);
        free(buf);
    }
    return failures;
}

/* An older caller's object allocated at exactly its historical size, so
 * any read past it trips ASan: filled by the frozen bare initialiser (called
 * directly and through its address) with nondefault tuning, then opened and
 * driven into both ConfigurationOpen calls. Keepalive stays unset and the
 * tuning arrives intact. */
static int test_exact_legacy_object(void)
{
    int failures = 0;
    void (*bare)(wtq_msquic_env_cfg_t *) = wtq_msquic_env_cfg_init;

    for (int via_pointer = 0; via_pointer < 2; ++via_pointer) {
        legacy_env_cfg_t *legacy = malloc(sizeof(legacy_env_cfg_t));
        WTQ_TEST_CHECK(legacy != NULL);
        if (legacy == NULL)
            return failures;
        wtq_msquic_env_cfg_t *cfg = (wtq_msquic_env_cfg_t *)(void *)legacy;
        if (via_pointer)
            bare(cfg);
        else
            (wtq_msquic_env_cfg_init)(cfg);
        WTQ_TEST_CHECK_EQ_SIZE(legacy->struct_size, sizeof(legacy_env_cfg_t));
        legacy->existing_api = &g_api;
        legacy->existing_registration = (HQUIC)0x10;
        nondefault_tuning(&legacy->tuning);

        struct capture c;
        failures += capture_paths(cfg, &c);
        failures += check_keep_alive(&c, false, 0);
        failures += check_nondefault_tuning(&c);
        free(legacy);
    }
    return failures;
}

/* A caller object that ends exactly at the end of the field -- before the
 * current struct's own tail padding on LP64 -- covers it: the value is
 * honored on both paths. The object is exactly that size. */
static int test_exact_full_field(void)
{
    int failures = 0;
    const size_t sz = KA_OFF + sizeof(uint32_t);
    const uint32_t value = 15000;
    unsigned char *buf = malloc(sz);
    WTQ_TEST_CHECK(buf != NULL);
    if (buf == NULL)
        return failures;
    wtq_msquic_env_cfg_t *cfg = (wtq_msquic_env_cfg_t *)(void *)buf;
    wtq_msquic_env_cfg_init_ex(cfg, sz);
    WTQ_TEST_CHECK_EQ_SIZE(cfg->struct_size, sz);
    borrow_fake(cfg);
    nondefault_tuning(&cfg->tuning);
    memcpy(buf + KA_OFF, &value, sizeof(value));

    struct capture c;
    failures += capture_paths(cfg, &c);
    failures += check_keep_alive(&c, true, value);
    failures += check_nondefault_tuning(&c);
    free(buf);
    return failures;
}

/* A struct_size ending before or inside the field leaves keepalive unset,
 * whatever bytes the partial field holds. The object is exactly that size. */
static int test_partial_field_is_absent(void)
{
    int failures = 0;

    for (size_t extra = 0; extra < sizeof(uint32_t); ++extra) {
        const size_t sz = KA_OFF + extra;
        unsigned char *buf = malloc(sz);
        WTQ_TEST_CHECK(buf != NULL);
        if (buf == NULL)
            return failures;
        wtq_msquic_env_cfg_t *cfg = (wtq_msquic_env_cfg_t *)(void *)buf;
        wtq_msquic_env_cfg_init_ex(cfg, sz);
        WTQ_TEST_CHECK_EQ_SIZE(cfg->struct_size, sz);
        memset(buf + KA_OFF, 0xFF, extra);
        borrow_fake(cfg);
        nondefault_tuning(&cfg->tuning);

        struct capture c;
        failures += capture_paths(cfg, &c);
        failures += check_keep_alive(&c, false, 0);
        failures += check_nondefault_tuning(&c);
        free(buf);
    }
    return failures;
}

/* A larger struct_size than this library knows: the covered field is
 * honored and the unknown tail ignored. */
static int test_oversized_config(const struct capture *base)
{
    int failures = 0;
    const size_t sz = sizeof(wtq_msquic_env_cfg_t) + 64;
    unsigned char *buf = malloc(sz);
    WTQ_TEST_CHECK(buf != NULL);
    if (buf == NULL)
        return failures;
    memset(buf, 0xC3, sz);
    wtq_msquic_env_cfg_t *cfg = (wtq_msquic_env_cfg_t *)(void *)buf;
    wtq_msquic_env_cfg_init(cfg);
    cfg->struct_size = (uint32_t)sz;
    borrow_fake(cfg);
    cfg->keep_alive_interval_ms = 4321;

    struct capture c;
    failures += capture_paths(cfg, &c);
    failures += check_keep_alive(&c, true, 4321);
    failures += check_rest_equal(&c, base);
    free(buf);
    return failures;
}

/* _ex writes nothing below the size that holds struct_size, otherwise
 * exactly the clamped size, stamps it, and never writes past it. */
static int test_init_ex_bounds(void)
{
    int failures = 0;
    const size_t full = sizeof(wtq_msquic_env_cfg_t);
    const size_t sizes[] = { 0, 1, 2, 3, 4, KA_OFF, KA_OFF + 2, full,
                             full + 16 };
    const wtq_msquic_env_cfg_t def = WTQ_MSQUIC_ENV_CFG_INIT;

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        unsigned char buf[sizeof(wtq_msquic_env_cfg_t) + 16 + CANARY_LEN];
        size_t want = sizes[i] < full ? sizes[i] : full;
        if (want < sizeof(uint32_t))
            want = 0;
        memset(buf, CANARY, sizeof(buf));
        wtq_msquic_env_cfg_init_ex((wtq_msquic_env_cfg_t *)(void *)buf,
                                   sizes[i]);
        for (size_t j = want; j < sizeof(buf); ++j)
            WTQ_TEST_CHECK_EQ_INT(buf[j], CANARY);
        if (want == 0)
            continue;
        uint32_t stamped;
        memcpy(&stamped, buf, sizeof(stamped));
        WTQ_TEST_CHECK_EQ_SIZE(stamped, want);
        WTQ_TEST_CHECK(memcmp(buf + sizeof(uint32_t),
                              (const unsigned char *)&def + sizeof(uint32_t),
                              want - sizeof(uint32_t)) == 0);
    }

    wtq_msquic_env_cfg_init_ex(NULL, full);
    wtq_msquic_env_cfg_init(NULL);
    (wtq_msquic_env_cfg_init)(NULL);
    return failures;
}

int main(void)
{
    int failures = 0;
    struct capture base;

    fake_api_init();
    failures += test_current_initializers_disable_explicitly(&base);
    failures += test_covered_values(&base);
    failures += test_legacy_object();
    failures += test_exact_legacy_object();
    failures += test_exact_full_field();
    failures += test_partial_field_is_absent();
    failures += test_oversized_config(&base);
    failures += test_init_ex_bounds();
    WTQ_TEST_PASS("msquic_keepalive");
    return failures ? 1 : 0;
}
