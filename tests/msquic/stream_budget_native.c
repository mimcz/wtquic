/* Real MsQuic loopback, public API only: mixed persistent load makes progress.
 *
 * A draft-18-shaped publisher session at the default native grants (U=8,
 * B=7). The client keeps three request bidi streams, a small announce uni
 * stream and a catalog uni stream open without FIN; the server answers every
 * request on its own bidi and keeps one local uni stream open. With all of
 * that still live, the client then sends three complete video uni streams.
 * The oracle is the server receiving each video exactly once, every byte and
 * FIN, and the client receiving each request reply exactly once and the
 * server's local bytes, before any persistent stream finishes and before the
 * session ends. Delivery is matched per identity: a duplicated payload never
 * stands in for a missing one (checked first, on synthetic records).
 *
 * The videos arrive while one of the server's two local reservations is in
 * use. Then, with every peer uni reservation resident (three critical streams
 * plus five retained WT handles), a second server-local open still succeeds
 * and the third, past max_local_streams=2, returns WOULD_BLOCK with NULL
 * output: peer occupancy does not consume local reservations. Peer admission
 * while every local reservation is held is covered by the fake-pair rows in
 * msquic_ops, not here. */
#if defined(__linux__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <wtquic/session.h>
#include <wtquic/stream.h>
#include <wtquic/wtquic_msquic.h>

#include "test_support.h"

enum {
    REQUESTS = 3,
    VIDEOS = 3,
    VIDEO_BYTES = 3000,
    SERVER_LOCALS = 2,
    RECORDS = 16,
    RECORD_BYTES = 4096,
};

static const uint8_t request_bytes[REQUESTS][4] = {
    { 'R', '0', 'q', 0 }, { 'R', '1', 'q', 0 }, { 'R', '2', 'q', 0 } };
static const uint8_t reply_bytes[REQUESTS][4] = {
    { 'P', '0', 'r', 0 }, { 'P', '1', 'r', 0 }, { 'P', '2', 'r', 0 } };
static const uint8_t announce_bytes[2] = { 'A', 1 };
static const uint8_t catalog_bytes[12] = {
    'C', '{', '"', 't', 'r', 'a', 'c', 'k', 's', '"', ':', '}' };
static const uint8_t server_local_bytes[3] = { 'S', 'R', 'V' };
static uint8_t video_bytes[VIDEOS][VIDEO_BYTES];

struct record {
    wtq_stream_t *stream;
    size_t len;
    bool fin;
    bool peer;
    bool finishes; /* a complete video group; everything else is persistent */
    uint8_t bytes[RECORD_BYTES];
};

struct side {
    pthread_mutex_t lane;
    pthread_cond_t changed;
    wtq_session_t *session;
    struct record records[RECORDS];
    unsigned record_count;
    unsigned persistent_closed;
    bool server, established, ended;
    int errors;
};

static void enter(void *ctx) { pthread_mutex_lock(&((struct side *)ctx)->lane); }
static void leave(void *ctx)
{
    struct side *s = ctx;
    pthread_cond_broadcast(&s->changed);
    pthread_mutex_unlock(&s->lane);
}

static struct record *track(struct side *s, wtq_stream_t *st, bool peer)
{
    if (s->record_count == RECORDS) { s->errors++; return NULL; }
    struct record *r = &s->records[s->record_count++];
    r->stream = st;
    r->peer = peer;
    wtq_stream_add_ref(st); /* retained: a peer record stays resident */
    wtq_stream_set_user(st, r);
    return r;
}

static void established(wtq_session_t *session, wtq_str_t sub, void *ctx)
{
    (void)sub;
    struct side *s = ctx;
    s->established = true;
    if (s->server) { s->session = session; wtq_session_add_ref(session); }
}

static void opened(wtq_session_t *session, wtq_stream_t *st, bool bidi, void *ctx)
{
    (void)session; (void)bidi;
    (void)track(ctx, st, true);
}

static void data(wtq_session_t *session, wtq_stream_t *st, const uint8_t *bytes,
                 size_t len, bool fin, void *ctx)
{
    (void)session;
    struct side *s = ctx;
    struct record *r = wtq_stream_get_user(st);
    if (r == NULL || r->fin || len > RECORD_BYTES - r->len) { s->errors++; return; }
    if (len) memcpy(r->bytes + r->len, bytes, len);
    r->len += len;
    r->fin = fin;
}

static void stream_closed(wtq_session_t *session, wtq_stream_t *st, void *ctx)
{
    (void)session;
    struct side *s = ctx;
    const struct record *r = wtq_stream_get_user(st);
    /* Requests, announce, catalog and server-local streams never finish. */
    if (r == NULL || !(r->finishes || (r->peer && r->len && r->bytes[0] == 'V')))
        s->persistent_closed++;
}

static void closed(wtq_session_t *session, uint32_t code, const uint8_t *reason,
                   size_t reason_len, bool clean, void *ctx)
{
    (void)session; (void)code; (void)reason; (void)reason_len; (void)clean;
    ((struct side *)ctx)->ended = true;
}

static wtq_result_t prepare(void *ctx, const wtq_msquic_accept_info_t *info,
    wtq_msquic_accept_decision_t *out)
{
    (void)info;
    out->accepted = true;
    out->guard = (wtq_guard_t){ .enter = enter, .leave = leave, .ctx = ctx };
    out->user = ctx;
    return WTQ_OK;
}

static void abandon(void *listener_user, void *user)
{
    (void)listener_user;
    ((struct side *)user)->errors++;
}

/* Peer records whose first byte is `kind` and whose bytes equal `want`
 * (length and FIN included). Caller holds s->lane. */
static unsigned exact(const struct side *s, uint8_t kind, const uint8_t *want,
                      size_t want_len, bool want_fin)
{
    unsigned n = 0;
    for (unsigned i = 0; i < s->record_count; ++i) {
        const struct record *r = &s->records[i];
        if (r->len && r->bytes[0] == kind && r->len == want_len &&
            r->fin == want_fin && memcmp(r->bytes, want, want_len) == 0) n++;
    }
    return n;
}

/* Records of this kind carrying any bytes. Caller holds s->lane. */
static unsigned kind_count(const struct side *s, uint8_t kind)
{
    unsigned n = 0;
    for (unsigned i = 0; i < s->record_count; ++i)
        if (s->records[i].len && s->records[i].bytes[0] == kind) n++;
    return n;
}

/* Exactly one exact record for EACH expected payload, and no other record of
 * that kind. Caller holds s->lane. */
static bool each_once(const struct side *s, uint8_t kind,
                      const uint8_t *const *want, size_t count, size_t len,
                      bool fin)
{
    for (size_t i = 0; i < count; ++i)
        if (exact(s, kind, want[i], len, fin) != 1) return false;
    return kind_count(s, kind) == count;
}

static const uint8_t *const request_set[REQUESTS] = {
    request_bytes[0], request_bytes[1], request_bytes[2] };
static const uint8_t *const reply_set[REQUESTS] = {
    reply_bytes[0], reply_bytes[1], reply_bytes[2] };
static const uint8_t *const video_set[VIDEOS] = {
    video_bytes[0], video_bytes[1], video_bytes[2] };

typedef bool (*ready_fn)(const struct side *s);

/* Caller holds s->lane. Bounded wait: the deadline only contains failure. */
static bool wait_until(struct side *s, ready_fn ready)
{
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += 10;
    while (!ready(s))
        if (pthread_cond_timedwait(&s->changed, &s->lane, &until) != 0)
            return ready(s);
    return true;
}

static bool is_established(const struct side *s) { return s->established; }
static bool server_has_requests(const struct side *s)
{
    return each_once(s, 'R', request_set, REQUESTS, sizeof(request_bytes[0]),
                     false) &&
        exact(s, 'A', announce_bytes, sizeof(announce_bytes), false) == 1 &&
        exact(s, 'C', catalog_bytes, sizeof(catalog_bytes), false) == 1;
}
static bool client_has_replies(const struct side *s)
{
    return each_once(s, 'P', reply_set, REQUESTS, sizeof(reply_bytes[0]),
                     false) &&
        exact(s, 'S', server_local_bytes, sizeof(server_local_bytes), false) == 1;
}
static bool server_has_videos(const struct side *s)
{
    return each_once(s, 'V', video_set, VIDEOS, VIDEO_BYTES, true);
}

/* Fill synthetic record `i` with one payload, as delivered with/without FIN. */
static void fake_record(struct side *s, unsigned i, const uint8_t *bytes,
                        size_t len, bool fin)
{
    struct record *r = &s->records[i];
    memset(r, 0, sizeof(*r));
    r->peer = true;
    memcpy(r->bytes, bytes, len);
    r->len = len;
    r->fin = fin;
    if (s->record_count < i + 1) s->record_count = i + 1;
}

/* The per-identity predicates on synthetic records, no transport: a set that
 * duplicates one payload and omits another has the right total of exact
 * matches but must not satisfy them; the complete set must, and an extra
 * duplicate of a complete set must not. */
static int oracle_controls(void)
{
    int failures = 0;
    static struct side fake;
    static const unsigned dup_omit[3] = { 0, 0, 2 };
    unsigned total;

    memset(&fake, 0, sizeof(fake));
    for (unsigned i = 0; i < VIDEOS; ++i)
        fake_record(&fake, i, video_bytes[dup_omit[i]], VIDEO_BYTES, true);
    total = 0;
    for (unsigned v = 0; v < VIDEOS; ++v)
        total += exact(&fake, 'V', video_bytes[v], VIDEO_BYTES, true);
    WTQ_TEST_CHECK_EQ_INT(total, VIDEOS);
    WTQ_TEST_CHECK(!server_has_videos(&fake));
    for (unsigned i = 0; i < VIDEOS; ++i)
        fake_record(&fake, i, video_bytes[i], VIDEO_BYTES, true);
    WTQ_TEST_CHECK(server_has_videos(&fake));
    fake_record(&fake, VIDEOS, video_bytes[1], VIDEO_BYTES, true);
    WTQ_TEST_CHECK(!server_has_videos(&fake));

    memset(&fake, 0, sizeof(fake));
    for (unsigned i = 0; i < REQUESTS; ++i)
        fake_record(&fake, i, request_bytes[dup_omit[i]],
                    sizeof(request_bytes[0]), false);
    fake_record(&fake, REQUESTS, announce_bytes, sizeof(announce_bytes), false);
    fake_record(&fake, REQUESTS + 1, catalog_bytes, sizeof(catalog_bytes), false);
    WTQ_TEST_CHECK(!server_has_requests(&fake));
    for (unsigned i = 0; i < REQUESTS; ++i)
        fake_record(&fake, i, request_bytes[i], sizeof(request_bytes[0]), false);
    WTQ_TEST_CHECK(server_has_requests(&fake));

    memset(&fake, 0, sizeof(fake));
    for (unsigned i = 0; i < REQUESTS; ++i)
        fake_record(&fake, i, reply_bytes[dup_omit[i]], sizeof(reply_bytes[0]),
                    false);
    fake_record(&fake, REQUESTS, server_local_bytes, sizeof(server_local_bytes),
                false);
    WTQ_TEST_CHECK(!client_has_replies(&fake));
    for (unsigned i = 0; i < REQUESTS; ++i)
        fake_record(&fake, i, reply_bytes[i], sizeof(reply_bytes[0]), false);
    WTQ_TEST_CHECK(client_has_replies(&fake));
    return failures;
}

static int send_one(wtq_stream_t *st, const uint8_t *bytes, size_t len, bool fin)
{
    int failures = 0;
    wtq_span_t span = { .data = bytes, .len = len };
    WTQ_TEST_CHECK_EQ_INT(wtq_stream_send(st, &span, 1, fin ? WTQ_SEND_FIN : 0,
                                          NULL), WTQ_OK);
    return failures;
}

/* Open a local stream, track it, and send its bytes. Caller holds s->lane. */
static int open_send(struct side *s, bool bidi, const uint8_t *bytes,
                     size_t len, bool fin)
{
    int failures = 0;
    wtq_stream_t *st = NULL;
    wtq_result_t rc = bidi ? wtq_session_open_bidi(s->session, &st)
                           : wtq_session_open_uni(s->session, &st);
    WTQ_TEST_CHECK_EQ_INT(rc, WTQ_OK);
    if (rc != WTQ_OK || st == NULL) return failures + 1;
    struct record *r = track(s, st, false);
    if (r == NULL) return failures + 1;
    r->finishes = fin;
    failures += send_one(st, bytes, len, fin);
    return failures;
}

static int budget(wtq_session_t *session, wtq_stream_budget_t *out)
{
    int failures = 0;
    *out = (wtq_stream_budget_t)WTQ_STREAM_BUDGET_INIT;
    WTQ_TEST_CHECK_EQ_INT(wtq_session_stream_budget(session, out), WTQ_OK);
    return failures;
}

int main(int argc, char **argv)
{
    int failures = 0;
    if (argc != 2) return 1;
    for (unsigned v = 0; v < VIDEOS; ++v) {
        video_bytes[v][0] = 'V';
        for (unsigned i = 1; i < VIDEO_BYTES; ++i)
            video_bytes[v][i] = (uint8_t)(v * 37u + i * 7u);
    }
    failures += oracle_controls();
    char cert[1024], key[1024];
    (void)snprintf(cert, sizeof(cert), "%s/cert.pem", argv[1]);
    (void)snprintf(key, sizeof(key), "%s/key.pem", argv[1]);
    static struct side client = { .lane = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER };
    static struct side server = { .lane = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER, .server = true };

    /* Default native grants, stated explicitly: U=8, B=7. */
    wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
    ecfg.tuning.peer_unidi_stream_count = 8;
    ecfg.tuning.peer_bidi_stream_count = 7;
    wtq_msquic_env_t *env = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ecfg, &env), WTQ_OK);
    if (!env) return failures;

    wtq_session_events_t events;
    wtq_session_events_init(&events);
    events.on_established = established;
    events.on_closed = closed;
    events.on_stream_opened = opened;
    events.on_stream_data = data;
    events.on_stream_closed = stream_closed;
    wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
    serve.path = "/moq";
    wtq_msquic_listener_cfg_t lcfg = WTQ_MSQUIC_LISTENER_CFG_INIT;
    lcfg.bind_address = "127.0.0.1";
    lcfg.cert_file = cert; lcfg.key_file = key;
    lcfg.paths = &serve; lcfg.path_count = 1;
    lcfg.events = &events; lcfg.user = &server;
    lcfg.accept_prepare = prepare;
    lcfg.accept_abandon = abandon;
    lcfg.max_local_streams = SERVER_LOCALS;
    wtq_msquic_listener_t *listener = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_listener_start(env, &lcfg, &listener), WTQ_OK);
    if (!listener) { wtq_msquic_env_close(env); return failures; }

    wtq_connect_config_t connect = WTQ_CONNECT_CONFIG_INIT;
    connect.authority = "localhost"; connect.path = "/moq";
    wtq_msquic_client_cfg_t cfg = WTQ_MSQUIC_CLIENT_CFG_INIT;
    cfg.server_name = "127.0.0.1";
    cfg.port = wtq_msquic_listener_port(listener);
    cfg.insecure_skip_verify = true;
    cfg.connect = &connect; cfg.events = &events; cfg.user = &client;
    cfg.guard = (wtq_guard_t){ .enter = enter, .leave = leave, .ctx = &client };

    /* 1. Client: persistent requests, announce and catalog, no FIN. */
    pthread_mutex_lock(&client.lane);
    WTQ_TEST_CHECK_EQ_INT(wtq_msquic_client_connect(env, &cfg, &client.session), WTQ_OK);
    bool ok = client.session && wait_until(&client, is_established);
    WTQ_TEST_CHECK(ok);
    if (ok) {
        wtq_stream_budget_t b;
        failures += budget(client.session, &b);
        WTQ_TEST_CHECK_EQ_INT(b.max_local_streams, 16);
        WTQ_TEST_CHECK_EQ_INT(b.api_capacity, 31);
        WTQ_TEST_CHECK_EQ_INT(b.engine_capacity, 32);
        for (unsigned i = 0; i < REQUESTS; ++i)
            failures += open_send(&client, true, request_bytes[i],
                                  sizeof(request_bytes[i]), false);
        failures += open_send(&client, false, announce_bytes,
                              sizeof(announce_bytes), false);
        failures += open_send(&client, false, catalog_bytes,
                              sizeof(catalog_bytes), false);
    }
    pthread_mutex_unlock(&client.lane);

    /* 2. Server: answer every request on its own stream; open one local. */
    pthread_mutex_lock(&server.lane);
    ok = ok && wait_until(&server, server_has_requests);
    WTQ_TEST_CHECK(ok);
    if (ok) {
        for (unsigned i = 0; i < server.record_count; ++i) {
            struct record *r = &server.records[i];
            if (r->peer && r->len && r->bytes[0] == 'R')
                failures += send_one(r->stream, reply_bytes[r->bytes[1] - '0'],
                                     sizeof(reply_bytes[0]), false);
        }
        failures += open_send(&server, false, server_local_bytes,
                              sizeof(server_local_bytes), false);
    }
    pthread_mutex_unlock(&server.lane);

    /* 3. Client: control progress observed, then complete video groups. */
    pthread_mutex_lock(&client.lane);
    ok = ok && wait_until(&client, client_has_replies);
    WTQ_TEST_CHECK(ok);
    if (ok)
        for (unsigned v = 0; v < VIDEOS; ++v)
            failures += open_send(&client, false, video_bytes[v], VIDEO_BYTES, true);
    pthread_mutex_unlock(&client.lane);

    /* 4. Server: every video byte and FIN, while nothing persistent ended. */
    pthread_mutex_lock(&server.lane);
    ok = ok && wait_until(&server, server_has_videos);
    WTQ_TEST_CHECK(ok);
    WTQ_TEST_CHECK(server_has_videos(&server));
    WTQ_TEST_CHECK_EQ_INT(server.persistent_closed, 0);
    WTQ_TEST_CHECK(!server.ended);
    if (ok) {
        wtq_stream_budget_t b;
        failures += budget(server.session, &b);
        WTQ_TEST_CHECK_EQ_INT(b.peer_unidi_stream_count, 8);
        WTQ_TEST_CHECK_EQ_INT(b.peer_bidi_stream_count, 7);
        WTQ_TEST_CHECK_EQ_INT(b.max_local_streams, SERVER_LOCALS);
        WTQ_TEST_CHECK_EQ_INT(b.api_capacity, 15 + SERVER_LOCALS);
        WTQ_TEST_CHECK_EQ_INT(b.engine_capacity, 15 + SERVER_LOCALS);
        WTQ_TEST_CHECK_EQ_INT(b.peer_uni_resident, 8); /* every uni grant */
        WTQ_TEST_CHECK_EQ_INT(b.peer_bidi_resident, 1 + REQUESTS);
        WTQ_TEST_CHECK_EQ_INT(b.local_resident, 1);
        WTQ_TEST_CHECK_EQ_INT(b.peer_wt_waiting, 0);
        WTQ_TEST_CHECK_EQ_U64(b.local_open_blocked, 0);

        /* 5. Peer residency does not consume local reservations; L does
         * bound locals, with NULL output and no stream. */
        failures += open_send(&server, false, server_local_bytes,
                              sizeof(server_local_bytes), false);
        wtq_stream_t *extra = (wtq_stream_t *)(void *)&server;
        WTQ_TEST_CHECK_EQ_INT(wtq_session_open_uni(server.session, &extra),
                              WTQ_ERR_WOULD_BLOCK);
        WTQ_TEST_CHECK(extra == NULL);
        failures += budget(server.session, &b);
        WTQ_TEST_CHECK_EQ_INT(b.local_resident, SERVER_LOCALS);
        WTQ_TEST_CHECK_EQ_INT(b.peer_uni_resident, 8);
        WTQ_TEST_CHECK_EQ_U64(b.local_open_blocked, 1);
        printf("native mixed: videos=%u/%u persistent_closed=%u "
               "peer_uni_resident=%u local_resident=%u blocked=%llu\n",
               kind_count(&server, 'V'), VIDEOS, server.persistent_closed,
               b.peer_uni_resident, b.local_resident,
               (unsigned long long)b.local_open_blocked);
    }
    pthread_mutex_unlock(&server.lane);

    pthread_mutex_lock(&client.lane);
    WTQ_TEST_CHECK_EQ_INT(client.persistent_closed, 0);
    WTQ_TEST_CHECK(!client.ended);
    pthread_mutex_unlock(&client.lane);

    wtq_msquic_listener_stop(listener);
    wtq_msquic_env_close(env);
    WTQ_TEST_CHECK_EQ_INT(client.errors + server.errors, 0);
    for (unsigned i = 0; i < RECORDS; ++i) {
        if (server.records[i].stream) wtq_stream_release(server.records[i].stream);
        if (client.records[i].stream) wtq_stream_release(client.records[i].stream);
    }
    if (server.session) wtq_session_release(server.session);
    if (client.session) wtq_session_release(client.session);
    return failures;
}
