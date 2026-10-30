/*
 * Environment keepalive against the real provider: a bounded loopback where
 * MsQuic reports, through QUIC_PARAM_CONN_SETTINGS, the KeepAliveIntervalMs
 * actually applied to the client connection and to the accepted server
 * connection.
 *
 * The process-wide MsQuic keepalive is set to a distinctive value first, so
 * each row shows the difference between a config that omits the field (the
 * provider's setting is inherited) and one that covers it (its value wins,
 * 0 included). No idle period is waited out; the rows read settings only.
 */
#if defined(__linux__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include "msq_internal.h"
#include "test_support.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define GLOBAL_KEEP_ALIVE_MS 7777u

struct observed {
    pthread_mutex_t mu;
    pthread_cond_t changed;
    unsigned client_established, server_established;
};

static void established(wtq_session_t *session, wtq_str_t protocol, void *ctx)
{
    (void)session; (void)protocol;
    struct observed *o = *(struct observed **)ctx;
    bool server = ((void **)ctx)[1] != NULL;

    pthread_mutex_lock(&o->mu);
    if (server)
        o->server_established++;
    else
        o->client_established++;
    pthread_cond_broadcast(&o->changed);
    pthread_mutex_unlock(&o->mu);
}

static bool wait_established(struct observed *o)
{
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 10;
    bool ok = true;

    pthread_mutex_lock(&o->mu);
    while (ok && (o->client_established == 0 || o->server_established == 0))
        if (pthread_cond_timedwait(&o->changed, &o->mu, &deadline) == ETIMEDOUT)
            ok = false;
    pthread_mutex_unlock(&o->mu);
    return ok;
}

/* The provider's keepalive on the environment's client and server
 * connection. Handles are copied under the environment lock; the queries
 * run without it. */
static bool read_applied(wtq_msquic_env_t *env, uint32_t *client,
                         uint32_t *server)
{
    HQUIC conns[2] = { NULL, NULL };

    pthread_mutex_lock(&env->mu);
    for (struct wtq_driver *d = env->conns; d != NULL; d = d->env_next)
        conns[d->is_client ? 0 : 1] = d->conn;
    pthread_mutex_unlock(&env->mu);
    if (conns[0] == NULL || conns[1] == NULL)
        return false;
    for (int i = 0; i < 2; ++i) {
        QUIC_SETTINGS s;
        uint32_t size = sizeof(s);
        memset(&s, 0, sizeof(s));
        if (QUIC_FAILED(env->api->GetParam(conns[i], QUIC_PARAM_CONN_SETTINGS,
                                           &size, &s)))
            return false;
        *(i == 0 ? client : server) = s.KeepAliveIntervalMs;
    }
    return true;
}

enum row_mode { ROW_ABSENT, ROW_COVERED };

struct row {
    const char *name;
    enum row_mode mode;
    uint32_t value;
    uint32_t expected;
};

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    int failures = 0;
    char cert[1024], key[1024];
    int nc = snprintf(cert, sizeof(cert), "%s/cert.pem", argv[1]);
    int nk = snprintf(key, sizeof(key), "%s/key.pem", argv[1]);
    if (nc < 0 || nk < 0 || (size_t)nc >= sizeof(cert) ||
        (size_t)nk >= sizeof(key))
        return 2;

    const QUIC_API_TABLE *api = NULL;
    if (QUIC_FAILED(MsQuicOpen2(&api)))
        return 2;
    QUIC_SETTINGS global;
    memset(&global, 0, sizeof(global));
    global.KeepAliveIntervalMs = GLOBAL_KEEP_ALIVE_MS;
    global.IsSet.KeepAliveIntervalMs = TRUE;
    WTQ_TEST_CHECK(QUIC_SUCCEEDED(api->SetParam(
        NULL, QUIC_PARAM_GLOBAL_SETTINGS, sizeof(global), &global)));

    static const struct row rows[] = {
        { "absent", ROW_ABSENT, 0, GLOBAL_KEEP_ALIVE_MS },
        { "covered-0", ROW_COVERED, 0, 0 },
        { "covered-15000", ROW_COVERED, 15000, 15000 },
    };
    for (size_t r = 0; r < sizeof(rows) / sizeof(rows[0]); ++r) {
        struct observed o = { .mu = PTHREAD_MUTEX_INITIALIZER,
                              .changed = PTHREAD_COND_INITIALIZER };
        /* Session user: the shared observation, and a server marker. */
        void *client_user[2] = { &o, NULL };
        void *server_user[2] = { &o, &o };
        wtq_msquic_env_t *env = NULL;
        wtq_msquic_listener_t *listener = NULL;
        wtq_session_t *client = NULL;
        uint32_t applied_client = UINT32_MAX, applied_server = UINT32_MAX;
        bool read = false;

        wtq_msquic_env_cfg_t ec;
        if (rows[r].mode == ROW_ABSENT) {
            (wtq_msquic_env_cfg_init)(&ec);
        } else {
            wtq_msquic_env_cfg_init(&ec);
            ec.keep_alive_interval_ms = rows[r].value;
        }
        WTQ_TEST_CHECK_EQ_INT(wtq_msquic_env_open(&ec, &env), WTQ_OK);
        if (env == NULL)
            break;

        wtq_session_events_t ev = WTQ_SESSION_EVENTS_INIT;
        ev.on_established = established;
        wtq_serve_config_t serve = WTQ_SERVE_CONFIG_INIT;
        serve.path = "/ka";
        wtq_msquic_listener_cfg_t lc = WTQ_MSQUIC_LISTENER_CFG_INIT;
        lc.bind_address = "127.0.0.1";
        lc.cert_file = cert;
        lc.key_file = key;
        lc.paths = &serve;
        lc.path_count = 1;
        lc.events = &ev;
        lc.user = server_user;
        WTQ_TEST_CHECK_EQ_INT(wtq_msquic_listener_start(env, &lc, &listener),
                              WTQ_OK);
        if (listener != NULL) {
            wtq_connect_config_t cc = WTQ_CONNECT_CONFIG_INIT;
            cc.authority = "localhost";
            cc.path = "/ka";
            wtq_msquic_client_cfg_t cfg = WTQ_MSQUIC_CLIENT_CFG_INIT;
            cfg.server_name = "127.0.0.1";
            cfg.port = wtq_msquic_listener_port(listener);
            cfg.insecure_skip_verify = true;
            cfg.connect = &cc;
            cfg.events = &ev;
            cfg.user = client_user;
            WTQ_TEST_CHECK_EQ_INT(wtq_msquic_client_connect(env, &cfg, &client),
                                  WTQ_OK);
            bool up = client != NULL && wait_established(&o);
            WTQ_TEST_CHECK(up);
            if (up) {
                read = read_applied(env, &applied_client, &applied_server);
                WTQ_TEST_CHECK(read);
            }
        }
        if (read) {
            WTQ_TEST_CHECK_EQ_U64(applied_client, rows[r].expected);
            WTQ_TEST_CHECK_EQ_U64(applied_server, rows[r].expected);
        }
        printf("keepalive native %s: global=%u client=%u server=%u expected=%u\n",
               rows[r].name, GLOBAL_KEEP_ALIVE_MS, (unsigned)applied_client,
               (unsigned)applied_server, (unsigned)rows[r].expected);

        if (listener != NULL)
            wtq_msquic_listener_stop(listener);
        wtq_msquic_env_close(env);
        /* After env_close no callback runs, so the app reference may go. */
        wtq_session_release(client);
        pthread_cond_destroy(&o.changed);
        pthread_mutex_destroy(&o.mu);
        if (failures)
            break;
    }

    MsQuicClose(api);
    WTQ_TEST_PASS("keepalive_native");
    return failures ? 1 : 0;
}
