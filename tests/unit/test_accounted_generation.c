/* Slot reuse during callbacks, with no transport or exported test hooks. */
#include <stddef.h>
#include <stdlib.h>
#include "../../src/engine/conn.c"
#include "test_support.h"

struct reuse_probe {
    int calls;
    wtq_estream_t *replacement;
    wtq_result_t result;
    uint64_t generation;
};

static void detached(wtq_driver_t *drv, wtq_dstream_t *ds, wtq_estream_t *es)
{
    (void)drv; (void)ds; (void)es;
}

/* The rows never reach the transport: every other operation refuses. */
static wtq_result_t no_open(wtq_driver_t *drv, wtq_estream_t *ectx,
                            wtq_dstream_t **out, uint64_t *id_out)
{
    (void)drv; (void)ectx; (void)out; (void)id_out;
    return WTQ_ERR_STATE;
}
static wtq_result_t no_send(wtq_driver_t *drv, wtq_dstream_t *ds,
                            const uint8_t *data, size_t len, bool fin)
{
    (void)drv; (void)ds; (void)data; (void)len; (void)fin;
    return WTQ_ERR_STATE;
}
static wtq_result_t no_shutdown(wtq_driver_t *drv, wtq_dstream_t *ds,
                                const wtq_shutdown_t *req)
{
    (void)drv; (void)ds; (void)req;
    return WTQ_ERR_STATE;
}
static wtq_result_t no_close(wtq_driver_t *drv, uint64_t h3_err)
{
    (void)drv; (void)h3_err;
    return WTQ_ERR_STATE;
}
static const wtq_driver_ops_t row_ops = {
    .open_uni = no_open, .open_bidi = no_open, .send = no_send,
    .shutdown_stream = no_shutdown, .conn_close = no_close, .detach = detached,
};
/* Opaque driver identity: only handed back to row_ops, never dereferenced. */
static max_align_t row_driver;

static void recycle(wtq_conn_t *conn, wtq_estream_t *es,
                    const uint8_t *p, size_t n, bool fin, void *ctx)
{
    (void)p; (void)n; (void)fin;
    struct reuse_probe *probe = ctx;
    if (++probe->calls != 1)
        return;
    probe->result = wtq_conn_on_stream_reset(conn, es, 0, 0);
    if (probe->result != WTQ_OK)
        return;
    probe->result = wtq_conn_on_peer_uni_opened(conn,
        (wtq_dstream_t *)(void *)probe, 11, &probe->replacement);
    if (probe->result != WTQ_OK)
        return;
    const uint8_t pre[] = { 0x40, 0x54, 0 };
    probe->result = wtq_conn_on_stream_bytes(conn, probe->replacement,
                                             pre, sizeof(pre), false, 0);
    probe->generation = probe->replacement->generation;
}

static int row(size_t n)
{
    int failures = 0;
    struct reuse_probe probe = { 0 };
    /* A legacy (unbudgeted) connection, created and sized by the engine. */
    wtq_conn_cfg_t cfg = {
        .alloc = wtq_alloc_default(),
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .callbacks = { .on_wt_stream_data = recycle, .ctx = &probe },
    };
    wtq_conn_t *conn = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_create(&cfg,
        (wtq_driver_t *)(void *)&row_driver, &row_ops, &conn), WTQ_OK);
    uint8_t *data = calloc(1, n);
    WTQ_TEST_CHECK(conn != NULL && data != NULL);
    if (conn == NULL || data == NULL) {
        wtq_conn_destroy(conn); free(data); return failures;
    }
    conn->session_established = true;
    conn->sess_state = SS_ESTABLISHED;
    wtq_estream_t *es = NULL;
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_on_peer_uni_opened(conn,
        (wtq_dstream_t *)(void *)conn, 7, &es), WTQ_OK);
    const uint8_t pre[] = { 0x40, 0x54, 0 };
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_on_stream_bytes(conn, es, pre,
        sizeof(pre), false, 0), WTQ_OK);
    uint64_t old = es->generation;
    size_t consumed = 0;
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_on_stream_bytes_accounted(conn, es,
        data, n, true, 0, &consumed), WTQ_OK);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, n); /* terminal old-stream tail discarded */
    WTQ_TEST_CHECK_EQ_INT(probe.result, WTQ_OK);
    WTQ_TEST_CHECK_EQ_INT(probe.calls, 1);
    WTQ_TEST_CHECK(probe.replacement == es); /* prove actual slot reuse */
    WTQ_TEST_CHECK(probe.generation != old);
    WTQ_TEST_CHECK(es->kind == ES_WT && es->wt_recv_open);
    conn->closed = true;
    consumed = 123;
    WTQ_TEST_CHECK_EQ_INT(wtq_conn_on_stream_bytes_accounted(conn, es,
        data, n, true, 0, &consumed), WTQ_ERR_CLOSED);
    WTQ_TEST_CHECK_EQ_SIZE(consumed, 0);
    WTQ_TEST_CHECK_EQ_INT(probe.calls, 1);
    free(data); wtq_conn_destroy(conn);
    return failures;
}

int main(void)
{
    return row(1) + row(65536);
}
