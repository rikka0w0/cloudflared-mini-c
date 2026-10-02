#include "control_stream.h"
#include "capnp_minimal.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static const uint64_t REGISTRATION_SERVER_IID = 0xf71695ec7fe85497ULL;
static const uint32_t REGISTER_ANSWER_ID = 1;
static const uint32_t UNREGISTER_ANSWER_ID = 2;

static void w16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}
static void w32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}
static void w64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (i * 8));
}
static uint32_t r32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static int encode_bootstrap(uint8_t *out, size_t out_cap, size_t *out_len) {
    uint8_t work[256];
    capnp_builder_t b;
    capnp_builder_init(&b, work, sizeof(work));
    int rp = capnp_alloc(&b, 1);
    int msg = capnp_alloc(&b, 2);
    int boot = capnp_alloc(&b, 2);
    if (rp < 0 || msg < 0 || boot < 0) return -1;
    capnp_write_struct_ptr(b.buf, (size_t)rp, (size_t)msg, 1, 1);
    w16(b.buf + msg, 8);
    capnp_write_struct_ptr(b.buf, (size_t)msg + 8, (size_t)boot, 1, 1);
    *out_len = capnp_finalize(&b, out, out_cap);
    return *out_len ? 0 : -1;
}

static int encode_call(const tunnel_auth_t *auth, const uint8_t *tunnel_id, size_t tunnel_id_len,
                       uint8_t conn_index, const conn_options_t *options, uint8_t *out,
                       size_t out_cap, size_t *out_len) {
    uint8_t work[4096];
    capnp_builder_t b;
    capnp_builder_init(&b, work, sizeof(work));

    int rp = capnp_alloc(&b, 1);
    int msg = capnp_alloc(&b, 2);
    if (rp < 0 || msg < 0) return -1;
    capnp_write_struct_ptr(b.buf, (size_t)rp, (size_t)msg, 1, 1);
    w16(b.buf + msg, 2);

    int call = capnp_alloc(&b, 6);
    if (call < 0) return -1;
    capnp_write_struct_ptr(b.buf, (size_t)msg + 8, (size_t)call, 3, 3);
    w32(b.buf + call, REGISTER_ANSWER_ID);
    w16(b.buf + call + 4, 0);
    w64(b.buf + call + 8, REGISTRATION_SERVER_IID);
    size_t call_ptrs = (size_t)call + 24;

    int target = capnp_alloc(&b, 2);
    int pa = capnp_alloc(&b, 2);
    if (target < 0 || pa < 0) return -1;
    capnp_write_struct_ptr(b.buf, call_ptrs, (size_t)target, 1, 1);
    w16(b.buf + target + 4, 1);
    capnp_write_struct_ptr(b.buf, (size_t)target + 8, (size_t)pa, 1, 1);

    int payload = capnp_alloc(&b, 2);
    int params = capnp_alloc(&b, 4);
    if (payload < 0 || params < 0) return -1;
    capnp_write_struct_ptr(b.buf, call_ptrs + 8, (size_t)payload, 0, 2);
    capnp_write_struct_ptr(b.buf, (size_t)payload, (size_t)params, 1, 3);
    b.buf[params] = conn_index;
    size_t params_ptrs = (size_t)params + 8;

    int ta = capnp_alloc(&b, 2);
    if (ta < 0) return -1;
    capnp_write_struct_ptr(b.buf, params_ptrs, (size_t)ta, 0, 2);
    if (capnp_write_text(&b, (size_t)ta, auth->account_tag) != 0) return -1;
    if (capnp_write_data(&b, (size_t)ta + 8, auth->tunnel_secret, auth->tunnel_secret_len) != 0)
        return -1;
    if (capnp_write_data(&b, params_ptrs + 8, tunnel_id, tunnel_id_len) != 0) return -1;

    int co = capnp_alloc(&b, 3);
    if (co < 0) return -1;
    capnp_write_struct_ptr(b.buf, params_ptrs + 16, (size_t)co, 1, 2);
    if (options) {
        if (options->replace_existing) b.buf[co] |= 1;
        b.buf[co + 1] = options->compression_quality;
        b.buf[co + 2] = options->num_previous_attempts;
        size_t co_ptrs = (size_t)co + 8;
        int ci = capnp_alloc(&b, 4);
        if (ci < 0) return -1;
        capnp_write_struct_ptr(b.buf, co_ptrs, (size_t)ci, 0, 4);
        if (options->client_id && capnp_write_data(&b, (size_t)ci, options->client_id, 16) != 0)
            return -1;
        if (capnp_write_text(&b, (size_t)ci + 16, options->version) != 0) return -1;
        if (capnp_write_text(&b, (size_t)ci + 24, options->arch) != 0) return -1;
    }

    *out_len = capnp_finalize(&b, out, out_cap);
    return *out_len ? 0 : -1;
}

static int encode_unregister_call(uint8_t *out, size_t out_cap, size_t *out_len) {
    uint8_t work[512];
    capnp_builder_t b;
    capnp_builder_init(&b, work, sizeof(work));

    int rp = capnp_alloc(&b, 1);
    int msg = capnp_alloc(&b, 2);
    if (rp < 0 || msg < 0) return -1;
    capnp_write_struct_ptr(b.buf, (size_t)rp, (size_t)msg, 1, 1);
    w16(b.buf + msg, 2);

    int call = capnp_alloc(&b, 6);
    if (call < 0) return -1;
    capnp_write_struct_ptr(b.buf, (size_t)msg + 8, (size_t)call, 3, 3);
    w32(b.buf + call, UNREGISTER_ANSWER_ID);
    w16(b.buf + call + 4, 1);
    w64(b.buf + call + 8, REGISTRATION_SERVER_IID);
    size_t call_ptrs = (size_t)call + 24;

    int target = capnp_alloc(&b, 2);
    int pa = capnp_alloc(&b, 2);
    if (target < 0 || pa < 0) return -1;
    capnp_write_struct_ptr(b.buf, call_ptrs, (size_t)target, 1, 1);
    w16(b.buf + target + 4, 1);
    capnp_write_struct_ptr(b.buf, (size_t)target + 8, (size_t)pa, 1, 1);

    int payload = capnp_alloc(&b, 2);
    int params = capnp_alloc(&b, 0);
    if (payload < 0 || params < 0) return -1;
    capnp_write_struct_ptr(b.buf, call_ptrs + 8, (size_t)payload, 0, 2);
    capnp_write_struct_ptr(b.buf, (size_t)payload, (size_t)params, 0, 0);

    *out_len = capnp_finalize(&b, out, out_cap);
    return *out_len ? 0 : -1;
}

int control_stream_encode_register(const tunnel_auth_t *auth, const uint8_t *tunnel_id,
                                   size_t tunnel_id_len, uint8_t conn_index,
                                   const conn_options_t *options, uint8_t *buf,
                                   size_t buf_cap, size_t *out_len) {
    size_t a = 0, b = 0;
    if (encode_bootstrap(buf, buf_cap, &a) != 0) return -1;
    if (encode_call(auth, tunnel_id, tunnel_id_len, conn_index, options, buf + a, buf_cap - a,
                    &b) != 0)
        return -1;
    *out_len = a + b;
    return 0;
}

int control_stream_encode_unregister(uint8_t *buf, size_t buf_cap, size_t *out_len) {
    return encode_unregister_call(buf, buf_cap, out_len);
}

int control_stream_decode_response(const uint8_t *data, size_t len, registration_result_t *result) {
    memset(result, 0, sizeof(*result));
    capnp_reader_t reader;
    if (capnp_read_message(data, len, &reader) != 0) return -1;
    size_t root_off;
    uint16_t root_dw, root_pc;
    if (capnp_read_struct_ptr(&reader, 0, &root_off, &root_dw, &root_pc) != 0) return -1;
    if (capnp_read_uint16(&reader, root_off, 0) != 3) return -1;
    size_t ret_off;
    uint16_t ret_dw, ret_pc;
    if (capnp_read_struct_ptr(&reader, root_off + root_dw * 8, &ret_off, &ret_dw, &ret_pc) != 0)
        return -1;
    uint32_t answer_id = ret_dw ? r32(reader.seg + ret_off) : 0;
    result->answer_id = answer_id;
    if (answer_id == 0) {
        result->is_bootstrap = true;
        return 0;
    }
    uint16_t ret_which = ret_dw ? capnp_read_uint16(&reader, ret_off, 6) : 0;
    if (answer_id == UNREGISTER_ANSWER_ID) {
        result->unregister_ack = ret_which == 0;
        result->success = result->unregister_ack;
        if (ret_which != 0) {
            snprintf(result->error, sizeof(result->error), "unregister return type %u", ret_which);
        }
        return 0;
    }
    size_t ret_ptrs = ret_off + ret_dw * 8;
    if (ret_which != 0) {
        snprintf(result->error, sizeof(result->error), "registration return type %u", ret_which);
        result->should_retry = true;
        return 0;
    }
    size_t payload_off, results_off, cr_off;
    uint16_t dw, pc;
    if (capnp_read_struct_ptr(&reader, ret_ptrs, &payload_off, &dw, &pc) != 0) return -1;
    if (capnp_read_struct_ptr(&reader, payload_off + dw * 8, &results_off, &dw, &pc) != 0)
        return -1;
    if (capnp_read_struct_ptr(&reader, results_off + dw * 8, &cr_off, &dw, &pc) != 0) return -1;
    uint16_t cr_which = capnp_read_uint16(&reader, cr_off, 0);
    size_t cr_ptrs = cr_off + dw * 8;
    if (cr_which == 0) {
        size_t err_off;
        if (capnp_read_struct_ptr(&reader, cr_ptrs, &err_off, &dw, &pc) == 0) {
            if (dw >= 1) result->retry_after_ns = (int64_t)((uint64_t)r32(reader.seg + err_off) |
                                                            ((uint64_t)r32(reader.seg + err_off + 4)
                                                             << 32));
            if (dw >= 2) result->should_retry = capnp_read_bool(&reader, err_off, 8, 0);
            size_t elen = 0;
            const char *e = capnp_read_text(&reader, err_off + dw * 8, &elen);
            if (e && elen) snprintf(result->error, sizeof(result->error), "%.*s", (int)elen, e);
        }
        return 0;
    }
    if (cr_which != 1) return -1;
    size_t details_off;
    if (capnp_read_struct_ptr(&reader, cr_ptrs, &details_off, &dw, &pc) != 0) return -1;
    result->tunnel_is_remote = capnp_read_bool(&reader, details_off, 0, 0);
    size_t dptrs = details_off + dw * 8;
    size_t ulen = 0, llen = 0;
    const uint8_t *uuid = capnp_read_data(&reader, dptrs, &ulen);
    const char *loc = capnp_read_text(&reader, dptrs + 8, &llen);
    if (uuid && ulen >= 16) {
        snprintf(result->uuid, sizeof(result->uuid),
                 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
                 uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14],
                 uuid[15]);
    }
    if (loc && llen) snprintf(result->location, sizeof(result->location), "%.*s", (int)llen, loc);
    result->success = true;
    return 0;
}
