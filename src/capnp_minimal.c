#include "capnp_minimal.h"

#include <stdio.h>
#include <string.h>

static size_t align8(size_t n) { return (n + 7u) & ~(size_t)7u; }

static uint16_t r16(const uint8_t *p) { return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
static uint32_t r32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
static void w32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void capnp_builder_init(capnp_builder_t *b, uint8_t *buf, size_t cap) {
    b->buf = buf;
    b->cap = cap;
    b->pos = 0;
    memset(buf, 0, cap);
}

int capnp_alloc(capnp_builder_t *b, size_t words) {
    size_t aligned = align8(b->pos);
    size_t need = aligned + words * 8;
    if (need > b->cap) return -1;
    if (aligned > b->pos) memset(b->buf + b->pos, 0, aligned - b->pos);
    int ret = (int)aligned;
    b->pos = need;
    return ret;
}

void capnp_write_struct_ptr(uint8_t *buf, size_t ptr_offset, size_t struct_offset,
                            uint16_t data_words, uint16_t ptr_count) {
    int32_t off_words = (int32_t)((struct_offset - ptr_offset - 8) / 8);
    uint32_t lo = ((uint32_t)(off_words << 2)) | 0;
    uint32_t hi = (uint32_t)data_words | ((uint32_t)ptr_count << 16);
    w32(buf + ptr_offset, lo);
    w32(buf + ptr_offset + 4, hi);
}

void capnp_write_list_ptr(uint8_t *buf, size_t ptr_offset, size_t list_offset,
                          uint8_t elem_size, uint32_t count) {
    int32_t off_words = (int32_t)((list_offset - ptr_offset - 8) / 8);
    uint32_t lo = ((uint32_t)(off_words << 2)) | 1;
    uint32_t hi = (uint32_t)elem_size | (count << 3);
    w32(buf + ptr_offset, lo);
    w32(buf + ptr_offset + 4, hi);
}

int capnp_write_text(capnp_builder_t *b, size_t ptr_offset, const char *text) {
    if (!text || !*text) {
        memset(b->buf + ptr_offset, 0, 8);
        return 0;
    }
    size_t slen = strlen(text);
    size_t count = slen + 1;
    int off = capnp_alloc(b, (count + 7) / 8);
    if (off < 0) return -1;
    memcpy(b->buf + off, text, slen);
    b->buf[off + slen] = 0;
    capnp_write_list_ptr(b->buf, ptr_offset, (size_t)off, 2, (uint32_t)count);
    return 0;
}

int capnp_write_data(capnp_builder_t *b, size_t ptr_offset, const uint8_t *data, size_t len) {
    if (!data || len == 0) {
        memset(b->buf + ptr_offset, 0, 8);
        return 0;
    }
    int off = capnp_alloc(b, (len + 7) / 8);
    if (off < 0) return -1;
    memcpy(b->buf + off, data, len);
    capnp_write_list_ptr(b->buf, ptr_offset, (size_t)off, 2, (uint32_t)len);
    return 0;
}

size_t capnp_finalize(const capnp_builder_t *b, uint8_t *out, size_t out_cap) {
    size_t seg_words = align8(b->pos) / 8;
    size_t total = 8 + seg_words * 8;
    if (total > out_cap) return 0;
    memset(out, 0, total);
    w32(out, 0);
    w32(out + 4, (uint32_t)seg_words);
    memcpy(out + 8, b->buf, b->pos);
    return total;
}

int capnp_read_message(const uint8_t *data, size_t len, capnp_reader_t *r) {
    if (len < 8) return -1;
    if (r32(data) != 0) return -1;
    size_t seg_len = (size_t)r32(data + 4) * 8;
    if (8 + seg_len > len) return -1;
    r->seg = data + 8;
    r->seg_len = seg_len;
    return 0;
}

int capnp_read_struct_ptr(const capnp_reader_t *r, size_t ptr_offset,
                          size_t *struct_offset, uint16_t *data_words, uint16_t *ptr_count) {
    if (ptr_offset + 8 > r->seg_len) return -1;
    uint32_t lo = r32(r->seg + ptr_offset);
    uint32_t hi = r32(r->seg + ptr_offset + 4);
    if (lo == 0 && hi == 0) return -1;
    if ((lo & 3) != 0) return -1;
    int32_t off_words = (int32_t)lo >> 2;
    *data_words = (uint16_t)(hi & 0xffff);
    *ptr_count = (uint16_t)(hi >> 16);
    int64_t off = (int64_t)ptr_offset + 8 + (int64_t)off_words * 8;
    if (off < 0 || (size_t)off > r->seg_len) return -1;
    *struct_offset = (size_t)off;
    return 0;
}

const char *capnp_read_text(const capnp_reader_t *r, size_t ptr_offset, size_t *out_len) {
    if (ptr_offset + 8 > r->seg_len) return NULL;
    uint32_t lo = r32(r->seg + ptr_offset);
    uint32_t hi = r32(r->seg + ptr_offset + 4);
    if (lo == 0 && hi == 0) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    if ((lo & 3) != 1 || (hi & 7) != 2) return NULL;
    int32_t off_words = (int32_t)lo >> 2;
    uint32_t count = hi >> 3;
    int64_t off = (int64_t)ptr_offset + 8 + (int64_t)off_words * 8;
    if (off < 0 || (size_t)off + count > r->seg_len) return NULL;
    if (out_len) *out_len = count ? count - 1 : 0;
    return (const char *)(r->seg + off);
}

const uint8_t *capnp_read_data(const capnp_reader_t *r, size_t ptr_offset, size_t *out_len) {
    if (ptr_offset + 8 > r->seg_len) return NULL;
    uint32_t lo = r32(r->seg + ptr_offset);
    uint32_t hi = r32(r->seg + ptr_offset + 4);
    if (lo == 0 && hi == 0) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    if ((lo & 3) != 1 || (hi & 7) != 2) return NULL;
    int32_t off_words = (int32_t)lo >> 2;
    uint32_t count = hi >> 3;
    int64_t off = (int64_t)ptr_offset + 8 + (int64_t)off_words * 8;
    if (off < 0 || (size_t)off + count > r->seg_len) return NULL;
    if (out_len) *out_len = count;
    return r->seg + off;
}

uint16_t capnp_read_uint16(const capnp_reader_t *r, size_t struct_data_offset, size_t byte_offset) {
    size_t off = struct_data_offset + byte_offset;
    if (off + 2 > r->seg_len) return 0;
    return r16(r->seg + off);
}

bool capnp_read_bool(const capnp_reader_t *r, size_t struct_data_offset, size_t byte_offset, int bit) {
    size_t off = struct_data_offset + byte_offset;
    if (off + 1 > r->seg_len) return false;
    return ((r->seg[off] >> bit) & 1) != 0;
}

size_t capnp_wire_message_size(const uint8_t *data, size_t len) {
    if (len < 8 || r32(data) != 0) return 0;
    size_t total = 8 + (size_t)r32(data + 4) * 8;
    return total <= len ? total : 0;
}
