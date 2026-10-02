#pragma once

#include "common.h"

void capnp_builder_init(capnp_builder_t *b, uint8_t *buf, size_t cap);
int capnp_alloc(capnp_builder_t *b, size_t words);
void capnp_write_struct_ptr(uint8_t *buf, size_t ptr_offset, size_t struct_offset,
                            uint16_t data_words, uint16_t ptr_count);
void capnp_write_list_ptr(uint8_t *buf, size_t ptr_offset, size_t list_offset,
                          uint8_t elem_size, uint32_t count);
int capnp_write_text(capnp_builder_t *b, size_t ptr_offset, const char *text);
int capnp_write_data(capnp_builder_t *b, size_t ptr_offset, const uint8_t *data, size_t len);
size_t capnp_finalize(const capnp_builder_t *b, uint8_t *out, size_t out_cap);

int capnp_read_message(const uint8_t *data, size_t len, capnp_reader_t *r);
int capnp_read_struct_ptr(const capnp_reader_t *r, size_t ptr_offset,
                          size_t *struct_offset, uint16_t *data_words, uint16_t *ptr_count);
const char *capnp_read_text(const capnp_reader_t *r, size_t ptr_offset, size_t *out_len);
const uint8_t *capnp_read_data(const capnp_reader_t *r, size_t ptr_offset, size_t *out_len);
uint16_t capnp_read_uint16(const capnp_reader_t *r, size_t struct_data_offset, size_t byte_offset);
bool capnp_read_bool(const capnp_reader_t *r, size_t struct_data_offset, size_t byte_offset, int bit);
size_t capnp_wire_message_size(const uint8_t *data, size_t len);

