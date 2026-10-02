#pragma once

#include "common.h"

int control_stream_encode_register(const tunnel_auth_t *auth,
                                   const uint8_t *tunnel_id, size_t tunnel_id_len,
                                   uint8_t conn_index,
                                   const conn_options_t *options,
                                   uint8_t *buf, size_t buf_cap, size_t *out_len);

int control_stream_encode_unregister(uint8_t *buf, size_t buf_cap, size_t *out_len);

int control_stream_decode_response(const uint8_t *data, size_t len,
                                   registration_result_t *result);
