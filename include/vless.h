#ifndef VLESS_H
#define VLESS_H

#include "common.h"

typedef struct {
    uint8_t in[BUF_SIZE * 4];
    size_t in_len;
    int header_done;
    uint8_t version;
    uint8_t cmd;
} vless_stream_t;

typedef int (*vless_send_ws_cb)(void *user_data, const uint8_t *data, size_t len);
typedef int (*vless_send_origin_cb)(void *user_data, const uint8_t *data, size_t len,
                                    int datagram);

int vless_is_udp(const vless_stream_t *s);
int vless_handle_client_data(vless_stream_t *s, int stream_id, const uint8_t *data, size_t len,
                             int *origin_fd, vless_send_origin_cb send_origin,
                             void *origin_user_data, vless_send_ws_cb send_ws,
                             void *send_user_data);
int vless_send_origin_data(vless_stream_t *s, const uint8_t *data, size_t len,
                           vless_send_ws_cb send_ws, void *send_user_data);

#endif
