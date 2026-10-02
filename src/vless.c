#include "vless.h"
#include "util.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VLESS_CMD_TCP 0x01
#define VLESS_CMD_UDP 0x02
#define VLESS_ATYP_IPV4 0x01
#define VLESS_ATYP_DOMAIN 0x02
#define VLESS_ATYP_IPV6 0x03

int vless_is_udp(const vless_stream_t *s) {
    return s && s->cmd == VLESS_CMD_UDP;
}

static int send_vless_response_header(vless_stream_t *s, vless_send_ws_cb send_ws,
                                      void *send_user_data) {
    uint8_t resp[2] = {s->version, 0};
    return send_ws(send_user_data, resp, sizeof(resp));
}

static int send_vless_udp_packet(vless_stream_t *s, const uint8_t *data, size_t len,
                                 vless_send_ws_cb send_ws, void *send_user_data) {
    (void)s;
    if (len > 0xffff) return -1;
    uint8_t *pkt = malloc(len + 2);
    if (!pkt) return -1;
    pkt[0] = (uint8_t)(len >> 8);
    pkt[1] = (uint8_t)len;
    memcpy(pkt + 2, data, len);
    int rv = send_ws(send_user_data, pkt, len + 2);
    free(pkt);
    return rv;
}

static int parse_vless_request(const uint8_t *buf, size_t len, size_t *used, uint8_t *version,
                               uint8_t *cmd, char *host, size_t host_len, char *port,
                               size_t port_len) {
    if (len < 18) return 0;
    size_t p = 0;
    *version = buf[p++];
    p += 16;
    uint8_t opt_len = buf[p++];
    if (len < p + opt_len + 4) return 0;
    p += opt_len;
    *cmd = buf[p++];
    if (*cmd != VLESS_CMD_TCP && *cmd != VLESS_CMD_UDP) return -1;

    uint16_t port_num = ((uint16_t)buf[p] << 8) | buf[p + 1];
    p += 2;
    uint8_t atyp = buf[p++];
    if (atyp == VLESS_ATYP_IPV4) {
        if (len < p + 4) return 0;
        if (!inet_ntop(AF_INET, buf + p, host, (socklen_t)host_len)) return -1;
        p += 4;
    } else if (atyp == VLESS_ATYP_DOMAIN) {
        if (len < p + 1) return 0;
        uint8_t n = buf[p++];
        if (n == 0 || n >= host_len) return -1;
        if (len < p + n) return 0;
        memcpy(host, buf + p, n);
        host[n] = 0;
        p += n;
    } else if (atyp == VLESS_ATYP_IPV6) {
        if (len < p + 16) return 0;
        if (!inet_ntop(AF_INET6, buf + p, host, (socklen_t)host_len)) return -1;
        p += 16;
    } else {
        return -1;
    }

    snprintf(port, port_len, "%u", port_num);
    *used = p;
    return 1;
}

static int handle_udp_payload(vless_stream_t *s, const uint8_t *data, size_t len,
                              vless_send_origin_cb send_origin, void *origin_user_data) {
    if (s->in_len + len > sizeof(s->in)) {
        s->in_len = 0;
        return -1;
    }
    memcpy(s->in + s->in_len, data, len);
    s->in_len += len;
    while (s->in_len >= 2) {
        size_t pkt_len = ((size_t)s->in[0] << 8) | s->in[1];
        if (s->in_len < pkt_len + 2) break;
        if (pkt_len && send_origin(origin_user_data, s->in + 2, pkt_len, 1) != 0) return -1;
        memmove(s->in, s->in + 2 + pkt_len, s->in_len - 2 - pkt_len);
        s->in_len -= 2 + pkt_len;
    }
    return 0;
}

int vless_handle_client_data(vless_stream_t *s, int stream_id, const uint8_t *data, size_t len,
                             int *origin_fd, vless_send_origin_cb send_origin,
                             void *origin_user_data, vless_send_ws_cb send_ws,
                             void *send_user_data) {
    if (!s->header_done) {
        if (s->in_len + len > sizeof(s->in)) return -1;
        memcpy(s->in + s->in_len, data, len);
        s->in_len += len;

        size_t used = 0;
        uint8_t version = 0, cmd = 0;
        char host[256], port[16];
        int ok = parse_vless_request(s->in, s->in_len, &used, &version, &cmd, host,
                                     sizeof(host), port, sizeof(port));
        if (ok == 0) return 0;
        if (ok < 0) return -1;

        *origin_fd = cmd == VLESS_CMD_TCP ? tcp_connect_host(host, port)
                                          : udp_connect_host(host, port);
        if (*origin_fd < 0) return -1;
        set_nonblock(*origin_fd, true);
        s->version = version;
        s->cmd = cmd;
        s->header_done = 1;
        fprintf(stderr, "vless stream %d: %s -> %s:%s\n", stream_id,
                cmd == VLESS_CMD_TCP ? "tcp" : "udp", host, port);
        if (send_vless_response_header(s, send_ws, send_user_data) != 0) return -1;

        size_t left = s->in_len - used;
        if (cmd == VLESS_CMD_TCP) {
            if (left && send_origin(origin_user_data, s->in + used, left, 0) != 0) return -1;
            s->in_len = 0;
        } else {
            if (left) {
                uint8_t tail[BUF_SIZE * 4];
                if (left > sizeof(tail)) return -1;
                memcpy(tail, s->in + used, left);
                s->in_len = 0;
                if (handle_udp_payload(s, tail, left, send_origin, origin_user_data) != 0)
                    return -1;
            } else {
                s->in_len = 0;
            }
        }
        return 0;
    }

    if (s->cmd == VLESS_CMD_TCP) {
        return send_origin(origin_user_data, data, len, 0);
    }
    return handle_udp_payload(s, data, len, send_origin, origin_user_data);
}

int vless_send_origin_data(vless_stream_t *s, const uint8_t *data, size_t len,
                           vless_send_ws_cb send_ws, void *send_user_data) {
    if (s->cmd == VLESS_CMD_UDP) return send_vless_udp_packet(s, data, len, send_ws, send_user_data);
    return send_ws(send_user_data, data, len);
}
