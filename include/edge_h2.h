#pragma once

#include "common.h"

int run_edge_h2(const tunnel_token_t *token, route_t *routes, size_t route_count,
                const char *websockify_path, const char *vless_path);
