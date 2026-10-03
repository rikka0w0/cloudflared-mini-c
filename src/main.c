#include "edge_h2.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

static void usage(const char *argv0) {
    fprintf(stderr, "usage: %s tunnel --protocol http2 run --token TOKEN [--websockify PATH] [--vless PATH]\n", argv0);
}

static int normalize_path_arg(const char *name, const char **path) {
    if ((*path)[0] == '/') (*path)++;
    if (!**path || strchr(*path, '/')) {
        fprintf(stderr, "invalid %s path\n", name);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 6 || strcmp(argv[1], "tunnel") != 0 || strcmp(argv[2], "--protocol") != 0 ||
        strcmp(argv[3], "http2") != 0 || strcmp(argv[4], "run") != 0) {
        usage(argv[0]);
        return 2;
    }

    const char *token_s = NULL;
    const char *websockify_path = NULL;
    const char *vless_path = NULL;

    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            token_s = argv[++i];
        } else if (strcmp(argv[i], "--websockify") == 0 && i + 1 < argc) {
            websockify_path = argv[++i];
            if (normalize_path_arg("--websockify", &websockify_path) != 0) return 2;
        } else if (strcmp(argv[i], "--vless") == 0 && i + 1 < argc) {
            vless_path = argv[++i];
            if (normalize_path_arg("--vless", &vless_path) != 0) return 2;
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (!token_s) {
        fprintf(stderr, "--token is required\n");
        return 2;
    }

    tunnel_token_t token;
    if (parse_token(token_s, &token) != 0) {
        fprintf(stderr, "failed to parse tunnel token\n");
        return 2;
    }
    fprintf(stderr, "loaded token: account=%s secret_len=%zu\n", token.account_tag,
            token.tunnel_secret_len);
    return run_edge_h2(&token, websockify_path, vless_path);
}
