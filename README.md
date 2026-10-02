# cloudflared-mini-c

Minimal Linux `cloudflared tunnel --protocol http2 run` client in C.

Run:

```sh
./cloudflared-mini tunnel --protocol http2 run --token TOKEN --websockify websockify
```

Routes come from the Cloudflare-managed tunnel configuration.

Supported `service` schemes:

- `http://host:port`: proxy HTTP requests to an HTTP/1.1 origin. WebSocket
  upgrade requests are passed through to the origin server.

When `--websockify PATH` is set, `/<PATH>/<host>/<port>` is checked before the
HTTP origin. If it is a WebSocket upgrade request, WebSocket binary frames are
bridged to the requested TCP endpoint. Non-WebSocket requests under that path
return 404.

For binary protocols such as SSH over WebSocket, use `websocat --binary`; `-t`
forces text frames and corrupts binary SSH packets.

Build:

```sh
make
```

The Makefile downloads and statically builds `nghttp2` from source if it is not
already present under `.deps/`. Static builds also download and build OpenSSL
1.1.1w under `.deps/openssl`.

TLS certificate verification to Cloudflare edge is currently disabled in this
minimal client.

Cross-compile for OpenWrt MIPS32 big-endian:

```sh
STAGING_DIR=$HOME/mcp/openwrt/staging_dir \
make CROSS_COMPILE=$HOME/mcp/openwrt/staging_dir/toolchain-mips_mips32_gcc-14.3.0_musl/bin/mips-openwrt-linux-musl- \
  OPENSSL_TARGET=linux-mips32 \
  BIN=cloudflared-mips-be
```
