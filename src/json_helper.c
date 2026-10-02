#include "json_helper.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static const char *skip_json_ws(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    return p;
}

const char *find_json_key(const char *start, const char *end, const char *key) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    size_t pat_len = strlen(pat);
    for (const char *p = start; p + pat_len <= end; p++) {
        if (memcmp(p, pat, pat_len) == 0) return p + pat_len;
    }
    return NULL;
}

int json_string_in_range(const char *start, const char *end, const char *key, char *out,
                         size_t out_cap) {
    const char *p = find_json_key(start, end, key);
    if (!p) return -1;
    p = memchr(p, ':', (size_t)(end - p));
    if (!p) return -1;
    p = skip_json_ws(p + 1, end);
    if (p >= end || *p != '"') return -1;
    p++;
    size_t n = 0;
    while (p < end && *p != '"') {
        if (*p == '\\' && p + 1 < end) p++;
        if (n + 1 < out_cap) out[n++] = *p;
        p++;
    }
    if (p >= end || *p != '"') return -1;
    out[n] = 0;
    return 0;
}

int json_int_in_range(const char *start, const char *end, const char *key, int *out) {
    const char *p = find_json_key(start, end, key);
    if (!p) return -1;
    p = memchr(p, ':', (size_t)(end - p));
    if (!p) return -1;
    p = skip_json_ws(p + 1, end);
    if (p >= end) return -1;
    *out = atoi(p);
    return 0;
}

const char *json_matching(const char *p, const char *end, char open, char close) {
    int depth = 0;
    int in_str = 0;
    int esc = 0;
    for (; p < end; p++) {
        if (in_str) {
            if (esc) esc = 0;
            else if (*p == '\\') esc = 1;
            else if (*p == '"') in_str = 0;
            continue;
        }
        if (*p == '"') in_str = 1;
        else if (*p == open) depth++;
        else if (*p == close) {
            depth--;
            if (depth == 0) return p + 1;
        }
    }
    return NULL;
}
