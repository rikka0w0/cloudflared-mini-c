#ifndef JSON_HELPER_H
#define JSON_HELPER_H

#include <stddef.h>

const char *find_json_key(const char *start, const char *end, const char *key);
int json_string_in_range(const char *start, const char *end, const char *key, char *out,
                         size_t out_cap);
int json_int_in_range(const char *start, const char *end, const char *key, int *out);
const char *json_matching(const char *p, const char *end, char open, char close);

#endif
