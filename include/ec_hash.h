#ifndef ETTERCAP_HASH_H_5A6177A238384013B5C415DA1653A43C
#define ETTERCAP_HASH_H_5A6177A238384013B5C415DA1653A43C

#include <stdio.h>

typedef unsigned long Fnv32_t;
#define FNV1_32_INIT ((Fnv32_t)0x811c9dc5)

typedef unsigned long long Fnv64_t;
#define FNV1_64_INIT ((Fnv64_t)0xcbf29ce484222325ULL)

EC_API_EXTERN Fnv32_t fnv_32(void *buf, size_t len);
EC_API_EXTERN Fnv64_t fnv_64(void *buf, size_t len);

#endif /* __FNV_H__ */

