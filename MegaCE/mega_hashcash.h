#ifndef MEGA_HASHCASH_H
#define MEGA_HASHCASH_H

#ifdef __cplusplus
extern "C" {
#endif

int mega_hashcash_parse_header(
    const char *headers,
    char *token,
    unsigned int token_size,
    unsigned int *easiness
);

int mega_hashcash_solve(
    const char *token,
    unsigned int easiness,
    char *prefix_b64,
    unsigned int prefix_b64_size
);

#ifdef __cplusplus
}
#endif

#endif
