#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "mega_hashcash.h"
#include "mega_crypto.h"
#include "mega_http.h"

typedef unsigned char hc_u8;
typedef unsigned long hc_u32;

typedef void (*wm_hashcash_progress_fn)(const char *message, void *user_data);
typedef int (*wm_hashcash_solve_fn)(
    const char *token,
    unsigned int easiness,
    char *prefix_b64,
    unsigned int prefix_b64_size,
    wm_hashcash_progress_fn progress,
    void *progress_user_data
);

#define HC_TOKEN_BYTES 48
#define HC_PREFIX_BYTES 4
#define HC_REPEAT 262144UL
#define HC_TIMEOUT_MS 300000UL

typedef struct hc_sha256 {
    hc_u32 state[8];
    unsigned __int64 bit_count;
    hc_u8 buffer[64];
} hc_sha256;

static const hc_u32 HC_SHA256_K[64] = {
    0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,
    0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
    0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
    0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
    0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,
    0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
    0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,
    0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
    0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
    0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
    0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,
    0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
    0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,
    0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
    0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
    0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

static hc_u32
hc_rotr(hc_u32 v, int n)
{
    return (v >> n) | (v << (32 - n));
}

static hc_u32
hc_load_be32(const hc_u8 *p)
{
    return ((hc_u32)p[0] << 24) | ((hc_u32)p[1] << 16)
        | ((hc_u32)p[2] << 8) | (hc_u32)p[3];
}

static void
hc_store_be32(hc_u8 *p, hc_u32 v)
{
    p[0] = (hc_u8)((v >> 24) & 0xff);
    p[1] = (hc_u8)((v >> 16) & 0xff);
    p[2] = (hc_u8)((v >> 8) & 0xff);
    p[3] = (hc_u8)(v & 0xff);
}

static void
hc_sha256_block(hc_sha256 *ctx, const hc_u8 *block)
{
    hc_u32 w[64];
    hc_u32 a;
    hc_u32 b;
    hc_u32 c;
    hc_u32 d;
    hc_u32 e;
    hc_u32 f;
    hc_u32 g;
    hc_u32 h;
    int i;

    for (i = 0; i < 16; ++i) {
        w[i] = hc_load_be32(block + i * 4);
    }
    for (i = 16; i < 64; ++i) {
        hc_u32 s0;
        hc_u32 s1;

        s0 = hc_rotr(w[i - 15], 7) ^ hc_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        s1 = hc_rotr(w[i - 2], 17) ^ hc_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        hc_u32 s1;
        hc_u32 ch;
        hc_u32 temp1;
        hc_u32 s0;
        hc_u32 maj;
        hc_u32 temp2;

        s1 = hc_rotr(e, 6) ^ hc_rotr(e, 11) ^ hc_rotr(e, 25);
        ch = (e & f) ^ ((~e) & g);
        temp1 = h + s1 + ch + HC_SHA256_K[i] + w[i];
        s0 = hc_rotr(a, 2) ^ hc_rotr(a, 13) ^ hc_rotr(a, 22);
        maj = (a & b) ^ (a & c) ^ (b & c);
        temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void
hc_sha256_init(hc_sha256 *ctx)
{
    ctx->state[0] = 0x6a09e667UL;
    ctx->state[1] = 0xbb67ae85UL;
    ctx->state[2] = 0x3c6ef372UL;
    ctx->state[3] = 0xa54ff53aUL;
    ctx->state[4] = 0x510e527fUL;
    ctx->state[5] = 0x9b05688cUL;
    ctx->state[6] = 0x1f83d9abUL;
    ctx->state[7] = 0x5be0cd19UL;
    ctx->bit_count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

static void
hc_sha256_update(hc_sha256 *ctx, const hc_u8 *data, unsigned int len)
{
    unsigned int used;

    used = (unsigned int)((ctx->bit_count >> 3) & 63);
    ctx->bit_count += ((unsigned __int64)len) << 3;

    if (used != 0) {
        unsigned int free_bytes;

        free_bytes = 64 - used;
        if (len < free_bytes) {
            memcpy(ctx->buffer + used, data, len);
            return;
        }

        memcpy(ctx->buffer + used, data, free_bytes);
        hc_sha256_block(ctx, ctx->buffer);
        data += free_bytes;
        len -= free_bytes;
    }

    while (len >= 64) {
        hc_sha256_block(ctx, data);
        data += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx->buffer, data, len);
    }
}

static void
hc_sha256_final(hc_sha256 *ctx, hc_u8 *digest)
{
    unsigned int used;
    int i;

    used = (unsigned int)((ctx->bit_count >> 3) & 63);
    ctx->buffer[used++] = 0x80;

    if (used > 56) {
        memset(ctx->buffer + used, 0, 64 - used);
        hc_sha256_block(ctx, ctx->buffer);
        used = 0;
    }

    memset(ctx->buffer + used, 0, 56 - used);
    ctx->buffer[56] = (hc_u8)((ctx->bit_count >> 56) & 0xff);
    ctx->buffer[57] = (hc_u8)((ctx->bit_count >> 48) & 0xff);
    ctx->buffer[58] = (hc_u8)((ctx->bit_count >> 40) & 0xff);
    ctx->buffer[59] = (hc_u8)((ctx->bit_count >> 32) & 0xff);
    ctx->buffer[60] = (hc_u8)((ctx->bit_count >> 24) & 0xff);
    ctx->buffer[61] = (hc_u8)((ctx->bit_count >> 16) & 0xff);
    ctx->buffer[62] = (hc_u8)((ctx->bit_count >> 8) & 0xff);
    ctx->buffer[63] = (hc_u8)(ctx->bit_count & 0xff);
    hc_sha256_block(ctx, ctx->buffer);

    for (i = 0; i < 8; ++i) {
        hc_store_be32(digest + i * 4, ctx->state[i]);
    }
}

static int
hc_from64(char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A';
    }
    if (ch >= 'a' && ch <= 'z') {
        return ch - 'a' + 26;
    }
    if (ch >= '0' && ch <= '9') {
        return ch - '0' + 52;
    }
    if (ch == '-' || ch == '+') {
        return 62;
    }
    if (ch == '_' || ch == '/') {
        return 63;
    }
    return -1;
}

static int
hc_base64url_decode(const char *text, hc_u8 *out, unsigned int out_size)
{
    unsigned int used;
    unsigned int bitbuf;
    int bitcount;

    used = 0;
    bitbuf = 0;
    bitcount = 0;
    while (text != 0 && *text != '\0') {
        int v;

        if (*text == '=') {
            break;
        }

        v = hc_from64(*text++);
        if (v < 0) {
            return -1;
        }

        bitbuf = (bitbuf << 6) | (unsigned int)v;
        bitcount += 6;
        if (bitcount >= 8) {
            bitcount -= 8;
            if (used >= out_size) {
                return -1;
            }
            out[used++] = (hc_u8)((bitbuf >> bitcount) & 0xff);
        }
    }

    return (int)used;
}

static int
hc_header_name_equals(const char *line, const char *name)
{
    while (*name != '\0' && *line != '\0') {
        char a;
        char b;

        a = *line++;
        b = *name++;
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = (char)(b - 'A' + 'a');
        }
        if (a != b) {
            return 0;
        }
    }

    return *name == '\0' && *line == ':';
}

int
mega_hashcash_parse_header(
    const char *headers,
    char *token,
    unsigned int token_size,
    unsigned int *easiness
)
{
    const char *line;

    if (token != 0 && token_size > 0) {
        token[0] = '\0';
    }
    if (easiness != 0) {
        *easiness = 0;
    }

    if (headers == 0 || token == 0 || token_size < 65 || easiness == 0) {
        return 0;
    }

    line = headers;
    while (*line != '\0') {
        const char *next;

        next = strstr(line, "\r\n");
        if (next == 0) {
            next = line + strlen(line);
        }

        if (hc_header_name_equals(line, "X-Hashcash")) {
            const char *p;
            const char *field;
            int version;
            int easy;
            unsigned int len;

            p = strchr(line, ':');
            if (p == 0 || p >= next) {
                return 0;
            }
            p++;
            while (p < next && (*p == ' ' || *p == '\t')) {
                p++;
            }

            version = atoi(p);
            p = strchr(p, ':');
            if (p == 0 || p >= next || version != 1) {
                return 0;
            }
            p++;

            easy = atoi(p);
            if (easy < 0 || easy > 255) {
                return 0;
            }
            p = strchr(p, ':');
            if (p == 0 || p >= next) {
                return 0;
            }
            p++;

            p = strchr(p, ':');
            if (p == 0 || p >= next) {
                return 0;
            }
            p++;
            field = p;
            while (p < next && *p > ' ') {
                p++;
            }

            len = (unsigned int)(p - field);
            if (len != 64 || len >= token_size) {
                return 0;
            }

            memcpy(token, field, len);
            token[len] = '\0';
            *easiness = (unsigned int)easy;
            return 1;
        }

        line = *next == '\0' ? next : next + 2;
    }

    return 0;
}

static hc_u32
hc_threshold_from_easiness(unsigned int e)
{
    unsigned int shift;

    shift = ((e >> 6) * 7) + 3;
    return (hc_u32)((((e & 63) << 1) + 1) << shift);
}

static void
hc_dll_progress(const char *message, void *user_data)
{
    (void)user_data;
    mega_http_progress_message(message);
}

static int
hc_try_dll_solver(
    const char *token,
    unsigned int easiness,
    char *prefix_b64,
    unsigned int prefix_b64_size,
    int *attempted
)
{
    HMODULE dll;
    wm_hashcash_solve_fn solve;
    int ok;

    if (attempted != 0) {
        *attempted = 0;
    }

    dll = LoadLibrary(TEXT("wm_https.dll"));
    if (dll == 0) {
        return 0;
    }

    solve = (wm_hashcash_solve_fn)GetProcAddressA(dll, "wm_hashcash_solve");
    if (solve == 0) {
        FreeLibrary(dll);
        return 0;
    }

    if (attempted != 0) {
        *attempted = 1;
    }
    mega_http_progress_message("Using BearSSL hashcash solver...");
    ok = solve(token, easiness, prefix_b64, prefix_b64_size,
        hc_dll_progress, 0);
    FreeLibrary(dll);
    return ok;
}

int
mega_hashcash_solve(
    const char *token,
    unsigned int easiness,
    char *prefix_b64,
    unsigned int prefix_b64_size
)
{
    hc_u8 token_bin[HC_TOKEN_BYTES];
    hc_u8 digest[32];
    hc_u8 prefix[HC_PREFIX_BYTES];
    hc_u8 first_block[64];
    hc_u8 fixed_blocks[3][64];
    hc_u32 threshold;
    hc_u32 nonce;
    int decoded;
    DWORD start_tick;
    DWORD last_progress_tick;
    int dll_attempted;

    if (token == 0 || prefix_b64 == 0 || prefix_b64_size == 0 || easiness > 255) {
        return 0;
    }

    if (hc_try_dll_solver(token, easiness, prefix_b64, prefix_b64_size,
        &dll_attempted))
    {
        return 1;
    }
    if (dll_attempted) {
        return 0;
    }

    decoded = hc_base64url_decode(token, token_bin, sizeof(token_bin));
    if (decoded != HC_TOKEN_BYTES) {
        return 0;
    }

    threshold = hc_threshold_from_easiness(easiness);

    memset(first_block, 0, sizeof(first_block));
    memcpy(first_block + 4, token_bin, HC_TOKEN_BYTES);
    memcpy(first_block + 4 + HC_TOKEN_BYTES, token_bin, 12);

    memcpy(fixed_blocks[0], token_bin + 12, 36);
    memcpy(fixed_blocks[0] + 36, token_bin, 28);
    memcpy(fixed_blocks[1], token_bin + 28, 20);
    memcpy(fixed_blocks[1] + 20, token_bin, 44);
    memcpy(fixed_blocks[2], token_bin + 44, 4);
    memcpy(fixed_blocks[2] + 4, token_bin, HC_TOKEN_BYTES);
    memcpy(fixed_blocks[2] + 52, token_bin, 12);

    start_tick = GetTickCount();
    last_progress_tick = start_tick;
    for (nonce = 0; ; ++nonce) {
        hc_sha256 ctx;
        hc_u32 first_word;
        unsigned long group;

        hc_store_be32(first_block, nonce);
        hc_sha256_init(&ctx);
        hc_sha256_block(&ctx, first_block);
        for (group = 0; group < 65535UL; ++group) {
            DWORD now_tick;

            hc_sha256_block(&ctx, fixed_blocks[0]);
            hc_sha256_block(&ctx, fixed_blocks[1]);
            hc_sha256_block(&ctx, fixed_blocks[2]);

            if ((group & 2047UL) == 2047UL) {
                now_tick = GetTickCount();
                if (now_tick - last_progress_tick >= 5000UL) {
                    char progress[112];

                    _snprintf(progress, sizeof(progress),
                        "Hashcash nonce %lu: %lu/65536 blocks in %lu seconds...",
                        nonce, group + 1UL, (now_tick - start_tick) / 1000UL);
                    progress[sizeof(progress) - 1] = '\0';
                    mega_http_progress_message(progress);
                    last_progress_tick = now_tick;
                }

                if (now_tick - start_tick >= HC_TIMEOUT_MS) {
                    mega_http_progress_message("Hashcash timed out.");
                    mega_crypto_zero(token_bin, sizeof(token_bin));
                    mega_crypto_zero(digest, sizeof(digest));
                    mega_crypto_zero(fixed_blocks, sizeof(fixed_blocks));
                    mega_crypto_zero(first_block, sizeof(first_block));
                    return 0;
                }
            }
        }
        hc_sha256_block(&ctx, fixed_blocks[0]);
        hc_sha256_block(&ctx, fixed_blocks[1]);
        ctx.bit_count = ((unsigned __int64)HC_REPEAT * HC_TOKEN_BYTES) << 3;
        hc_sha256_update(&ctx, token_bin + 44, 4);
        hc_sha256_final(&ctx, digest);

        first_word = hc_load_be32(digest);
        if (first_word <= threshold) {
            hc_store_be32(prefix, nonce);
            mega_crypto_zero(token_bin, sizeof(token_bin));
            mega_crypto_zero(digest, sizeof(digest));
            mega_crypto_zero(fixed_blocks, sizeof(fixed_blocks));
            mega_crypto_zero(first_block, sizeof(first_block));
            decoded = mega_crypto_base64url_encode(prefix, sizeof(prefix),
                prefix_b64, prefix_b64_size);
            mega_crypto_zero(prefix, sizeof(prefix));
            return decoded;
        }

        if ((nonce & 7UL) == 7UL) {
            char progress[96];
            DWORD elapsed;

            elapsed = (GetTickCount() - start_tick) / 1000UL;
            _snprintf(progress, sizeof(progress),
                "Hashcash tried %lu nonces in %lu seconds...",
                nonce + 1UL, elapsed);
            progress[sizeof(progress) - 1] = '\0';
            mega_http_progress_message(progress);
        }

        if (nonce == 0xffffffffUL) {
            break;
        }
    }

    mega_crypto_zero(token_bin, sizeof(token_bin));
    mega_crypto_zero(digest, sizeof(digest));
    mega_crypto_zero(fixed_blocks, sizeof(fixed_blocks));
    mega_crypto_zero(first_block, sizeof(first_block));
    return 0;
}
