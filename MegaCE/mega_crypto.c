#include <string.h>
#include <stdio.h>
#include <windows.h>
#include "mega_crypto.h"
#include "mega_http.h"

typedef unsigned char mega_byte;

typedef void (*wm_crypto_progress_fn)(const char *message, void *user_data);
typedef int (*wm_pbkdf2_sha512_b64salt_fn)(
    const char *password,
    const char *salt_b64,
    unsigned int iterations,
    unsigned char *out,
    unsigned int out_len,
    wm_crypto_progress_fn progress,
    void *progress_user_data
);

void
mega_crypto_zero(void *buffer, unsigned int buffer_size)
{
    volatile mega_byte *p;

    p = (volatile mega_byte *)buffer;
    while (p != 0 && buffer_size > 0) {
        *p++ = 0;
        buffer_size--;
    }
}

static const mega_byte AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const mega_byte AES_INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const mega_byte AES_RCON[10] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static mega_byte
aes_xtime(mega_byte x)
{
    return (mega_byte)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

static mega_byte
aes_mul(mega_byte a, mega_byte b)
{
    mega_byte result;

    result = 0;
    while (b != 0) {
        if ((b & 1) != 0) {
            result ^= a;
        }
        a = aes_xtime(a);
        b >>= 1;
    }

    return result;
}

static void
aes_key_expand(const mega_byte *key, mega_byte *round_key)
{
    int i;
    mega_byte temp[4];

    memcpy(round_key, key, 16);
    for (i = 4; i < 44; ++i) {
        temp[0] = round_key[(i - 1) * 4 + 0];
        temp[1] = round_key[(i - 1) * 4 + 1];
        temp[2] = round_key[(i - 1) * 4 + 2];
        temp[3] = round_key[(i - 1) * 4 + 3];

        if ((i & 3) == 0) {
            mega_byte t;

            t = temp[0];
            temp[0] = (mega_byte)(AES_SBOX[temp[1]] ^ AES_RCON[(i / 4) - 1]);
            temp[1] = AES_SBOX[temp[2]];
            temp[2] = AES_SBOX[temp[3]];
            temp[3] = AES_SBOX[t];
        }

        round_key[i * 4 + 0] = (mega_byte)(round_key[(i - 4) * 4 + 0] ^ temp[0]);
        round_key[i * 4 + 1] = (mega_byte)(round_key[(i - 4) * 4 + 1] ^ temp[1]);
        round_key[i * 4 + 2] = (mega_byte)(round_key[(i - 4) * 4 + 2] ^ temp[2]);
        round_key[i * 4 + 3] = (mega_byte)(round_key[(i - 4) * 4 + 3] ^ temp[3]);
    }
}

static void
aes_add_round_key(mega_byte *state, const mega_byte *round_key)
{
    int i;

    for (i = 0; i < 16; ++i) {
        state[i] ^= round_key[i];
    }
}

static void
aes_sub_bytes(mega_byte *state)
{
    int i;

    for (i = 0; i < 16; ++i) {
        state[i] = AES_SBOX[state[i]];
    }
}

static void
aes_inv_sub_bytes(mega_byte *state)
{
    int i;

    for (i = 0; i < 16; ++i) {
        state[i] = AES_INV_SBOX[state[i]];
    }
}

static void
aes_shift_rows(mega_byte *s)
{
    mega_byte t;

    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static void
aes_inv_shift_rows(mega_byte *s)
{
    mega_byte t;

    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

static void
aes_mix_columns(mega_byte *s)
{
    int i;

    for (i = 0; i < 4; ++i) {
        mega_byte *c;
        mega_byte a0;
        mega_byte a1;
        mega_byte a2;
        mega_byte a3;
        mega_byte t;
        mega_byte u;

        c = s + i * 4;
        a0 = c[0];
        a1 = c[1];
        a2 = c[2];
        a3 = c[3];
        t = (mega_byte)(a0 ^ a1 ^ a2 ^ a3);
        u = a0;
        c[0] ^= (mega_byte)(t ^ aes_xtime((mega_byte)(a0 ^ a1)));
        c[1] ^= (mega_byte)(t ^ aes_xtime((mega_byte)(a1 ^ a2)));
        c[2] ^= (mega_byte)(t ^ aes_xtime((mega_byte)(a2 ^ a3)));
        c[3] ^= (mega_byte)(t ^ aes_xtime((mega_byte)(a3 ^ u)));
    }
}

static void
aes_inv_mix_columns(mega_byte *s)
{
    int i;

    for (i = 0; i < 4; ++i) {
        mega_byte *c;
        mega_byte a0;
        mega_byte a1;
        mega_byte a2;
        mega_byte a3;

        c = s + i * 4;
        a0 = c[0];
        a1 = c[1];
        a2 = c[2];
        a3 = c[3];

        c[0] = (mega_byte)(aes_mul(a0, 0x0e) ^ aes_mul(a1, 0x0b)
            ^ aes_mul(a2, 0x0d) ^ aes_mul(a3, 0x09));
        c[1] = (mega_byte)(aes_mul(a0, 0x09) ^ aes_mul(a1, 0x0e)
            ^ aes_mul(a2, 0x0b) ^ aes_mul(a3, 0x0d));
        c[2] = (mega_byte)(aes_mul(a0, 0x0d) ^ aes_mul(a1, 0x09)
            ^ aes_mul(a2, 0x0e) ^ aes_mul(a3, 0x0b));
        c[3] = (mega_byte)(aes_mul(a0, 0x0b) ^ aes_mul(a1, 0x0d)
            ^ aes_mul(a2, 0x09) ^ aes_mul(a3, 0x0e));
    }
}

static void
aes_encrypt_block(const mega_byte *key, mega_byte *block)
{
    mega_byte round_key[176];
    int round;

    aes_key_expand(key, round_key);
    aes_add_round_key(block, round_key);
    for (round = 1; round < 10; ++round) {
        aes_sub_bytes(block);
        aes_shift_rows(block);
        aes_mix_columns(block);
        aes_add_round_key(block, round_key + round * 16);
    }
    aes_sub_bytes(block);
    aes_shift_rows(block);
    aes_add_round_key(block, round_key + 160);
}

int
mega_crypto_aes128_encrypt_block(
    const unsigned char *key,
    unsigned char *block
)
{
    if (key == 0 || block == 0) {
        return 0;
    }
    aes_encrypt_block((const mega_byte *)key, (mega_byte *)block);
    return 1;
}

int
mega_crypto_aes128_decrypt_block(
    const unsigned char *key,
    unsigned char *block
)
{
    mega_byte round_key[176];
    int round;

    if (key == 0 || block == 0) {
        return 0;
    }

    aes_key_expand((const mega_byte *)key, round_key);
    aes_add_round_key((mega_byte *)block, round_key + 160);
    for (round = 9; round > 0; --round) {
        aes_inv_shift_rows((mega_byte *)block);
        aes_inv_sub_bytes((mega_byte *)block);
        aes_add_round_key((mega_byte *)block, round_key + round * 16);
        aes_inv_mix_columns((mega_byte *)block);
    }
    aes_inv_shift_rows((mega_byte *)block);
    aes_inv_sub_bytes((mega_byte *)block);
    aes_add_round_key((mega_byte *)block, round_key);

    mega_crypto_zero(round_key, sizeof(round_key));
    return 1;
}

static void
ascii_lower_copy(const char *src, char *dst, unsigned int dst_size)
{
    unsigned int used;

    used = 0;
    if (dst_size == 0) {
        return;
    }

    while (src != 0 && *src != '\0' && used + 1 < dst_size) {
        char ch;

        ch = *src++;
        if (ch >= 'A' && ch <= 'Z') {
            ch = (char)(ch - 'A' + 'a');
        }
        dst[used++] = ch;
    }
    dst[used] = '\0';
}

int
mega_crypto_base64url_decode(
    const char *text,
    unsigned char *out,
    unsigned int out_size
)
{
    unsigned int accum;
    int bits;
    unsigned int used;

    if (text == 0 || out == 0) {
        return -1;
    }

    accum = 0;
    bits = 0;
    used = 0;

    while (*text != '\0') {
        char ch;
        int value;

        ch = *text++;
        if (ch >= 'A' && ch <= 'Z') {
            value = ch - 'A';
        } else if (ch >= 'a' && ch <= 'z') {
            value = ch - 'a' + 26;
        } else if (ch >= '0' && ch <= '9') {
            value = ch - '0' + 52;
        } else if (ch == '-') {
            value = 62;
        } else if (ch == '_') {
            value = 63;
        } else if (ch == '=') {
            break;
        } else {
            return -1;
        }

        accum = (accum << 6) | (unsigned int)value;
        bits += 6;
        while (bits >= 8) {
            bits -= 8;
            if (used >= out_size) {
                return -1;
            }
            out[used++] = (unsigned char)((accum >> bits) & 0xff);
        }
    }

    return (int)used;
}

int
mega_crypto_base64url_encode(
    const unsigned char *data,
    int data_len,
    char *out,
    unsigned int out_size
)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    unsigned int used;
    int i;

    used = 0;
    i = 0;
    while (i < data_len) {
        int remain;
        unsigned int value;
        int chars;
        int c;

        remain = data_len - i;
        value = (unsigned int)data[i] << 16;
        if (remain > 1) {
            value |= (unsigned int)data[i + 1] << 8;
        }
        if (remain > 2) {
            value |= (unsigned int)data[i + 2];
        }

        chars = remain >= 3 ? 4 : remain + 1;
        if (used + (unsigned int)chars >= out_size) {
            return 0;
        }

        for (c = 0; c < chars; ++c) {
            out[used++] = alphabet[(value >> (18 - c * 6)) & 0x3f];
        }
        i += 3;
    }

    if (used >= out_size) {
        return 0;
    }
    out[used] = '\0';
    return 1;
}

int
mega_crypto_random_bytes(unsigned char *buffer, unsigned int buffer_size)
{
    SYSTEMTIME st;
    DWORD x;
    unsigned int i;

    if (buffer == 0 && buffer_size > 0) {
        return 0;
    }

    GetSystemTime(&st);
    x = GetTickCount();
    x ^= ((DWORD)st.wMilliseconds << 16) ^ (DWORD)st.wSecond;
    x ^= ((DWORD)st.wMinute << 24) ^ ((DWORD)st.wHour << 8);
    x ^= (DWORD)(unsigned long)buffer;

    for (i = 0; i < buffer_size; ++i) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        buffer[i] = (unsigned char)(x & 0xff);
    }

    return 1;
}

static void
mega_crypto_dll_progress(const char *message, void *user_data)
{
    (void)user_data;
    mega_http_progress_message(message);
}

int
mega_crypto_v2_derive_key(
    const char *password,
    const char *salt_b64,
    unsigned char *derived_key,
    unsigned int derived_key_size
)
{
    HMODULE dll;
    wm_pbkdf2_sha512_b64salt_fn pbkdf2;
    int ok;

    if (password == 0 || salt_b64 == 0 || derived_key == 0 || derived_key_size == 0) {
        return 0;
    }

    dll = LoadLibrary(TEXT("wm_https.dll"));
    if (dll == 0) {
        return 0;
    }

    pbkdf2 = (wm_pbkdf2_sha512_b64salt_fn)GetProcAddressA(dll,
        "wm_pbkdf2_sha512_b64salt");
    if (pbkdf2 == 0) {
        FreeLibrary(dll);
        return 0;
    }

    mega_http_progress_message("Deriving MEGA v2 login key...");
    ok = pbkdf2(password, salt_b64, 100000U, derived_key, derived_key_size,
        mega_crypto_dll_progress, 0);
    FreeLibrary(dll);
    return ok;
}

static int
bytes_equal(const mega_byte *a, const mega_byte *b, int len)
{
    int i;
    mega_byte diff;

    diff = 0;
    for (i = 0; i < len; ++i) {
        diff |= (mega_byte)(a[i] ^ b[i]);
    }

    return diff == 0;
}

static int v1_user_hash_sdk_bytes(
    const char *email,
    const char *password,
    char *user_hash,
    unsigned int user_hash_size
);

int
mega_crypto_self_test(char *report, unsigned int report_size)
{
    static const mega_byte aes_key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const mega_byte aes_expected[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };
    static const mega_byte aes_plain[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    mega_byte aes_block[16];
    char hash[32];
    int aes_ok;
    int aes_decrypt_ok;
    int hash_ok;

    aes_block[0] = 0x00; aes_block[1] = 0x11; aes_block[2] = 0x22; aes_block[3] = 0x33;
    aes_block[4] = 0x44; aes_block[5] = 0x55; aes_block[6] = 0x66; aes_block[7] = 0x77;
    aes_block[8] = 0x88; aes_block[9] = 0x99; aes_block[10] = 0xaa; aes_block[11] = 0xbb;
    aes_block[12] = 0xcc; aes_block[13] = 0xdd; aes_block[14] = 0xee; aes_block[15] = 0xff;

    aes_encrypt_block(aes_key, aes_block);
    aes_ok = bytes_equal(aes_block, aes_expected, 16);
    mega_crypto_aes128_decrypt_block(aes_key, aes_block);
    aes_decrypt_ok = bytes_equal(aes_block, aes_plain, 16);

    hash[0] = '\0';
    hash_ok = mega_crypto_v1_user_hash("test@example.com", "password",
        hash, sizeof(hash));

    if (report != 0 && report_size > 0) {
        _snprintf(report, report_size,
            "crypto self-test: AES=%s AESdec=%s sample_uh=%s",
            aes_ok ? "ok" : "FAIL",
            aes_decrypt_ok ? "ok" : "FAIL",
            hash_ok ? hash : "(failed)");
        report[report_size - 1] = '\0';
    }

    return aes_ok && aes_decrypt_ok && hash_ok;
}

int
mega_crypto_v1_user_hash(
    const char *email,
    const char *password,
    char *user_hash,
    unsigned int user_hash_size
)
{
    return v1_user_hash_sdk_bytes(email, password, user_hash, user_hash_size);
}

static int
prepare_key_bytes(const char *password, mega_byte *out_key)
{
    static const mega_byte initial_key[16] = {
        0x93,0xc4,0x67,0xe3,0x7d,0xb0,0xc7,0xa4,
        0xd1,0xbe,0x3f,0x81,0x01,0x52,0xcb,0x56
    };
    mega_byte keys[16][16];
    mega_byte key_buffer[16];
    int password_len;
    int block_count;
    int block;
    int round;

    if (password == 0 || out_key == 0) {
        return 0;
    }

    password_len = (int)strlen(password);
    if (password_len <= 0) {
        return 0;
    }

    block_count = (password_len + 15) / 16;
    if (block_count <= 0 || block_count > 16) {
        return 0;
    }

    memset(keys, 0, sizeof(keys));
    for (block = 0; block < block_count; ++block) {
        int available;

        available = password_len - block * 16;
        if (available > 16) {
            available = 16;
        }
        memcpy(keys[block], password + block * 16, available);
    }

    memcpy(key_buffer, initial_key, sizeof(key_buffer));
    for (round = 0; round < 65536; ++round) {
        for (block = 0; block < block_count; ++block) {
            aes_encrypt_block(keys[block], key_buffer);
        }
    }

    memcpy(out_key, key_buffer, 16);
    mega_crypto_zero(keys, sizeof(keys));
    mega_crypto_zero(key_buffer, sizeof(key_buffer));
    return 1;
}

static int
v1_user_hash_sdk_bytes(
    const char *email,
    const char *password,
    char *user_hash,
    unsigned int user_hash_size
)
{
    mega_byte password_key[16];
    mega_byte hash[16];
    char lowered_email[256];
    int email_len;
    int full_len;
    int i;

    if (email == 0 || password == 0 || user_hash == 0 || user_hash_size == 0) {
        return 0;
    }

    if (!prepare_key_bytes(password, password_key)) {
        return 0;
    }

    ascii_lower_copy(email, lowered_email, sizeof(lowered_email));
    email_len = (int)strlen(lowered_email);
    if (email_len <= 0) {
        mega_crypto_zero(password_key, sizeof(password_key));
        return 0;
    }

    memset(hash, 0, sizeof(hash));
    full_len = email_len & ~15;
    if (email_len > full_len) {
        memcpy(hash, lowered_email + full_len, email_len - full_len);
    }

    while (full_len > 0) {
        full_len -= 16;
        for (i = 0; i < 16; ++i) {
            hash[i] ^= (mega_byte)lowered_email[full_len + i];
        }
    }

    for (i = 0; i < 16384; ++i) {
        aes_encrypt_block(password_key, hash);
    }

    memcpy(hash + 4, hash + 8, 4);
    i = mega_crypto_base64url_encode(hash, 8, user_hash, user_hash_size);

    mega_crypto_zero(password_key, sizeof(password_key));
    mega_crypto_zero(hash, sizeof(hash));
    return i;
}
