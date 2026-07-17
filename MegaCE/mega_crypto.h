#ifndef MEGA_CRYPTO_H
#define MEGA_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

int mega_crypto_v1_user_hash(
    const char *email,
    const char *password,
    char *user_hash,
    unsigned int user_hash_size
);

int mega_crypto_base64url_encode(
    const unsigned char *data,
    int data_len,
    char *out,
    unsigned int out_size
);

int mega_crypto_base64url_decode(
    const char *text,
    unsigned char *out,
    unsigned int out_size
);

int mega_crypto_aes128_decrypt_block(
    const unsigned char *key,
    unsigned char *block
);

int mega_crypto_aes128_encrypt_block(
    const unsigned char *key,
    unsigned char *block
);

int mega_crypto_random_bytes(unsigned char *buffer, unsigned int buffer_size);

int mega_crypto_v2_derive_key(
    const char *password,
    const char *salt_b64,
    unsigned char *derived_key,
    unsigned int derived_key_size
);

int mega_crypto_self_test(char *report, unsigned int report_size);

void mega_crypto_zero(void *buffer, unsigned int buffer_size);

#ifdef __cplusplus
}
#endif

#endif
