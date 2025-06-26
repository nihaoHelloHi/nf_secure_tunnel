//
// Created by tangmin on 25-6-25.
//

#include "nst.h"

int nst_encrypt_aes_gcm(const u8 *in, size_t in_len, u8 *out, size_t *out_len,
                        const u8 *key, size_t key_len, const u8 *aad, size_t aad_len){
    return OK;
}
int nst_decrypt_aes_gcm(const u8 *in, size_t in_len, u8 *out, size_t *out_len,
                        const u8 *key, size_t key_len, const u8 *aad, size_t aad_len){
    return OK;
}

int nst_encrypt_aes_cbc_hmac(const u8 *in, size_t in_len, u8 *out, size_t *out_len,
                             const u8 *key, size_t key_len){
    return OK;
}
int nst_decrypt_aes_cbc_hmac(const u8 *in, size_t in_len, u8 *out, size_t *out_len,
                             const u8 *key, size_t key_len){
    return OK;
}

int nst_encrypt_sm4_gcm(const u8 *in, size_t in_len, u8 *out, size_t *out_len,
                        const u8 *key, size_t key_len, const u8 *aad, size_t aad_len){
    return OK;
}
int nst_decrypt_sm4_gcm(const u8 *in, size_t in_len, u8 *out, size_t *out_len,
                        const u8 *key, size_t key_len, const u8 *aad, size_t aad_len){
    return OK;
}

int nst_encrypt_sm4_cbc_sm3(const u8 *in, size_t in_len, u8 *out, size_t *out_len,
                            const u8 *key, size_t key_len){
    return OK;
}
int nst_decrypt_sm4_cbc_sm3(const u8 *in, size_t in_len, u8 *out, size_t *out_len,
                            const u8 *key, size_t key_len){
    return OK;
}
