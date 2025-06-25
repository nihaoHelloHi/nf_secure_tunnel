// 加密解密
#include "nst.h"

bool nst_encrypt_enable = true;      // 加密启用
bool nst_decrypt_enable = true;      // 解密启用

// 秘钥盒
u8 nst_keybox[ENCRYPT_BOX_MAX_KEYS][ENCRYPT_KEY_LEN];

void init_keybox(){

}

int nst_mutate_key(u8 kpos, u8 kval){
    return 0;
}

/*
 * 使用扰动后的秘钥进行加密
 * 不加密nst_hdr，只加密payload
 * */
int nst_encrypt_skb(struct sk_buff *skb, struct nst_hdr *nsthdr){
    // 取出传输层payload



    // 加密

    // 更新tcp/udp len， ip len

    return 0;
}

int nst_decrypt_skb(struct sk_buff *skb, const u8 *key, size_t keylen){
    return 0;
}