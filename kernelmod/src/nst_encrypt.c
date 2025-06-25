// 加密解密
#include "nst.h"

bool nst_encrypt_enable = true;      // 加密启用
bool nst_decrypt_enable = true;      // 解密启用

// 秘钥盒


int nst_modify_key(u16 kpos, u16 kval){
    return 0;
}

int nst_encrypt_skb(struct sk_buff *skb, const u8 *key, size_t keylen, struct net_device *dev){
    return 0;
}
int nst_decrypt_skb(struct sk_buff *skb, const u8 *key, size_t keylen){
    return 0;
}