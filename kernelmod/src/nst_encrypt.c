// 加密解密
#include "nst.h"

bool nst_encrypt_enable;      // 加密启用
bool nst_decrypt_enable;      // 解密启用

int nst_encrypt_skb(struct sk_buff *skb, const u8 *key, size_t keylen, struct net_device *dev){
    return 0;
}
int nst_decrypt_skb(struct sk_buff *skb, const u8 *key, size_t keylen){
    return 0;
}