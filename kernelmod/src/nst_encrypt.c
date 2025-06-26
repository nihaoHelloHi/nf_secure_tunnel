// 加密解密
#include "nst.h"

bool nst_encrypt_enable = true;      // 加密启用
bool nst_decrypt_enable = true;      // 解密启用
u32 cur_key_num = 0;                 // 当前密钥数量

// 秘钥盒
u8 nst_keybox[ENCRYPT_BOX_MAX_KEYS][ENCRYPT_KEY_LEN];

void init_keybox(){

}

// 如果要有增删秘钥需要添加主机间的同步机制
int add_key(){
    return OK;
}

int del_key(){
    return OK;
}

int nst_mutate_key(u8* key, struct nst_hdr *nsthdr){
    int i = 0;
    u16 kid = be16_to_cpu(nsthdr->kid);
    u8* base_key = NULL;
    u16 end_pos = 0;

    if (kid >= cur_key_num)
        return -EINVAL;
    base_key = nst_keybox[kid];
    for (i = 0; i < ENCRYPT_KEY_LEN; ++i)
        key[i] = base_key[i];

    // 扰动
    end_pos = nsthdr->kpos + (nsthdr->kval % (ENCRYPT_KEY_LEN - nsthdr->kpos));
    if(end_pos > ENCRYPT_KEY_LEN)
        end_pos = ENCRYPT_KEY_LEN;
    for (i = (int)nsthdr->kpos; i < end_pos; ++i)
        key[i] ^= (u8)(nsthdr->kval >> (i - nsthdr->kpos));

    return OK;
}

/*
 * 使用扰动后的秘钥进行加密
 * 不加密nst_hdr，只加密payload
 * 并在payload中插入nst_hdr
 * */
int nst_encrypt_skb(struct sk_buff *skb, struct nst_hdr *nsthdr){
    // 取出传输层payload地址和长度
    u16 origin_pl_len = 0;
    u8* origin_pl = get_transport_payload(skb, &origin_pl_len);
    size_t encrypted_pl_max_len = sizeof(struct nst_hdr) + origin_pl_len + 32; // 保留padding或tag
    size_t encrypted_pl_len = encrypted_pl_max_len - sizeof(struct nst_hdr);
    u8 key[ENCRYPT_KEY_LEN];
    u8* encrypted_pack = NULL; // 整包包头起始地址
    u8* encrypted_pl = NULL; // 加密后pl起始地址
    int err = -1;
    const u8 *aad = (const u8 *)nsthdr;
    size_t aad_len = sizeof(struct nst_hdr);

    if (origin_pl == NULL || origin_pl_len == 0)
        return -EINVAL;

    // 获取扰动秘钥
    if (nst_mutate_key(key, nsthdr) != OK)
        return -EINVAL;

    // 分配输出缓冲区
    encrypted_pack = kmalloc(encrypted_pl_max_len, GFP_ATOMIC);
    encrypted_pl = encrypted_pack + sizeof(struct nst_hdr); // 留出头部空间
    if (encrypted_pl == NULL)
        return  -ENOMEM;

    // 加密
    switch (nsthdr->cipher_id) {
        case ENCRYPT_ALGO_AES_GCM:
            err = nst_encrypt_aes_gcm(origin_pl, origin_pl_len, encrypted_pl, &encrypted_pl_len, key, ENCRYPT_KEY_LEN, aad, aad_len);
            break;
        case ENCRYPT_ALGO_AES_CBC:
            err = nst_encrypt_aes_cbc_hmac(origin_pl, origin_pl_len, encrypted_pl, &encrypted_pl_len, key, ENCRYPT_KEY_LEN);
            break;
        case ENCRYPT_ALGO_SM4_GCM:
            err = nst_encrypt_sm4_gcm(origin_pl, origin_pl_len, encrypted_pl, &encrypted_pl_len, key, ENCRYPT_KEY_LEN, aad, aad_len);
            break;
        case ENCRYPT_ALGO_SM4_CBC:
            err = nst_encrypt_sm4_cbc_sm3(origin_pl, origin_pl_len, encrypted_pl, &encrypted_pl_len, key, ENCRYPT_KEY_LEN);
            break;
        default:
            kfree(encrypted_pack);
            return -EINVAL;
    }

    if (err != OK) {
        kfree(encrypted_pack);
        return err;
    }

    // 插入nst_hdr

    // 更新tcp/udp ，ip报头数据，校验和后更新

    return 0;
}

int nst_decrypt_skb(struct sk_buff *skb, const u8 *key, size_t keylen){
    return 0;
}