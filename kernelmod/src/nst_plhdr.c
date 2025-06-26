#include "nst.h"

/*
 * 填充头部token
 * 是否用 HMAC 或 PSK 生成token
 */
static int fill_token_field(u8 *hdr_token, char* content){

}

/*
 * 获取当前时间(秒级)，并转换大小端
 */
static __be64 get_current_unix_timestamp(){
    u64 ts = (u64)ktime_get_real_seconds();
    return cpu_to_be64(ts);
}

/*
 * 随机生成nonce
 */
static __be64 generate_random_nonce(){
    u64 nonce;
    get_random_bytes(&nonce, sizeof(nonce));
    nonce ^= (u64)ktime_get_real_ns(); // 结合当前时间戳
    return cpu_to_be64(nonce);
}

/*
 * 获取传输层skb明文长度
 */
static __be16 get_transport_len(struct sk_buff *skb){
    u16 pl_len = skb->len - skb_transport_offset(skb);
    return cpu_to_be16(pl_len);
}

/*
 * 随机选择密钥和扰动参数
 */
static void gen_key(struct nst_hdr *nsthdr){
    get_random_bytes(&nsthdr->kpos, sizeof(nsthdr->kpos));
    get_random_bytes(&nsthdr->kval, sizeof(nsthdr->kval));
    get_random_bytes(&nsthdr->kid, sizeof(nsthdr->kid));
    nsthdr->kpos = nsthdr->kpos % ENCRYPT_KEY_LEN;
    nsthdr->kid = cpu_to_be16(nsthdr->kid % cur_key_num);
}

// --------------------------------------------------------------------------------
// === payload头部构造 ===
int nst_build_hdr(struct nst_hdr *nsthdr, struct sk_buff *skb){
    if(!nsthdr || !skb)
        return -EINVAL;

    // 构造时直接采用大端
    nsthdr->magic = cpu_to_be32(NST_MAGIC);
    nsthdr->version = NST_VERSION;
    nsthdr->cipher_id = ENCRYPT_ALGO_DEFAULT; // 假设 AES-GCM
    nsthdr->timestamp = get_current_unix_timestamp();
    nsthdr->nonce = generate_random_nonce(); // 可选固定递增
    nsthdr->transport_len = get_transport_len(skb);
    nsthdr->flags = cpu_to_be32(0);

    // token
    if(fill_token_field(nsthdr->token, '\0') != OK)  // HMAC 或 PSK
        return -EINVAL;

    // key
    gen_key(nsthdr);
    return OK;
}

// --------------------------------------------------------------------------------
// === payload头部处理 ===
int nst_insert_hdr(struct sk_buff *skb, const struct nst_hdr *hdr){
    return 0;
}
int nst_parse_hdr(struct sk_buff *skb, struct nst_hdr *hdr_out){
    return 0;
}
int nst_validate_hdr(const struct nst_hdr *hdr){
    return 0;
}
