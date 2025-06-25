#include "nst.h"

bool nst_drop_invalid;        // 是否丢弃非法包
bool nst_enable;              // 总开关

unsigned int hook_local_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    // ① 是否启用模块？
    if (!nst_enable)
        return NF_ACCEPT;

    // ② 检查skb是否有效且为TCP/UDP
    if (!skb || !skb->protocol == htons(ETH_P_IP))
        return NF_ACCEPT;

    iphdr = ip_hdr(skb);
    if (iphdr->protocol != IPPROTO_TCP && iphdr->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    // ③ 尝试线性化 skb（必要）
    if (skb_linearize(skb) != 0)
        return NF_DROP;

    // ④ 构造头部 nst_hdr
    nst_hdr hdr;
    hdr.magic = NST_MAGIC;
    hdr.timestamp = get_current_unix_timestamp();
    hdr.nonce = generate_random_nonce(); // 可选固定递增
    hdr.payload_len = get_payload_len(skb);
    hdr.version = NST_VERSION;
    hdr.cipher_id = 1; // 假设 AES-GCM
    fill_token_field(&hdr.token, ...);  // HMAC 或 PSK

    // ⑤ 封装 + 加密
    if (nst_encrypt_enable)
    {
        if (nst_encrypt_skb(skb, key, keylen, state->out) != 0)
            return NF_DROP;
    }
    
    // ⑥ 记录日志
    if (nst_log_enable)
        nst_log_packet(skb, "[NST OUT] 加密并封装成功");

    // ⑦ 修复校验和
    nst_fix_ip_csum(skb);
    if (iphdr->protocol == IPPROTO_TCP)
        nst_fix_tcp_csum(skb);
    else
        nst_fix_udp_csum(skb);

    return NF_ACCEPT;
}



unsigned int hook_local_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    if (!nst_enable)
        return NF_ACCEPT;

    return NF_ACCEPT;
}