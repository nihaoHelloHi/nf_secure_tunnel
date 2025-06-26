#include "nst.h"

bool nst_drop_invalid = true;        // 是否丢弃非法包
bool nst_enable = true;              // 总开关

unsigned int hook_local_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    struct iphdr *ip_header = NULL;
    struct nst_hdr nst_header;

    // ① 是否启用模块？
    if (!nst_enable)
        return NF_ACCEPT;

    // ② 检查skb是否有效且为TCP/UDP
    if (!skb || skb->protocol != htons(ETH_P_IP))
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (ip_header->protocol != IPPROTO_TCP && ip_header->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    if (ip_header->version != 4)
        return NF_ACCEPT;

    // ③ 尝试线性化 skb（必要）
    if (skb_linearize(skb) != 0){
        printk("线性化skb失败");
        return NF_DROP;
    }

    // ④ 构造头部 nst_hdr
    if(nst_build_hdr(&nst_header, skb) != OK)
        return NF_DROP;

    // mark:需要注意pskb_may_pull判断长度是否够用？边界判断

    // ⑤ 封装 + 加密 + 更新IP、Transport报头数据 + 修复校验和
    if (nst_encrypt_enable){
        if (nst_encrypt_skb(skb, &nst_header) != OK)
            return NF_DROP;
    }

    // ⑥ 记录日志
    if (nst_log_enable)
        nst_log_packet(skb, "[NST OUT] 加密并封装成功");

    return NF_ACCEPT;
}



unsigned int hook_local_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    if (!nst_enable)
        return NF_ACCEPT;

    return NF_ACCEPT;
}