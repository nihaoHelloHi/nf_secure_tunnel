//
// Created by tangmin on 25-6-25.
//
#include "dependency.h"

/*
 * 取出传输层的payload
 * 输入：已线性化的skb,经过是否需要加密判断的skb
 * 返回：char* == u8* payload地址
 * NULL代表错误
 * */
u8* get_transport_payload(struct sk_buff *skb, u16 *len){
    struct iphdr* ip_header = ip_hdr(skb);
    u8* pl_start = NULL;
    u32 pl_len = 0;
    u32 ip_hdrlen = ip_header->ihl * 4;

    if (ip_header->protocol == IPPROTO_TCP){
        // 验证tcp头部完整性,确保skb长度足够
        if(!pskb_may_pull(skb,ip_hdrlen + sizeof(struct tcphdr)))
            return NULL;
        struct tcphdr* tcp_header = tcp_hdr(skb);
        // 计算payload开始位置和长度
        u32 tcp_hdrlen = tcp_header->doff * 4;
        u32 tot_len = be16_to_cpu(ip_header->tot_len);
        if (tot_len < ip_hdrlen +tcp_hdrlen)
            return NULL;
        pl_start = (u8*)tcp_header + tcp_hdrlen;
        pl_len = tot_len - ip_hdrlen - tcp_hdrlen;
    }
    else if(ip_header->protocol == IPPROTO_UDP){
        if(!pskb_may_pull(skb, ip_hdrlen + sizeof(struct udphdr)))
            return NULL;
        struct udphdr* udp_header = udp_hdr(skb);
        u32 udp_len = be16_to_cpu(udp_header->len);
        if (udp_len < sizeof(struct udphdr))
                return NULL;
        pl_start = (u8*)udp_header + sizeof(struct udphdr);
        pl_len = udp_len - sizeof(struct udphdr);
    }
    else
        return NULL;

    if (pl_len > 0xFFFF)
        return NULL;

    *len = (u16)pl_len;
    return pl_start;
}