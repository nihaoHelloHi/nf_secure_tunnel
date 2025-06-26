// 校验和
#include "nst.h"

// 仅适用于线性skb
void nst_fix_ip_csum(struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);

    iph->check = 0;
    iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
}
void nst_fix_udp_csum(struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);
    struct udphdr *udph = udp_hdr(skb);

    udph->check = 0;

    udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,ntohs(udph->len), IPPROTO_UDP,
                                    csum_partial((char *)udph, ntohs(udph->len), 0));

    if (udph->check == 0)
        udph->check = CSUM_MANGLED_0;  // 符合 RFC 要求的“伪校验和”
}
void nst_fix_tcp_csum(struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);
    int tcp_len = ntohs(iph->tot_len) - iph->ihl * 4;

    tcph->check = 0;
    tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,tcp_len, IPPROTO_TCP,
                                    csum_partial((char *)tcph, tcp_len, 0));
}