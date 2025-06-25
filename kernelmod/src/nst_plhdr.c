#include "nst.h"
// --------------------------------------------------------------------------------
// === payload头部构造 ===



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
