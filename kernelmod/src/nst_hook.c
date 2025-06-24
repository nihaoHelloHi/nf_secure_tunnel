#include "../include/nst.h"
unsigned int hook_local_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    if (!nst_enable)
        return NF_ACCEPT;
}

unsigned int hook_local_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    if (!nst_enable)
        return NF_ACCEPT;
}