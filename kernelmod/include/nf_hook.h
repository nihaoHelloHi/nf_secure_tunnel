//
// Created by tangmin on 25-6-24.
//

#ifndef NF_SECURE_TUNNEL_NF_HOOK_H
#define NF_SECURE_TUNNEL_NF_HOOK_H

// 钩子函数
unsigned int hook_local_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int hook_local_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

#endif //NF_SECURE_TUNNEL_NF_HOOK_H
