//
// Created by tangmin on 25-6-26.
//

#ifndef NF_SECURE_TUNNEL_TOOLS_H
#define NF_SECURE_TUNNEL_TOOLS_H

#include "dependency.h"

u8* get_transport_payload(struct sk_buff *skb, u16 *len);

#endif //NF_SECURE_TUNNEL_TOOLS_H
