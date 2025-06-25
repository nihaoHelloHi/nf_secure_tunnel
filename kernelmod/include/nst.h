#ifndef NF_SECURE_TUNNEL_H
#define NF_SECURE_TUNNEL_H

#include "dependency.h"

// --------------------------------------------------------------------------------
// === 协议参数 ===
#define NST_MAGIC             0xBEEF1337    // 协议魔数
#define NST_VERSION           1             // 当前协议版本
#define NST_TOKEN_LEN         16            // Token长度
#define NST_NONCE_LEN         8             // Nonce长度
#define NST_HEADER_SIZE       44            // 固定头部长度
#define NST_MAX_PAYLOAD       1400          // 最大加密payload，保证不超过 MTU

// --------------------------------------------------------------------------------
// === 加密算法ID ===
#define ENCRYPT_ALGO_DEFALUT 0


// --------------------------------------------------------------------------------
// === 协议头部结构 ===
// 4+4+8+8+16+2+1+1+2+2 = 48B
struct nst_hdr {
    __be32 magic;                   // 魔数标识协议
    u8 version;                     // 协议版本
    u8 cipher_id;                   // 加密算法ID
    __be16 payload_len;             // 明文 payload 长度
    __be64 timestamp;               // 时间戳，防重放
    __be64 nonce;                   // 随机数/计数器
    u8 token[NST_TOKEN_LEN];        // 认证字段（对称或HMAC）
    __be16 kpos;                    // 秘钥改变位置, 0表示不修改
    __be16 kval;                    // 秘钥改变值
    __be16 flags;                   // 保留标志位
    __be16 reserved;                // 保留字段
} __attribute__((packed));          // 取消结构对齐

// --------------------------------------------------------------------------------
// === 防重放模块 ===

struct seen_packet {
    u64 timestamp;
    u64 nonce;
};

// --------------------------------------------------------------------------------
// === 控制开关 ===
extern bool nst_enable;              // 总开关
extern bool nst_log_enable;          // 日志开关
extern bool nst_encrypt_enable;      // 加密启用
extern bool nst_decrypt_enable;      // 解密启用
extern bool nst_drop_invalid;        // 是否丢弃非法包

// --------------------------------------------------------------------------------
// === payload头部模块 ===
int nst_build_hdr(struct nst_hdr *hdr, struct sk_buff *skb);
int nst_insert_hdr(struct sk_buff *skb, const struct nst_hdr *hdr);
int nst_parse_hdr(struct sk_buff *skb, struct nst_hdr *hdr_out);
int nst_validate_hdr(const struct nst_hdr *hdr);

// --------------------------------------------------------------------------------
// === 加解密接口 ===
int nst_modify_key(u16 kpos, u16 kval);
int nst_encrypt_skb(struct sk_buff *skb, const u8 *key, size_t keylen, struct net_device *dev);
int nst_decrypt_skb(struct sk_buff *skb, const u8 *key, size_t keylen);

// --------------------------------------------------------------------------------
// === 校验和处理模块 ===
void nst_fix_ip_csum(struct sk_buff *skb);
void nst_fix_udp_csum(struct sk_buff *skb);
void nst_fix_tcp_csum(struct sk_buff *skb);

// --------------------------------------------------------------------------------
// === 防重放模块接口 ===
bool nst_replay_check(u64 timestamp, u64 nonce);
void nst_replay_remember(u64 timestamp, u64 nonce);

// --------------------------------------------------------------------------------
// === 日志模块 ===
void nst_log_connection(const struct sk_buff *skb, const char *prefix);
void nst_log_packet(const struct sk_buff *skb, const char *msg);

// --------------------------------------------------------------------------------
// === 钩子实现 ===
unsigned int hook_local_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int hook_local_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

// --------------------------------------------------------------------------------
// === 连接跟踪模块（简化接口） ===
int nst_conntrack_register(u32 saddr, u32 daddr, u16 sport, u16 dport, u8 proto);
bool nst_conntrack_exists(u32 saddr, u32 daddr, u16 sport, u16 dport, u8 proto);
void nst_conntrack_cleanup(void);

#endif // NF_SECURE_TUNNEL_H
