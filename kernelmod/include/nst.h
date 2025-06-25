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
// === 协议头部结构 ===

struct nst_hdr {
    __be32 magic;                     // 魔数标识协议
    __be64 timestamp;                // 时间戳，防重放
    __be64 nonce;                    // 随机数/计数器
    u8 token[NST_TOKEN_LEN];         // 认证字段（对称或HMAC）
    __be16 payload_len;              // 明文 payload 长度
    struct {
        u8 version;                  // 协议版本
        u8 cipher_id;                // 加密算法ID
        __be16 flags;                // 保留标志位
        __be16 reserved;             // 保留字段
    } __attribute__((packed)) extra;
} __attribute__((packed));

// --------------------------------------------------------------------------------
// === 防重放模块 ===

struct seen_packet {
    uint64_t timestamp;
    uint64_t nonce;
};

// --------------------------------------------------------------------------------
// === 控制开关 ===
extern bool nst_enable;              // 总开关
extern bool nst_log_enable;          // 日志开关
extern bool nst_encrypt_enable;      // 加密启用
extern bool nst_decrypt_enable;      // 解密启用
extern bool nst_drop_invalid;        // 是否丢弃非法包

// --------------------------------------------------------------------------------
// === 加解密接口 ===
int nst_encrypt_skb(struct sk_buff *skb, const u8 *key, size_t keylen, struct net_device *dev);
int nst_decrypt_skb(struct sk_buff *skb, const u8 *key, size_t keylen);

// --------------------------------------------------------------------------------
// === 校验和处理模块 ===
void nst_fix_ip_csum(struct sk_buff *skb);
void nst_fix_udp_csum(struct sk_buff *skb);
void nst_fix_tcp_csum(struct sk_buff *skb);

// --------------------------------------------------------------------------------
// === payload头部模块 ===
int nst_build_hdr();
int nst_insert_hdr(struct sk_buff *skb, const struct nst_hdr *hdr);
int nst_parse_hdr(struct sk_buff *skb, struct nst_hdr *hdr_out);
int nst_validate_hdr(const struct nst_hdr *hdr);

// --------------------------------------------------------------------------------
// === 防重放模块接口 ===
bool nst_replay_check(uint64_t timestamp, uint64_t nonce);
void nst_replay_remember(uint64_t timestamp, uint64_t nonce);

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
int nst_conntrack_register(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint8_t proto);
bool nst_conntrack_exists(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint8_t proto);
void nst_conntrack_cleanup(void);

#endif // NF_SECURE_TUNNEL_H
