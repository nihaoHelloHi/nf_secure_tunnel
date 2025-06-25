#include "nst.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tangmin");

static struct nf_hook_ops nf_local_in={
	.hook = hook_local_in, // 钩子入口
	.pf = PF_INET, // 协议族标识
	.hooknum = NF_INET_PRE_ROUTING, //数据包被拦截的位置，所有入站流量
	.priority = NF_IP_PRI_FIRST // 钩子的优先级
};

static struct nf_hook_ops nf_local_out={
	.hook = hook_local_out,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_FIRST
};



static int __init nst_init(void)
{
    pr_info("NST module loaded.\n");
    return 0;
}

static void __exit nst_exit(void)
{
    pr_info("NST module unloaded.\n");
}

module_init(nst_init);
module_exit(nst_exit);

