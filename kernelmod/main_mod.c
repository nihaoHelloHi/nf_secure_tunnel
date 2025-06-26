#include "nst.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tangmin");

static struct nf_hook_ops nf_local_in={
	.hook = hook_local_in, // 钩子入口
	.pf = PF_INET, // 协议族标识
	.hooknum = NF_INET_LOCAL_IN, //数据包被拦截的位置，所有入站流量
	.priority = NF_IP_PRI_FIRST // 钩子的优先级
};

static struct nf_hook_ops nf_local_out={
	.hook = hook_local_out,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST
};

static int __init nst_init(void)
{
    pr_info("NST module loaded.\n");
    nf_register_net_hook(&init_net, &nf_local_in);
    nf_register_net_hook(&init_net, &nf_local_out);
    return 0;
}

static void __exit nst_exit(void)
{
    pr_info("NST module unloaded.\n");
    nf_unregister_net_hook(&init_net, &nf_local_in);
    nf_unregister_net_hook(&init_net, &nf_local_out);
}

module_init(nst_init);
module_exit(nst_exit);

