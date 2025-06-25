// 连接跟踪
#include "nst.h"

// 连接红黑树

int nst_conntrack_register(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint8_t proto){
    return 0;
}
bool nst_conntrack_exists(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint8_t proto){
    return false;
}
void nst_conntrack_cleanup(void){
    
}