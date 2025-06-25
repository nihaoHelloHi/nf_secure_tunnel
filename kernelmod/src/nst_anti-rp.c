// 防重放
#include "nst.h"
bool nst_replay_check(uint64_t timestamp, uint64_t nonce){
    return false;
}
void nst_replay_remember(uint64_t timestamp, uint64_t nonce){

}