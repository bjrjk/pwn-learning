#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cred.h>
MODULE_LICENSE("GPT");

void* test_unset_seccomp_flag_in_thread_info_flags(void) {
    return current->thread_info.flags &= ~(1 << TIF_SECCOMP);
}