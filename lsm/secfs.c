#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include "secfs.h"
#include "restrict.h"

static ssize_t hello_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    char *kbuf;

    kbuf = kmalloc(count, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, buf, count)) {
        kfree(kbuf);
        return -EFAULT;
    }
  
    pid_t thread_id = current->pid;

    pr_info("hello\n%s\n%d",kbuf,thread_id);

    kfree(kbuf);
    return count;
}

struct file_operations securityfs_fops = {
    .write = hello_write,
};
