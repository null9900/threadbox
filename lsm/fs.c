#include <linux/fs.h>
#include <linux/security.h>
#include <linux/socket.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include "fs.h"
#include "restrict.h"
#include "debug.h"

static ssize_t add_promises(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
  char *buffer = (char*)kmalloc(count, GFP_KERNEL);
  pid_t pid = current->tgid;
  pid_t tid = current->pid;
  copy_from_user(buffer, buf, count);
  parse_promises(pid, tid, buffer);
  kfree(buffer);
  return count;
}

static ssize_t funcsandbox_ps_sandbox(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
  pid_t pid = current->tgid;
  add_sandbox_ps(pid);
  return count;
}

static ssize_t funcsandbox_debug(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
  char *buffer = (char*)kmalloc(count, GFP_KERNEL);
  pid_t pid = current->tgid;
  pid_t tid = current->pid;
  copy_from_user(buffer, buf, count);
  set_debug_name(pid, tid, buffer, count);
  return count;
}

const struct file_operations promises_ops = {
  .write	= add_promises,
  .llseek = generic_file_llseek
};

const struct file_operations ps_sandbox_ops = {
  .write	= funcsandbox_ps_sandbox,
  .llseek = generic_file_llseek
};

const struct file_operations debug_ops = {
  .write	= funcsandbox_debug,
  .llseek = generic_file_llseek
};

static __init int create_fs_nodes(void){
  struct dentry *funcsandbox_dir = securityfs_create_dir(FS_FOLDER_NAME, NULL);
	securityfs_create_file("promises", 0666, funcsandbox_dir, NULL, &promises_ops);
	securityfs_create_file("sandbox_ps", 0666, funcsandbox_dir, NULL, &ps_sandbox_ops);
	securityfs_create_file("debug", 0666, funcsandbox_dir, NULL, &debug_ops);
  return 0;
}

__initcall(create_fs_nodes);
