#include <linux/fs.h>
#include <linux/security.h>
#include <linux/socket.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include "fs.h"
#include "restrict.h"

static ssize_t funcsandbox_bind_socket(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
  pid_t thread_id = current->pid;
  pid_t pid = current->tgid;
  int res;
  if(kstrtoint_from_user(buf, count, 10, &res)){
    return -EFAULT;
  }
  pr_info("ok = %d\n", res);
  restrict_bind_port(pid, thread_id, res);
  return count;
}

static ssize_t funcsandbox_fork(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
  pid_t pid = current->tgid;
  pid_t thread_id = current->pid;
  restrict_fork(pid, thread_id);
  return count;
}

static ssize_t funcsandbox_remove_sandbox(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
  pid_t pid = current->tgid;
  pid_t thread_id = current->pid;
  remove_sandbox(pid, thread_id);
  return count;
}

static ssize_t funcsandbox_ps_sandbox(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
  pid_t pid = current->tgid;
  add_sandbox_ps(pid);
  return count;
}

const struct file_operations bind_socket_ops = {
  .write	= funcsandbox_bind_socket,
  .llseek = generic_file_llseek
};

const struct file_operations fork_ops = {
  .write	= funcsandbox_fork,
  .llseek = generic_file_llseek
};

const struct file_operations remove_sandbox_ops = {
  .write	= funcsandbox_remove_sandbox,
  .llseek = generic_file_llseek
};

const struct file_operations ps_sandbox_ops = {
  .write	= funcsandbox_ps_sandbox,
  .llseek = generic_file_llseek
};

static __init int create_fs_nodes(void){
  struct dentry *funcsandbox_dir = securityfs_create_dir(FS_FOLDER_NAME, NULL);
	securityfs_create_file("bind_socket", 0666, funcsandbox_dir, NULL, &bind_socket_ops);
	securityfs_create_file("fork", 0666, funcsandbox_dir, NULL, &fork_ops);
	securityfs_create_file("remove_sandbox", 0666, funcsandbox_dir, NULL, &remove_sandbox_ops);
	securityfs_create_file("sandbox_ps", 0666, funcsandbox_dir, NULL, &ps_sandbox_ops);
  return 0;
}

__initcall(create_fs_nodes);
