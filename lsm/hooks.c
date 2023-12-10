#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include "init.h"
#include "hooks.h"
#include "restrict.h"
#include "thread.h"

static int sandbox_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen){
  pid_t thread_id = current->pid;
  pid_t tgid = current->tgid;
  if (address->sa_family == AF_INET) {
    struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
    unsigned short port = ntohs(addr_in->sin_port);
    printk(KERN_INFO "Bound port: %u\n", port);
    if(check_bind_port(tgid, thread_id, port) != 1){
      pr_info("access is deined for %d %d\n", thread_id, port);
      return -EPERM;
    }
  }
  return 0;
}

static int sandbox_socket_listen(struct socket *sock, int backlog){
  //pid_t thread_id = current->pid;
  //pid_t tgid = current->tgid;
  //struct inet_sock *inet = inet_sk(sock);
  //unsigned short port = ntohs(inet->inet_sport);
  //if(check_listen_port(tgid, thread_id, port) != 1){
  //  pr_info("access is deined for %d %d\n", thread_id, port);
  //  return -EPERM;
  //}
  //pr_info("access is allowed for %d %d\n", thread_id, port);
  return 0;
}

static int sandbox_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
  pid_t thread_id = current->pid;
  pid_t tgid = current->tgid;
  if(check_ioctl(tgid, thread_id, cmd) != 1){
    if (file->f_path.dentry) {
        printk(KERN_INFO "File name: %s\n", file->f_path.dentry->d_iname);
        unsigned int major_num = MAJOR(file->f_inode->i_rdev);
        unsigned int minor_num = MINOR(file->f_inode->i_rdev);
        printk(KERN_INFO "Major number: %u, Minor number: %u\n", major_num, minor_num);
    }
    pr_info("ioctl access is deined for %d %d\n", thread_id, cmd);
    return -EPERM;
  }
  return 0;
}

static int sandbox_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg){
  pid_t thread_id = current->pid;
  pid_t tgid = current->tgid;
  if(check_fcntl(tgid, thread_id, cmd) != 1){
    if (file->f_path.dentry) {
        printk(KERN_INFO "File name: %s\n", file->f_path.dentry->d_iname);
        unsigned int major_num = MAJOR(file->f_inode->i_rdev);
        unsigned int minor_num = MINOR(file->f_inode->i_rdev);
        printk(KERN_INFO "Major number: %u, Minor number: %u\n", major_num, minor_num);
    }
    pr_info("fcntl access is deined for %d %d\n", thread_id, cmd);
    return -EPERM;
  }
  return 0;
}

static int sandbox_task_alloc(struct task_struct *task, unsigned long clone_flags){
  pid_t thread_id = current->pid;
  pid_t tgid = current->tgid;
  if(check_fork(tgid, thread_id) != 1){
    pr_info("fork access is deined for %d\n", thread_id);
    return -EPERM;
  }
  return 0;
}

static int sandbox_file_open(struct file *file){
  pid_t thread_id = current->pid;
  pid_t tgid = current->tgid;
  char full_path[PATH_MAX]; 
  struct path path;
  char *result;
  char* mode;
  if(check_sandboxed_process(tgid, thread_id)==0){
    return 0;
  }
  if (file->f_path.dentry) {
    path = file->f_path;
    path_get(&path);
    path_put(&path);
    result = d_path(&path, full_path, PATH_MAX);
    if (IS_ERR(result)) {
        pr_err("Failed to get the path\n");
    } else {
        unsigned int flags = file->f_flags & O_ACCMODE;
        if (flags == O_RDONLY) {
          mode = "RO";
        }else if (flags == O_WRONLY) {
          mode = "WO";
        }else if (flags == O_RDWR) {
          mode = "RW";
        }else {
          mode = "NAN";
        }
        pr_info("Full path and mode : %s %s %u\n", result, mode, file->f_flags);
    }
    //if (path.dentry && path.mnt && path.dentry->d_name.len > 0) {
    //  pr_info("%s\n",path.dentry->d_name.name);
    //}
  }
  return 0;
}

struct security_hook_list hooks[] __ro_after_init = {
  LSM_HOOK_INIT(socket_bind, sandbox_socket_bind),
  LSM_HOOK_INIT(socket_listen, sandbox_socket_listen),
  //LSM_HOOK_INIT(file_ioctl, sandbox_file_ioctl),
  //LSM_HOOK_INIT(file_fcntl, sandbox_file_fcntl),
  LSM_HOOK_INIT(task_alloc, sandbox_task_alloc),
  LSM_HOOK_INIT(file_open, sandbox_file_open)
};

__init void create_hooks(void){
  pr_info("Creating hooks\n");
	security_add_hooks(hooks, ARRAY_SIZE(hooks), FUNCSANDBOX_NAME);
}
