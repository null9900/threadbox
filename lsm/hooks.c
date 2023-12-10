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
    if(check_bind_port(tgid, thread_id, port) == -1){
      pr_info("access is deined for %d %d\n", thread_id, port);
      return -EPERM;
    }
  }
  return 0;
}

static int sandbox_task_alloc(struct task_struct *task, unsigned long clone_flags){
  pid_t thread_id = current->pid;
  pid_t tgid = current->tgid;
  if(check_fork(tgid, thread_id) == -1){
    pr_info("fork access is deined for %d\n", thread_id);
    return -EPERM;
  }
  return 0;
}

struct security_hook_list hooks[] __ro_after_init = {
  LSM_HOOK_INIT(socket_bind, sandbox_socket_bind),
  //LSM_HOOK_INIT(socket_listen, sandbox_socket_listen),
  LSM_HOOK_INIT(task_alloc, sandbox_task_alloc),
  //LSM_HOOK_INIT(file_open, sandbox_file_open)
};

__init void create_hooks(void){
  pr_info("Creating hooks\n");
	security_add_hooks(hooks, ARRAY_SIZE(hooks), FUNCSANDBOX_NAME);
}
