#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/path.h>
#include "init.h"
#include "hooks.h"
#include "restrict.h"

#define REQUIRE_PROMISE(current, x)                           \
  do{                                                         \
    pid_t thread_id = current->pid;                           \
    pid_t tgid = current->tgid;                               \
    if(require_promise(tgid, thread_id, x) == 0){             \
      pr_info("%s access is deined for %d\n", x, thread_id);  \
      kill_proc(current);                                     \
      return -EPERM;                                          \
    }                                                         \
  } while(0)

static int sandbox_task_alloc(struct task_struct *task, unsigned long clone_flags){
  REQUIRE_PROMISE(current, "proc");
  // init_child_thread(current, task);
  return 0;
}

static int sandbox_task_fix_setuid(struct cred *new, const struct cred *old, int flags){
  REQUIRE_PROMISE(current, "id");
  return 0;
}

static int sandbox_task_fix_setgid(struct cred *new, const struct cred *old,int flags){
  REQUIRE_PROMISE(current, "id");
  return 0;
}

static int sandbox_task_fix_setgroups(struct cred *new, const struct cred *old){
  REQUIRE_PROMISE(current, "id");
  return 0;
}

static int sandbox_task_setpgid(struct task_struct *p, pid_t pgid){
  REQUIRE_PROMISE(current, "id");
  return 0;
}

static int sandbox_task_getpgid(struct task_struct *p){
  REQUIRE_PROMISE(current, "id");
  return 0;
}

static int sandbox_task_getsid(struct task_struct *p){
  REQUIRE_PROMISE(current, "id");
  return 0;
}

static int sandbox_task_setnice(struct task_struct *p, int nice){
  REQUIRE_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_setioprio(struct task_struct *p, int ioprio){
  REQUIRE_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_getioprio(struct task_struct *p){
  REQUIRE_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_prlimit(const struct cred *cred, const struct cred *tcred, unsigned int flags){
  REQUIRE_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_setrlimit(struct task_struct *p, unsigned int resource, struct rlimit *new_rlim){
  REQUIRE_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_setscheduler(struct task_struct *p){
  REQUIRE_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_getscheduler(struct task_struct *p){
  REQUIRE_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_movememory(struct task_struct *p){
  REQUIRE_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_kill(struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred){
  REQUIRE_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5){
  REQUIRE_PROMISE(current, "proc");
  return 0;
}

static int sandbox_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen){
  if (address->sa_family == AF_INET)
    REQUIRE_PROMISE(current, "net");
  if (address->sa_family == AF_UNIX)
    REQUIRE_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_create(int family, int type, int protocol, int kern){
  REQUIRE_PROMISE(current, "net");
  return 0;
}

static int sandbox_socket_post_create(struct socket *sock, int family,int type, int protocol, int kern){
  REQUIRE_PROMISE(current, "net");
  return 0;
}

static int sandbox_socket_socketpair(struct socket *socka, struct socket *sockb){
  REQUIRE_PROMISE(current, "net");
  return 0;
}

static int sandbox_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen){
  if (address->sa_family == AF_INET)
    REQUIRE_PROMISE(current, "net");
  if (address->sa_family == AF_UNIX)
    REQUIRE_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_listen(struct socket *sock, int backlog){
  REQUIRE_PROMISE(current, "net");
  return 0;
}

static int sandbox_socket_accept(struct socket *sock, struct socket *newsock){
  REQUIRE_PROMISE(current, "net");
  return 0;
}

static int sandbox_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size){
  REQUIRE_PROMISE(current, "net");
  return 0;
}

static int sandbox_socket_recvmsg(struct socket *sock, struct msghdr *msg,int size, int flags){
  REQUIRE_PROMISE(current, "net");
  return 0;
}

static int sandbox_socket_getsockname(struct socket *sock){
  REQUIRE_PROMISE(current, "net");
  return 0;
}

static int sandbox_socket_getpeername(struct socket *sock){
  REQUIRE_PROMISE(current, "net");
  return 0;
}

static int sandbox_socket_getsockopt(struct socket *sock, int level, int optname){
  REQUIRE_PROMISE(current, "net");
  return 0;
}

static int sandbox_socket_setsockopt(struct socket *sock, int level, int optname){
  REQUIRE_PROMISE(current, "net");
  return 0;
}

static int sandbox_socket_shutdown(struct socket *sock, int how){
  REQUIRE_PROMISE(current, "net");
  return 0;
}

static int sandbox_socket_getpeersec_stream(struct socket *sock, sockptr_t optval, sockptr_t optlen, unsigned int len){
  REQUIRE_PROMISE(current, "net");
  return 0;
}

static int sandbox_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid){
  REQUIRE_PROMISE(current, "net");
  return 0;
}

// check clean up of a sandboxed process.
static void sandbox_task_free(struct task_struct *task){
  int proc_id = task->tgid;
  int thread_id = task->pid;
  pid_t t2 = current->pid;
  pid_t p2 = current->tgid;
  if(proc_id == p2 && thread_id == t2) return;
  remove_sandbox(proc_id,thread_id);
}

static int sandbox_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev){ 
  REQUIRE_PROMISE(current, "dpath");
  return 0;
}

static int sandbox_path_mknod(const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev){
  REQUIRE_PROMISE(current, "dpath");
  return 0;
}

static int sandbox_file_open(struct file *file){
  struct path path;
  char file_path[2000];
  char* result;

  path = file->f_path;
  result = d_path(&path, file_path, 2000);

  char *target_path = "/sys/kernel/security/funcsandbox/promises";
  
  unsigned int flags = file->f_flags & O_ACCMODE;
  if (flags == O_WRONLY || flags == O_RDWR){
    if (strcmp(result, target_path) != 0) {
      REQUIRE_PROMISE(current, "wpath");
    }
  }
  if (flags == O_RDONLY){
    REQUIRE_PROMISE(current, "rpath");
  }
  if (file->f_flags & O_CREAT) {
    if (strcmp(result, target_path) != 0) {
      REQUIRE_PROMISE(current, "cpath");
    } 
  }
  return 0;
}

struct security_hook_list hooks[] __ro_after_init = {

  // LSM related
  LSM_HOOK_INIT(task_free, sandbox_task_free),

  // net promise
  LSM_HOOK_INIT(socket_create, sandbox_socket_create),
  LSM_HOOK_INIT(socket_post_create, sandbox_socket_post_create),
  LSM_HOOK_INIT(socket_socketpair, sandbox_socket_socketpair),
  LSM_HOOK_INIT(socket_connect, sandbox_socket_connect),
  LSM_HOOK_INIT(socket_bind, sandbox_socket_bind),
  LSM_HOOK_INIT(socket_listen, sandbox_socket_listen),
  LSM_HOOK_INIT(socket_accept, sandbox_socket_accept),
  LSM_HOOK_INIT(socket_sendmsg, sandbox_socket_sendmsg),
  LSM_HOOK_INIT(socket_recvmsg, sandbox_socket_recvmsg),
  LSM_HOOK_INIT(socket_getsockname, sandbox_socket_getsockname),
  LSM_HOOK_INIT(socket_getpeername, sandbox_socket_getpeername),
  LSM_HOOK_INIT(socket_getsockopt, sandbox_socket_getsockopt),
  LSM_HOOK_INIT(socket_setsockopt, sandbox_socket_setsockopt),
  LSM_HOOK_INIT(socket_shutdown, sandbox_socket_shutdown),
  LSM_HOOK_INIT(socket_getpeersec_stream, sandbox_socket_getpeersec_stream),
  LSM_HOOK_INIT(socket_getpeersec_dgram, sandbox_socket_getpeersec_dgram),

  // proc promise
  LSM_HOOK_INIT(task_alloc, sandbox_task_alloc),
  LSM_HOOK_INIT(task_setnice, sandbox_task_setnice),
  LSM_HOOK_INIT(task_setioprio, sandbox_task_setioprio),
  LSM_HOOK_INIT(task_getioprio, sandbox_task_getioprio),
  LSM_HOOK_INIT(task_prlimit, sandbox_task_prlimit),
  LSM_HOOK_INIT(task_setrlimit, sandbox_task_setrlimit),
  LSM_HOOK_INIT(task_setscheduler, sandbox_task_setscheduler),
  LSM_HOOK_INIT(task_getscheduler, sandbox_task_getscheduler),
  LSM_HOOK_INIT(task_movememory, sandbox_task_movememory),
  LSM_HOOK_INIT(task_kill, sandbox_task_kill),
  LSM_HOOK_INIT(task_prctl, sandbox_task_prctl),

  // wpath promises 
  LSM_HOOK_INIT(file_open, sandbox_file_open),

  // cpath promise

  // dpath promise
  LSM_HOOK_INIT(inode_mknod, sandbox_inode_mknod),
  LSM_HOOK_INIT(path_mknod, sandbox_path_mknod),

  // id promise
  LSM_HOOK_INIT(task_fix_setuid, sandbox_task_fix_setuid),
  LSM_HOOK_INIT(task_fix_setgid, sandbox_task_fix_setgid),
  LSM_HOOK_INIT(task_fix_setgroups, sandbox_task_fix_setgroups),
  LSM_HOOK_INIT(task_setpgid, sandbox_task_setpgid),
  LSM_HOOK_INIT(task_getpgid, sandbox_task_getpgid),
  LSM_HOOK_INIT(task_getsid, sandbox_task_getsid),

};

__init void create_hooks(void){
  pr_info("Creating hooks\n");
	security_add_hooks(hooks, ARRAY_SIZE(hooks), FUNCSANDBOX_NAME);
}
