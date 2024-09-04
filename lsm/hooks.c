#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/path.h>
#include <net/sock.h>
#include "init.h"
#include "hooks.h"
#include "thread.h"
#include "restrict.h"
#include "debug.h"

// check if a promise (permission) is granted to a thread
#define CHECK_NEEDED_PROMISE(current, x)                      \
  do{                                                         \
    pid_t tid = current->pid;                                 \
    pid_t pid = current->tgid;                                \
    int index = -1;                                           \
    int ps = get_process(pid,0);                              \
    if(ps==-1) return 0;                                      \
    index = get_thread(tid, pid, 0);                          \
    if(index==-1) return 0;                                   \
    if(require_promise(index, x) == 0){                       \
      debug(index, "denied", x);                              \
      if(threads_list[index].learning_mode==1) return 0;      \
      kill_proc(current);                                     \
      return -EPERM;                                          \
    }                                                         \
    debug(index, "allowed", x);                               \
  } while(0)

static int sandbox_task_alloc(struct task_struct *task, unsigned long clone_flags){
  if (clone_flags & CLONE_THREAD) 
    CHECK_NEEDED_PROMISE(current, "threading");
  else 
    CHECK_NEEDED_PROMISE(current, "proc");
  // I think this is where I can apply execpromises if I have it in my model
  // init_child_thread(current, task); forgot what is this honestly, but keeping it here.
  return 0;
}

static int sandbox_task_fix_setuid(struct cred *new, const struct cred *old, int flags){
  CHECK_NEEDED_PROMISE(current, "id");
  return 0;
}

static int sandbox_task_fix_setgid(struct cred *new, const struct cred *old,int flags){
  CHECK_NEEDED_PROMISE(current, "id");
  return 0;
}

static int sandbox_task_fix_setgroups(struct cred *new, const struct cred *old){
  CHECK_NEEDED_PROMISE(current, "id");
  return 0;
}

static int sandbox_task_setpgid(struct task_struct *p, pid_t pgid){
  CHECK_NEEDED_PROMISE(current, "id");
  return 0;
}

static int sandbox_task_getpgid(struct task_struct *p){
  CHECK_NEEDED_PROMISE(current, "id");
  return 0;
}

static int sandbox_task_getsid(struct task_struct *p){
  CHECK_NEEDED_PROMISE(current, "id");
  return 0;
}

static int sandbox_task_setnice(struct task_struct *p, int nice){
  CHECK_NEEDED_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_setioprio(struct task_struct *p, int ioprio){
  CHECK_NEEDED_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_getioprio(struct task_struct *p){
  CHECK_NEEDED_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_prlimit(const struct cred *cred, const struct cred *tcred, unsigned int flags){
  CHECK_NEEDED_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_setrlimit(struct task_struct *p, unsigned int resource, struct rlimit *new_rlim){
  CHECK_NEEDED_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_setscheduler(struct task_struct *p){
  CHECK_NEEDED_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_getscheduler(struct task_struct *p){
  CHECK_NEEDED_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_movememory(struct task_struct *p){
  CHECK_NEEDED_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_kill(struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred){
  CHECK_NEEDED_PROMISE(current, "proc");
  return 0;
}

static int sandbox_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5){
  CHECK_NEEDED_PROMISE(current, "proc");
  return 0;
}

static int sandbox_socket_bind(struct socket *soc, struct sockaddr *address, int addrlen){
  if(address->sa_family == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(address->sa_family == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_create(int family, int type, int protocol, int kern){
  if(family == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(family == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_post_create(struct socket *soc, int family, int type, int protocol, int kern){
  if(family == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(family == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_socketpair(struct socket *socka, struct socket *sockb){
  struct sock *sk = socka->sk;
  int type = sk->sk_family;
  if(type == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(type == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_connect(struct socket *soc, struct sockaddr *address, int addrlen){
  if(address->sa_family == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(address->sa_family == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_listen(struct socket *soc, int backlog){
  struct sock *sk = soc->sk;
  int type = sk->sk_family;
  if(type == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(type == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_accept(struct socket *soc, struct socket *newsock){
  struct sock *sk = soc->sk;
  int type = sk->sk_family;
  if(type == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(type == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_sendmsg(struct socket *soc, struct msghdr *msg, int size){
  struct sock *sk = soc->sk;
  int type = sk->sk_family;
  if(type == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(type == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_recvmsg(struct socket *soc, struct msghdr *msg,int size, int flags){
  struct sock *sk = soc->sk;
  int type = sk->sk_family;
  if(type == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(type == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_getsockname(struct socket *soc){
  struct sock *sk = soc->sk;
  int type = sk->sk_family;
  if(type == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(type == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_getpeername(struct socket *soc){
  struct sock *sk = soc->sk;
  int type = sk->sk_family;
  if(type == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(type == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_getsockopt(struct socket *soc, int level, int optname){
  struct sock *sk = soc->sk;
  int type = sk->sk_family;
  if(type == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(type == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_setsockopt(struct socket *soc, int level, int optname){
  struct sock *sk = soc->sk;
  int type = sk->sk_family;
  if(type == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(type == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_shutdown(struct socket *soc, int how){
  struct sock *sk = soc->sk;
  int type = sk->sk_family;
  if(type == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(type == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_getpeersec_stream(struct socket *soc, sockptr_t optval, sockptr_t optlen, unsigned int len){
  struct sock *sk = soc->sk;
  int type = sk->sk_family;
  if(type == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(type == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_socket_getpeersec_dgram(struct socket *soc, struct sk_buff *skb, u32 *secid){
  struct sock *sk = soc->sk;
  int type = sk->sk_family;
  if(type == AF_INET) CHECK_NEEDED_PROMISE(current, "net");
  if(type == AF_UNIX) CHECK_NEEDED_PROMISE(current, "unix");
  return 0;
}

static int sandbox_path_mknod(const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev){
  // dpath before
  CHECK_NEEDED_PROMISE(current, "wpath");
  return 0;
}

static int sandbox_file_open(struct file *file){
  unsigned int flags = file->f_flags & O_ACCMODE;
  if(flags == O_WRONLY || flags == O_RDWR) CHECK_NEEDED_PROMISE(current, "wpath");
  // cpath before
  if(file->f_flags & O_CREAT) CHECK_NEEDED_PROMISE(current, "wpath");
  if(flags == O_RDONLY) CHECK_NEEDED_PROMISE(current, "rpath");
  return 0;
}

int sandbox_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode){ 
  CHECK_NEEDED_PROMISE(current, "wpath");
  return 0;
}

int sandbox_path_rmdir(const struct path *dir, struct dentry *dentry){
  CHECK_NEEDED_PROMISE(current, "wpath");
  return 0;
}

int sandbox_path_symlink(const struct path *dir, struct dentry *dentry, const char *old_name){
  CHECK_NEEDED_PROMISE(current, "wpath");
  return 0; 
}

int sandbox_path_link(struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry){
  CHECK_NEEDED_PROMISE(current, "wpath");
  return 0; 
}

int sandbox_path_unlink(const struct path *dir, struct dentry *dentry){
  CHECK_NEEDED_PROMISE(current, "wpath");
  return 0; 
}

int sandbox_path_rename(const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, unsigned int flags){
  CHECK_NEEDED_PROMISE(current, "wpath");
  return 0; 
}

int sandbox_path_truncate(const struct path *path){
  CHECK_NEEDED_PROMISE(current, "wpath");
  return 0; 
}

int sandbox_path_chmod(const struct path *path, umode_t mode){
  CHECK_NEEDED_PROMISE(current, "wpath");
  return 0; 
}

int sandbox_path_chown(const struct path *path, kuid_t uid, kgid_t gid){
  CHECK_NEEDED_PROMISE(current, "wpath");
  return 0; 
}

// check clean up a sandboxed process/thread.
static void sandbox_task_free(struct task_struct *task){
  int pid = task->tgid;
  int tid = task->pid;
  int remove_process = 0;
  pid_t cpid = current->tgid;
  pid_t ctid = current->pid;
  // this is the main thread, so remove from sandboxed_ps
  if(cpid == pid && ctid == tid) remove_process=1;
  remove_sandbox(pid, tid, remove_process);
}

struct security_hook_list hooks[] __ro_after_init = {
  // LSM related
  LSM_HOOK_INIT(task_free, sandbox_task_free),

  // net promise
  LSM_HOOK_INIT(socket_create, sandbox_socket_create),
  //LSM_HOOK_INIT(socket_post_create, sandbox_socket_post_create),
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
  //LSM_HOOK_INIT(task_getioprio, sandbox_task_getioprio),
  LSM_HOOK_INIT(task_prlimit, sandbox_task_prlimit),
  LSM_HOOK_INIT(task_setrlimit, sandbox_task_setrlimit),
  LSM_HOOK_INIT(task_setscheduler, sandbox_task_setscheduler),
  //LSM_HOOK_INIT(task_getscheduler, sandbox_task_getscheduler),
  //LSM_HOOK_INIT(task_movememory, sandbox_task_movememory),
  LSM_HOOK_INIT(task_kill, sandbox_task_kill),
  LSM_HOOK_INIT(task_prctl, sandbox_task_prctl),

  // wpath promises 
  LSM_HOOK_INIT(file_open, sandbox_file_open),
  LSM_HOOK_INIT(path_mkdir, sandbox_path_mkdir),
  LSM_HOOK_INIT(path_rmdir, sandbox_path_rmdir),
  LSM_HOOK_INIT(path_unlink, sandbox_path_unlink),
  LSM_HOOK_INIT(path_symlink, sandbox_path_symlink),
  LSM_HOOK_INIT(path_link, sandbox_path_link),
  LSM_HOOK_INIT(path_rename, sandbox_path_rename),
  LSM_HOOK_INIT(path_truncate, sandbox_path_truncate),
  LSM_HOOK_INIT(path_chmod, sandbox_path_chmod),
  LSM_HOOK_INIT(path_chown, sandbox_path_chown),
  LSM_HOOK_INIT(path_mknod, sandbox_path_mknod),
  //LSM_HOOK_INIT(inode_mknod, sandbox_inode_mknod),

  // id promise
  LSM_HOOK_INIT(task_fix_setuid, sandbox_task_fix_setuid),
  LSM_HOOK_INIT(task_fix_setgid, sandbox_task_fix_setgid),
  LSM_HOOK_INIT(task_fix_setgroups, sandbox_task_fix_setgroups),
  LSM_HOOK_INIT(task_setpgid, sandbox_task_setpgid),
  LSM_HOOK_INIT(task_getpgid, sandbox_task_getpgid),
  LSM_HOOK_INIT(task_getsid, sandbox_task_getsid),
};

__init void create_hooks(void){
	security_add_hooks(hooks, ARRAY_SIZE(hooks), FUNCSANDBOX_NAME);
}
