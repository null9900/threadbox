#include "restrict.h"
#include "thread.h"

int add_sandbox_ps(int pid){
  return sandbox_ps(pid);
}

int check_listen_port(int pid, int tid, int port){
  return check_thread_listen_port(pid, tid, port); 
}

int check_bind_port(int pid, int tid, int port){
  return check_thread_bind_port(pid, tid, port);
}

int check_ioctl(int pid, int tid, int ioctl){
  return check_thread_ioctl(pid, tid, ioctl);
}

int check_fcntl(int pid, int tid, int fcntl){
  return check_thread_fcntl(pid, tid, fcntl);
}

int check_all(int pid, int tid){
  return check_thread_all(pid, tid);
}

int check_fork(int pid, int tid){
  return check_thread_fork(pid, tid);
}

void restrict_listen_port(int pid, int tid, int port){
  perm_port_listen(pid, tid, port); 
}

void restrict_bind_port(int pid, int tid, int port){
  perm_port_bind(pid, tid, port);
}

void restrict_ioctl(int pid, int tid, int ioctl){
  perm_ioctl(pid, tid, ioctl);
}

void restrict_fcntl(int pid, int tid, int fcntl){
  perm_fcntl(pid, tid, fcntl);
}

void restrict_all(int pid, int tid){
  perm_disable(pid, tid);
}

void restrict_fork(int pid, int tid){
  perm_fork(pid, tid);
}

void remove_sandbox(int pid, int tid){
  perm_remove(pid, tid);
}
