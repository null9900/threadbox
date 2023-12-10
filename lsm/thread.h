#pragma once
#define MAX_SIZE 100

typedef struct{
  int tid;
  int disable_all;
  int allowed_ioctl;
  int allowed_port_listen;
  int allowed_port_bind;
  int allowd_socket_type;
  int allowed_fcntl;
  int allowed_fork;
  int sandboxed;
} Thread;

int sandbox_ps(int pid);

int check_thread_listen_port(int pid, int tid, int port);
int check_thread_bind_port(int pid, int tid, int port);
int check_thread_ioctl(int pid, int tid, int ioctl);
int check_thread_fcntl(int pid, int tid, int fcntl);
int check_thread_fork(int pid, int tid);
int check_thread_all(int pid, int tid);
int check_sandboxed_process(int pid, int tid);

void perm_ioctl(int pid, int tid, int ioctl);
void perm_port_listen(int pid, int tid, int port);
void perm_port_bind(int pid, int tid, int port);
void perm_fcntl(int pid, int tid, int fcntl);
void perm_fork(int pid, int tid);
void perm_disable(int pid, int tid);
void perm_remove(int pid, int tid);
void init_list(void);
