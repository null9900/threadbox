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
  unsigned int promises;
} Thread;

extern Thread threads_list[MAX_SIZE];
extern int sandboxed_ps[MAX_SIZE];
extern int t_index;

void init_list(void);
int get_thread(int tid, int create);
int check_process(int pid);

extern char *promises[];
extern const int P_NUM;
