#pragma once
#define MAX_SIZE 100

typedef struct{
  int tid;
  int pid;
  int sandboxed;
  unsigned int promises;
} Thread;

extern Thread threads_list[MAX_SIZE];
extern int sandboxed_ps[MAX_SIZE];

void init_list(void);
int get_thread(int tid, int pid, int create);
int get_process(int pid, int create);

extern char *promises[];
extern const int P_NUM;
