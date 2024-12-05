#pragma once

#include <linux/types.h>

#define MAX_SIZE 100
#define FILE_NAME_SIZE 100

typedef struct{
  int tid;
  int pid;
  u8 sandboxed;
  unsigned int promises;
  char debug_name[MAX_SIZE];
  u8 debug;
  u8 learning_mode;
} Thread;

extern Thread threads_list[MAX_SIZE];
extern int sandboxed_ps[MAX_SIZE];

void init_list(void);
int get_thread(int tid, int pid, int create);
int get_process(int pid, int create);

extern char *promises[];
extern const int P_NUM;
