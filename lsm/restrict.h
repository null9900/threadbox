#pragma once
#include <linux/sched.h>

// used by fs.c
int add_sandbox_ps(int pid);
int parse_promises(int pid, int tid, char *promise);

// used by hooks.c
int require_promise(int pid, int tid, char *promise);
void remove_sandbox(int pid, int tid, int remove_process);
void kill_proc(struct task_struct *task);
void init_child_thread(struct task_struct *main, struct task_struct *task);


