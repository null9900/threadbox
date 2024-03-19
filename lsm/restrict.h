#pragma once
#include <linux/sched.h>

int add_sandbox_ps(int pid, int tidi, char *promises);

int require_promise(int pid, int tid, char *promise);
int parse_promises(int pid, int tid, char *promise);

void remove_sandbox(int pid, int tid);

void debug(void);
void kill_proc(struct task_struct *task);
void init_child_thread(struct task_struct *main, struct task_struct *task);

