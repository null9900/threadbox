#pragma once

int add_sandbox_ps(int pid);

int check_bind_port(int pid, int tid, int port);
int check_fork(int pid, int tid);

void restrict_bind_port(int pid, int tid, int port);
void restrict_fork(int pid, int tid);

void remove_sandbox(int pid, int tid);
