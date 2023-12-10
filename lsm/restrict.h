#pragma once

int add_sandbox_ps(int pid);
int check_listen_port(int pid, int tid, int port);
int check_bind_port(int pid, int tid, int port);
int check_ioctl(int pid, int tid, int ioclt);
int check_fcntl(int pid, int tid, int fnctl);
int check_fork(int pid, int tid);
int check_all(int pid, int tid);

void restrict_listen_port(int pid, int tid, int port);
void restrict_bind_port(int pid, int tid, int port);
void restrict_ioctl(int pid, int tid, int ioctl);
void restrict_fcntl(int pid, int tid, int fcntl);
void restrict_all(int pid, int tid);
void restrict_fork(int pid, int tid);
void remove_sandbox(int pid, int tid);
