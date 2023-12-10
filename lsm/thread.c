#include "thread.h"

static Thread threads_list[MAX_SIZE];
static int sandboxed_ps[MAX_SIZE];
static int t_index = 0;

static int get_thread(int tid,int create){
  for(int i=0; i<MAX_SIZE; i++){
    if(threads_list[i].tid == tid){
      return i;
    }
  }
  if(t_index==MAX_SIZE) return -1;
  if(!create)
    return -1;
  threads_list[t_index].tid = tid;
  int to_return = t_index;
  t_index++;
  return to_return;
}

static int check_process(int pid){
  for(int i =0;i<MAX_SIZE;i++){
    if(sandboxed_ps[i]==pid)
      return 1;
  }
  return 0;
}

int sandbox_ps(int pid){
  for(int i =0;i<MAX_SIZE;i++){
    if(sandboxed_ps[i]==-1){
      sandboxed_ps[i]=pid;
      return 1;
    }
  }
  return 0;
}

int check_thread_listen_port(int pid, int tid, int port){
  int ps = check_process(pid);
  if(ps==0) return 1;
  int index = get_thread(tid,0);
  if(index==-1) return 0;
  if(threads_list[index].allowed_port_listen==port)
    return 1;
  return 0;
}

int check_thread_bind_port(int pid, int tid, int port){
  int ps = check_process(pid);
  if(ps==0) return 1;
  int index = get_thread(tid,0);
  if(index==-1) return 0;
  if(threads_list[index].allowed_port_bind!=port)
    return 0;
  return 1;
}

int check_thread_ioctl(int pid, int tid, int ioctl){
  int ps = check_process(pid);
  if(ps==0) return 1;
  int index = get_thread(tid,0);
  if(index==-1) return 0;
  if(threads_list[index].allowed_ioctl==ioctl)
    return 1;
  return 0;
}

int check_thread_fcntl(int pid, int tid, int fcntl){
  int ps = check_process(pid);
  if(ps==0) return 1;
  int index = get_thread(tid,0);
  if(index==-1) return 0;
  if(threads_list[index].allowed_fcntl==fcntl)
    return 1;
  return 0;
}

int check_thread_fork(int pid, int tid){
  int ps = check_process(pid);
  if(ps==0) return 1;
  int index = get_thread(tid,0);
  if(index==-1) return 0;
  if(threads_list[index].allowed_fork==1)
    return 1;
  return 0;
}

int check_thread_all(int pid, int tid){
  int ps = check_process(pid);
  if(ps==0) return 1;
  int index = get_thread(tid,0);
  if(index==-1) return 0;
  if(threads_list[index].disable_all==1)
    return 0;
  return 1;
}

void perm_disable(int pid, int tid){
  int ps = check_process(pid);
  if(ps==0) return;
  int index = get_thread(tid,1);
  if(threads_list[index].sandboxed == 1){
    return;
  }
  threads_list[index].disable_all = 1;
  threads_list[index].sandboxed = 1;
}

void perm_fork(int pid, int tid){
  int ps = check_process(pid);
  if(ps==0) return;
  int index = get_thread(tid,1);
  if(threads_list[index].sandboxed == 1){
    return;
  }
  threads_list[index].allowed_fork = 1;
  threads_list[index].sandboxed = 1;
}

void perm_ioctl(int pid, int tid, int ioctl){
  int ps = check_process(pid);
  if(ps==0) return;
  int index = get_thread(tid,1);
  if(threads_list[index].sandboxed == 1){
    return;
  }
  threads_list[index].allowed_ioctl=ioctl;
  threads_list[index].sandboxed = 1;
}

void perm_fcntl(int pid, int tid, int fcntl){
  int ps = check_process(pid);
  if(ps==0) return;
  int index = get_thread(tid,1);
  if(threads_list[index].sandboxed == 1){
    return;
  }
  threads_list[index].allowed_fcntl=fcntl;
  threads_list[index].sandboxed = 1;
}

void perm_port_listen(int pid, int tid, int port){
  int ps = check_process(pid);
  if(ps==0) return;
  int index = get_thread(tid,1);
  if(threads_list[index].sandboxed == 1){
    return;
  }
  threads_list[index].allowed_port_listen=port;
  threads_list[index].sandboxed = 1;
}

void perm_port_bind(int pid, int tid, int port){
  int ps = check_process(pid);
  if(ps==0) return;
  int index = get_thread(tid,1);
  if(threads_list[index].sandboxed == 1){
    return;
  }
  threads_list[index].allowed_port_bind=port;
  threads_list[index].sandboxed = 1;
}

void perm_remove(int pid, int tid){
  int ps = check_process(pid);
  if(ps==0) return;
  int index = get_thread(tid,0);
  if(index==-1) return;
  threads_list[index].disable_all = 1;
  threads_list[index].sandboxed = 0;
}

int check_sandboxed_process(int pid, int tid){
  int ps = check_process(pid);
  if(ps==0) return 0;
  return 1;
}

void init_list(){ 
  for(int i=0; i<MAX_SIZE; i++){
    threads_list[i].tid = -1;
    threads_list[i].sandboxed = -1;
    threads_list[i].disable_all = 1;
    sandboxed_ps[i] = -1;
  }
}
