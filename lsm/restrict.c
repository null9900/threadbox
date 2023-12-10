#include "restrict.h"
#include "thread.h"

int add_sandbox_ps(int pid){
  for(int i =0;i<MAX_SIZE;i++){
    if(sandboxed_ps[i]==-1){
      sandboxed_ps[i]=pid;
      return 1;
    }
  }
  return 0;
}

void remove_sandbox(int pid, int tid){
  int ps = check_process(pid);
  if(ps==0) return;
  int index = get_thread(tid,0);
  if(index==-1) return;
  threads_list[index].disable_all = 1;
  threads_list[index].sandboxed = 0;
}

int check_bind_port(int pid, int tid, int port){ 
  int ps = check_process(pid);
  if(ps==0) return 1;
  int index = get_thread(tid,0);
  if(index==-1) return 1;
  if(threads_list[index].allowed_port_bind!=port)
    return -1;
  return 0;
}

int check_fork(int pid, int tid){
  int ps = check_process(pid);
  if(ps==0) return 1;
  int index = get_thread(tid,0);
  if(index==-1) return 1;
  if(threads_list[index].allowed_fork!=1)
    return -1;
  return 0;
}

void restrict_bind_port(int pid, int tid, int port){
  int ps = check_process(pid);
  if(ps==0) return;
  int index = get_thread(tid,1);
  if(threads_list[index].sandboxed == 1){
    return;
  }
  threads_list[index].allowed_port_bind=port;
  threads_list[index].sandboxed = 1;
}

void restrict_fork(int pid, int tid){
  int ps = check_process(pid);
  if(ps==0) return;
  int index = get_thread(tid,1);
  if(threads_list[index].sandboxed == 1){
    return;
  }
  threads_list[index].allowed_fork = 1;
  threads_list[index].sandboxed = 1;
}
