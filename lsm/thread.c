#include "thread.h"

Thread threads_list[MAX_SIZE];
int sandboxed_ps[MAX_SIZE];
int t_index = 0;

int get_thread(int tid,int create){
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

int check_process(int pid){
  for(int i =0;i<MAX_SIZE;i++){
    if(sandboxed_ps[i]==pid)
      return 1;
  }
  return 0;
}

void init_list(){ 
  for(int i=0; i<MAX_SIZE; i++){
    threads_list[i].tid = -1;
    threads_list[i].sandboxed = -1;
    threads_list[i].disable_all = 1;
    sandboxed_ps[i] = -1;
  }
}
