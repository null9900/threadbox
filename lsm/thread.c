#include "thread.h"

Thread threads_list[MAX_SIZE];
int sandboxed_ps[MAX_SIZE];

char *promises[] = {"proc","net","id","wpath","rpath","unix", "threading"};
const int P_NUM=7;

// check if thread is sandboxed and return its index
int get_thread(int tid, int pid, int create){
  // check if thread exists, return its index
  for(int i=0; i<MAX_SIZE; i++){
    if(threads_list[i].tid == tid && threads_list[i].pid == pid) return i;
  }
  if(!create) return -1;
  // add new thread if not there
  // this is in a different loop to avoid TOCTOU
  // still prone to race conditions but can be solved with a mutex
  for(int i=0; i<MAX_SIZE; i++){
    if(threads_list[i].tid == -1){
      threads_list[i].tid = tid;
      threads_list[i].pid = pid;
      return i;
    }
  } 
  return -1;
}

// check if process is sandboxed and return its index
int get_process(int pid,int create){
  for(int i=0; i<MAX_SIZE; i++){
    if(sandboxed_ps[i]==pid) return i;
  }
  if(!create) return -1;
  for(int i=0; i<MAX_SIZE; i++){
    if(sandboxed_ps[i]==-1){
      sandboxed_ps[i]=pid;
      return i;
    }
  }
  return -1;
}

void init_list(){ 
  for(int i=0; i<MAX_SIZE; i++){
    threads_list[i].tid = -1;
    threads_list[i].pid = -1;
    threads_list[i].sandboxed = 0;
    threads_list[i].debug = 0;
    threads_list[i].learning_mode = 0;
    threads_list[i].promises = 0;
    sandboxed_ps[i] = -1;
  }
}
