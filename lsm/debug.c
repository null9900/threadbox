#include <linux/string.h>
#include "debug.h"
#include "thread.h"

void set_learning_mode(int pid, int tid){
  int ps = get_process(pid,0);
  if(ps==-1) return;
  int index = get_thread(tid, pid, 0);
  if(index==-1) return;
  threads_list[index].learning_mode = 1;
}

void set_debug_name(int pid, int tid, char* name, int count){ 
  int ps = get_process(pid,0);
  if(ps==-1) return;
  int index = get_thread(tid, pid, 0);
  if(index==-1) return;
  strscpy(threads_list[index].debug_name, name, count+1);
  threads_list[index].debug = 1;
}

void debug(int index, char* action, char* promise){
  if(threads_list[index].debug==0) return;
  char* debug_name = threads_list[index].debug_name;
  pr_info("%s promise: %s for Thread: %s\n",action, promise, debug_name);
}
