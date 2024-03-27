#include "debug.h"
#include "thread.h"
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/path.h>
#include <linux/namei.h>

void set_debug_name(int pid, int tid, char* name, int count){ 
  int ps = get_process(pid,0);
  if(ps==-1) return;
  int index = get_thread(tid, pid, 0);
  if(index==-1) return;
  strscpy(threads_list[index].debug_name, name, count+1);
  threads_list[index].debug = 1;
}

void debug(int tid, int pid, char* promise){
  int index = get_thread(tid, pid, 0);
  if(index==-1) return;
  if(threads_list[index].debug==0){
    pr_info("%s access is deined for thread %d\n", promise, tid);
  }else{
    char* debug_name = threads_list[index].debug_name;
    pr_info("%s access is deined for %s module \n", promise, debug_name);
  }
}
