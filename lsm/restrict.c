#include <linux/string.h>
#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include "restrict.h"
#include "thread.h"

// return promise id (number)
static int get_promise_id(char* promise){
  for(int i =0; i<P_NUM; i++){
    if(strncmp(promise,promises[i], strlen(promises[i]))==0) return i;
  }
  return -1;
}

// track that a process declared to be sandboxed
int add_sandbox_ps(int pid){
  return get_process(pid, 1);
}

// untrack threads/process
void remove_sandbox(int pid, int tid, int remove_process){
  int ps = get_process(pid,0);
  if(ps==-1) return;
  int index = get_thread(tid, pid, 0);
  if(index==-1) return;
  //pr_info("removing sandbox for pid %d tid %d\n",pid, tid);
  threads_list[index].sandboxed = 0;
  threads_list[index].promises = 0;
  threads_list[index].tid = -1;
  threads_list[index].pid = -1;
  threads_list[index].debug = 0;
  threads_list[index].learning_mode = 0;
  if(remove_process==1) sandboxed_ps[ps] = -1;
}

// check if a thread has a promise
int require_promise(int index, char* promise){
  int p_id = get_promise_id(promise);
  return  threads_list[index].promises & (1 << p_id);
}

// add promises to a thread
int parse_promises(int pid, int tid, char* promises){
  int ps = get_process(pid,0);
  if(ps==-1) return 1;
  int index = get_thread(tid, pid, 1);
  if(index==-1) return 1;
  
  //pr_info("parsing prom for pid %d tid %d\n",pid, tid);
  char* copy;
  copy=kstrdup(promises, GFP_KERNEL);
  char* tok = copy, *end = copy;
  int new_promises = 0;
  
  while(tok!=NULL){
    strsep(&end, " ");
    int pi = get_promise_id(tok);
    // if unknown promise or empty promises then give no permissions
    if(pi==-1){
      new_promises = 0;
      break;
    }
    new_promises |= (1 << pi);
    tok = end;
  }
  threads_list[index].promises = new_promises;
  threads_list[index].sandboxed = 1;
  return 0;
}

void kill_proc(struct task_struct *task){
  pr_info("kiling a process pid %d tid %d\n", current->tgid, current->pid);
  send_sig(SIGTERM, task, 1);
}

// not used now, I have not idea why I wrote this but keeping it in case
void init_child_thread(struct task_struct *main, struct task_struct *task){
  int ps = get_process(main->tgid,0);
  if(ps==-1) return;
  if(main->tgid == task->tgid){
    pr_info("setting default perm for %d %d\n", task->tgid, task->pid);
    int index = get_thread(task->pid, main->tgid, 1);
    threads_list[index].sandboxed = 0;
    threads_list[index].promises = 0;
  }
}
