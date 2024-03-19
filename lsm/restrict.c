#include "restrict.h"
#include "thread.h"
#include <linux/string.h>
#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>

static int get_promise_id(char* promise){
  for(int i =0;i<P_NUM;i++){
    if( strncmp(promise,promises[i], strlen(promises[i]))==0){
      return i;
    }
  }
  return -1;
}

void debug(){ 
  for(int i=0; i<t_index; i++){
    pr_info("thread index %d id %d promises %d\n",i,threads_list[i].tid,threads_list[i].promises);
  }
}

int add_sandbox_ps(int pid, int tid, char *promises){
  for(int i =0;i<MAX_SIZE;i++){
    if(sandboxed_ps[i]==-1){
      sandboxed_ps[i]=pid;
      int index = get_thread(tid,1);
      threads_list[index].sandboxed = 0;
      threads_list[index].promises = 0;
      parse_promises(pid, tid, promises);
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
  pr_info("removing sandbox for pid %d tid %d\n",pid, tid);
  threads_list[index].disable_all = 1;
  threads_list[index].sandboxed = 0;
  threads_list[index].promises = 0;
  threads_list[index].tid = -1;
}

int require_promise(int pid, int tid, char* promise){
  int ps = check_process(pid);
  if(ps==0) return 1;
  int index = get_thread(tid,0);
  if(index == -1) {
    return 1;
  }
  int p_id= get_promise_id(promise);
  int result =  threads_list[index].promises & (1 << p_id);
  return result;
}

int parse_promises(int pid, int tid, char* promises){
  int ps = check_process(pid);
  if(ps==0) return 1;
  int index = get_thread(tid,1);
  if(index==-1) return 1;
  if (threads_list[index].sandboxed==1) return 1;

  pr_info("parsing prom for pid %d tid %d\n",pid, tid);
  char* copy;
  copy=kstrdup(promises, GFP_KERNEL);

  char* tok = copy, *end = copy;
  int new_promises = 0;
  while(tok!=NULL){
    strsep(&end, " ");
    int pi = get_promise_id(tok);
    if(pi==-1) return -1;
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

void init_child_thread(struct task_struct *main, struct task_struct *task){
  int ps = check_process(main->tgid);
  if(ps==0) return;
  if(main->tgid == task->tgid){
    pr_info("setting default perm for %d %d\n", task->tgid, task->pid);
    int index = get_thread(task->pid,1);
    threads_list[index].sandboxed = 0;
    threads_list[index].promises = 0;
  }
}
