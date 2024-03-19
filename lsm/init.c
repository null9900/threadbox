#include <linux/lsm_hooks.h>
#include "init.h"
#include "hooks.h"
#include "thread.h"

static int __init funcsandbox_init(void){
	pr_info("Funcsandbox is protecting!\n");
  create_hooks();
  init_list();
	return 0;
}

DEFINE_LSM(FUNCSANDBOX_NAME) = {
	.name = FUNCSANDBOX_NAME,
	.init = funcsandbox_init
};
