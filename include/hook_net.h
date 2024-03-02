#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/ip.h>

static struct nf_hook_ops nfhook;
struct net_device *dev;

typedef struct {
  unsigned char kind;
  unsigned char size;
}
tcp_option_t;


int register_net_hook(void);