#include <linux/module.h>
#include <linux/version.h>
#include <linux/kern_levels.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


#define KMODULE_NAME "ipsec_drop"
#define ERR(...) printk( KERN_ERR KMODULE_NAME": "__VA_ARGS__ )
#define LOG(...) printk( KERN_INFO KMODULE_NAME": "__VA_ARGS__ )

#define DEBUG_MODE
#undef DEBUG_MODE


void log_frame(const struct sk_buff * skb)
{
  const struct ethhdr* eth = eth_hdr(skb);
  //это не обязательно ipv4!!!:
  const struct iphdr* iph = ip_hdr(skb);
  if (iph)
  {
    LOG(
      "rx %s %pM > %pM (%04x) hdrlen=%d proto=%02x %pI4 > %pI4\n",
      skb->dev->name,
      eth->h_dest, eth->h_source, (int)htons(skb->protocol),
      (int)iph->ihl,
      (int)iph->protocol,
      &iph->saddr,
      &iph->daddr
    );
  }
  else if (eth)
  {
    LOG(
      "rx %s %pM > %pM (%04x) len=%d\n",
      skb->dev->name,
      eth->h_dest, eth->h_source, (int)htons(skb->protocol),
      (int)skb->len
    );
  }
  else
  {
    LOG(
      "rx %s len=%d\n",
      skb->dev->name,
      (int)skb->len
    );
  }
}

int ipsec_drop_check(struct sk_buff *skb)
{
  int rest_octets;
  const unsigned char* opts;
  //const struct iphdr *iph = ip_hdr(skb);
  const struct iphdr *nh = (struct iphdr *)skb_network_header(skb);
  unsigned int iphdr_size = sizeof(struct iphdr);

  // получаем информацию о сообщении сетевого уровня
  // (ждём здесь только ipv4, т.к. ограничили это на этапе регистрации)
  // быстро проверяем, а если ли ip-options в пришедшем пакете?
  if (nh && ((4*nh->ihl) > iphdr_size))
  {
    // поиск ip-options из RFC-1108, если таковые найдутся, то запрещаем их
    rest_octets = 4 * nh->ihl - iphdr_size;
    opts = (const unsigned char*)(nh) + iphdr_size;

    while (rest_octets >= 4)
    {
      #ifdef DEBUG_MODE
      ERR("ip-option %02x %02x\n", (int)(*opts&0xff), (int)(*(opts+1)&0xff));
      #endif

      // все опции пропускаем, кроме:
      //  - DoD Basic Security (130) и
      //  - DoD Extended Security (133)
      if (*opts == 130 || *opts == 133)
      {
        // попался, дропаем его!
        return NF_DROP;
      }
      // проверка инвалидного состояния (зацикливание)
      // и переход к следующим ip-options
      if (opts[1] == 0) break;
      rest_octets -= opts[1];
      opts += opts[1];
    }
  }
  return NF_ACCEPT;
}

unsigned int ipsec_drop_prerouting(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  // непонятно что от нас хотят? но падать на ровном месте не будем
  if (skb == NULL) return NF_DROP;

  #ifdef DEBUG_MODE
  log_frame(skb);
  #endif

  // иногда приходит всякая ерунда без mac, - пропускаем
  if (!skb_mac_header_was_set(skb)) return NF_DROP;
  else if (skb->mac_len != ETH_HLEN) return NF_DROP;

  // проверяем содержимое пришедшего пакета
  return ipsec_drop_check(skb);
}

unsigned int ipsec_drop_postrouting(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  // непонятно что от нас хотят? но падать на ровном месте не будем
  if (skb == NULL) return NF_DROP;

  #ifdef DEBUG_MODE
  log_frame(skb);
  #endif

  // проверяем содержимое пришедшего пакета
  return ipsec_drop_check(skb);
}

struct nf_hook_ops prerouting_hook = {
  .hooknum = NF_INET_PRE_ROUTING,
  .priority = NF_IP_PRI_NAT_DST - 1,
  .pf = NFPROTO_IPV4,
  .hook = &ipsec_drop_prerouting
};
struct nf_hook_ops postrouting_hook = {
  .hooknum = NF_INET_POST_ROUTING,
  .priority = NF_IP_PRI_FIRST,
  .pf = NFPROTO_IPV4,
  .hook = &ipsec_drop_postrouting
};

static void ipsec_drop_unregister_hooks( void )
{
  struct net *n;
  // дерегистрация фильтра фреймов
  for_each_net(n)
  {
    nf_unregister_net_hook(n, &prerouting_hook);
    nf_unregister_net_hook(n, &postrouting_hook);
  }
  LOG( "ipsec drop hooks detached\n");
}

static int __init ipsec_drop_init( void )
{
  int err;
  struct net *n;

  // настройка перехвата сообщений сетевого интерфейса (ip)
  // подключаем этот модуль для ip-стека до прерутинга с высоким приоритетом
  // кажется (судя по исходникам ядра) можно подключить эти хуки к dev, если указать pf=NFPROTO_NETDEV
  // (более подробно не разбирался)
  for_each_net(n)
  {
    err = nf_register_net_hook(n, &prerouting_hook);
    if (err < 0)
    {
      ERR("ipsec drop hooks not registered, err=%d", err);
      goto err;
    }
    err = nf_register_net_hook(n, &postrouting_hook);
    if (err < 0)
    {
      ERR("ipsec drop hooks not registered, err=%d", err);
      goto err;
    }
  }

  LOG("module %s loaded\n", THIS_MODULE->name);
  return 0;

err:
  ipsec_drop_unregister_hooks();
  ERR("module %s stopped, err=%d", THIS_MODULE->name, err);
  return err;
}

void __exit ipsec_drop_exit( void )
{
  ipsec_drop_unregister_hooks();
  LOG("module %s unloaded\n", THIS_MODULE->name);
}

module_init( ipsec_drop_init );
module_exit( ipsec_drop_exit );

MODULE_AUTHOR( "Noname Unnamed" );
MODULE_LICENSE( "GPL" );
MODULE_VERSION( "0.1" );
MODULE_DESCRIPTION("ip security (RFC 1108) dropper");
