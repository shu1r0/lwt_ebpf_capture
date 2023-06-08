
#include <stdbool.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/seg6.h>
#include <linux/seg6_local.h>

#include <linux/pkt_cls.h>

#include "bpf_helpers.h"
#include "bpf_trace_helpers.h"

struct metadata
{
  __u16 cookie;
  __u16 pkt_len;
} __attribute__((packed));

// Perf Map
struct bpf_map_def SEC("maps") perf_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = 128,
};

static __always_inline long perf_event_packet(void *ctx, __u16 cookie, __u16 pkt_len)
{
  struct metadata meta = {
      .cookie = cookie,
      .pkt_len = pkt_len};
  __u64 flags = BPF_F_CURRENT_CPU | ((__u64)pkt_len << 32);
  return bpf_perf_event_output(ctx, &perf_map, flags, &meta, sizeof(meta));
}

SEC("lwt_in/capture")
int capture(struct __sk_buff *skb)
{
  bpf_trace("Enter packet");
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  __u16 cookie = 0xbeef;
  __u16 pkt_len = data_end - data;
  long r = perf_event_packet(skb, cookie, pkt_len);

  return BPF_OK;
}

char _license[] SEC("license") = "GPL";
