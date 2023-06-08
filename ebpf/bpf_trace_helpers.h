#include "bpf_helpers.h"
#include <endian.h>

#define WARNING
#ifdef WARNING
#define bpf_warn(fmt, args...) bpf_printk(fmt, ##args)
#else
#define bpf_warn(fmt, args...)
#endif

#define INFO
#ifdef INFO
#define bpf_info(fmt, args...) bpf_printk(fmt, ##args)
#else
#define bpf_info(fmt, args...)
#endif

#define DEBUG
#ifdef DEBUG
#define bpf_debug(fmt, args...) bpf_printk(fmt, ##args)
#else
#define bpf_debug(fmt, args...)
#endif

#define TRACE
#ifdef TRACE
#define bpf_trace(fmt, args...) bpf_printk(fmt, ##args)
#else
#define bpf_trace(fmt, args...)
#endif