#ifndef _NFCT_PROTO_H_
#define _NFCT_PROTO_H_

#include <stdint.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#ifndef ICMPV6_NI_QUERY
#define ICMPV6_NI_QUERY 139
#endif

#ifndef ICMPV6_NI_REPLY
#define ICMPV6_NI_REPLY 140
#endif

uint8_t __icmp_reply_type(uint8_t type);
uint8_t __icmpv6_reply_type(uint8_t type);

#endif
