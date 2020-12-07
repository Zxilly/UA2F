#include <internal/proto.h>
#include <internal/internal.h>

static const uint8_t invmap_icmp[] = {
	[ICMP_ECHO]		= ICMP_ECHOREPLY + 1,
	[ICMP_ECHOREPLY]	= ICMP_ECHO + 1,
	[ICMP_TIMESTAMP]	= ICMP_TIMESTAMPREPLY + 1,
	[ICMP_TIMESTAMPREPLY]	= ICMP_TIMESTAMP + 1,
	[ICMP_INFO_REQUEST]	= ICMP_INFO_REPLY + 1,
	[ICMP_INFO_REPLY]	= ICMP_INFO_REQUEST + 1,
	[ICMP_ADDRESS]		= ICMP_ADDRESSREPLY + 1,
	[ICMP_ADDRESSREPLY]	= ICMP_ADDRESS + 1
};

static const uint8_t invmap_icmpv6[] = {
	[ICMPV6_ECHO_REQUEST - 128]	= ICMPV6_ECHO_REPLY + 1,
	[ICMPV6_ECHO_REPLY - 128]	= ICMPV6_ECHO_REQUEST + 1,
	[ICMPV6_NI_QUERY - 128]		= ICMPV6_NI_QUERY + 1,
	[ICMPV6_NI_REPLY - 128]		= ICMPV6_NI_REPLY + 1
};

uint8_t __icmp_reply_type(uint8_t type)
{
	if (type < ARRAY_SIZE(invmap_icmp))
		return invmap_icmp[type];

	return 0;
}

uint8_t __icmpv6_reply_type(uint8_t type)
{
	if (type - 128 < ARRAY_SIZE(invmap_icmpv6))
		return invmap_icmpv6[type - 128];

	return 0;
}
