
# include <inttypes.h>
# include <fcntl.h>
# include <unistd.h>
# include <sys/types.h>
# include <stdio.h>
# include <stdbool.h>
# include <linux/if_ether.h>
# include <linux/ip.h>
# include <linux/tcp.h>
# include <linux/udp.h>
# include <linux/icmp.h>
# include <netdb.h>

# define DEFAULTLOGNAME "mitm_log.txt"

# define PRINT_ETHHDR(fd, eth) (													\
		dprintf(fd, "\n*** ETHERNET HEADER (%lu)***\n\
\t-h_dest (uint8_t[6]): %x:%x:%x:%x:%x:%x\n\
\t-h_source (uint8_t[6]): %x:%x:%x:%x:%x:%x\n\
\t-h_proto (uint16_t): %hu\n\n",													\
		sizeof(eth),																\
		(eth).h_dest[0], (eth).h_dest[1], (eth).h_dest[2],							\
		(eth).h_dest[3], (eth).h_dest[4], (eth).h_dest[5],							\
		(eth).h_source[0], (eth).h_source[1], (eth).h_source[2],					\
		(eth).h_source[3], (eth).h_source[4], (eth).h_source[5],					\
		(eth).h_proto)																\
)

# define PRINT_IPHDR(fd, ip) (														\
		dprintf(fd, "\n*** IP HEADER (%lu)***\n\
\t-version (uin8_t:4): %hhu\n\
\t-ihl (uin8_t:4): %hhu\n\
\t-tos (uint8_t): %hhu\n\
\t-tot_len (uint16_t): %hu\n\
\t-id (uint16_t): %hu\n\
\t-fragoff (uint16_t): %hu\n\
\t-ttl (uint8_t): %hu\n\
\t-protocol (uint8_t): %hu\n\
\t-check (uint16_t): %hu\n\
\t-saddr (uint32_t): %u\n\
\t-daddr (uin32_t): %u\n\n",														\
		(ip).ihl * 4,																\
		(ip).ihl,																	\
		(ip).version,																\
		(ip).tos,																	\
		(ip).tot_len,																\
		(ip).id		,																\
		(ip).frag_off,																\
		(ip).ttl,																	\
		(ip).protocol,																\
		(ip).check,																	\
		(ip).saddr,																	\
		(ip).daddr)																	\
)

# define PRINT_TCPHDR(fd, tcp) (													\
		dprintf(fd, "\n***TCP HEADER (%lu)***\n\
\t-source (uint16_t): %hu\n\
\t-dest (uint16_t): %hu\n\
\t-seq (uint16_t): %hu\n\
\t-ack_seq (uint16_t): %hu\n\
\t-res1 (uint16_t:4): %hhu\n\
\t-doff (uint16_t:4): %hhu\n\
\t-fin (uint16_t:1): %hhu\n\
\t-syn (uint16_t:1): %hhu\n\
\t-rst (uint16_t:1): %hhu\n\
\t-psh (uint16_t:1): %hhu\n\
\t-ack (uint16_t:1): %hu\n\
\t-urg (uint16_t:1): %hhu\n\
\t-ece (uint16_t:1): %hhu\n\
\t-cwr (uint16_t:1): %hhu\n\
\t-window (uint16_t): %hu\n\
\t-check (uint16_t): %hu\n\
\t-urg_prt (uint16_t): %hu\n\n",													\		
		(tcp).doff,																	\
		(tcp).source,																\
		(tcp).dest,																	\
		(tcp).seq,																	\
		(tcp).ack_seq,																\
		(tcp).res1,																	\
		(tcp).doff,																	\
		(tcp).fin,																	\
		(tcp).syn,																	\
		(tcp).rst,																	\
		(tcp).psh,																	\
		(tcp).ack,																	\
		(tcp).urg,																	\
		(tcp).ece,																	\
		(tcp).cwr,																	\
		(tcp).window,																\
		(tcp).check,																\
		(tcp).urg_ptr)																\
)

# define PRINT_UDPHDR(fd, udp) (													\
		dprintf(fd, "\n*** UDP HEADER (%lu)***\n\
\t-source (uint16_t): %hu\n\
\t-dest (uint16_t): %hu\n\
\t-len (uint16_t): %hu\n\
\t-check (uint16_t): %hu\n\n",														\
		(udp).len,																	\
		(udp).source,																\
		(udp).dest,																	\
		(udp).len,																	\
		(udp).check)																\
)

# define PRINT_ICMPHDR(fd, icp) ()

# define PRINT_PAYLOAD(fd, payload, payloadlen)										\
		for (ssize_t i = 0 ; i < (payloadlen) ; i++)								\
			dprinf((fd), "[%5ld]={dec: %3hhd, udec: %3hhu, hex: %2x, ascii: %c}\n",	\
			i, (payload)[i], (payload)[i], (payload)[i],(payload)[i]);				\
			write((fd), "\nraw data: ", sizeof("\nraw data: ") - 1);				\
			write((fd), (payload), (payloadlen));									\
			write((fd), "\n", sizeof("\n") - 1);

# define PRINT_START_PACKET(fd, len) (												\
		dprintf(fd, "############ START PACKET (%ld) ############\n\n", len)		\
)

# define PRINT_END_PACKET(fd, len) (												\
		dprintf(fd, "\n\n############ END PACKET (%ld) ############\n\n", len)		\
)

void log_content(uint8_t* const content, ssize_t contentlen)
{
	static bool openonce = false;

	int logfd;

	if (openonce == false)
	{
		openonce = true;
		if ((logfd = open(DEFAULTLOGNAME, O_CREAT | O_WRONLY)) < 0)
			return ;
	}

		PRINT_START_PACKET(logfd, contentlen);

	if (contentlen < sizeof(struct ethhdr))
	{
		PRINT_END_PACKET(logfd, contentlen);
		return ;
	}

	const struct ethhdr* const eth = (const struct ethhdr*)content;
	PRINT_ETHHDR(logfd, *eth);

	if (contentlen < sizeof(*eth) + sizeof(struct iphdr)
	|| eth->h_proto != ETH_P_IP)
	{
		PRINT_END_PACKET(logfd, contentlen);
		return ;
	}

	///TODO: Also must forward ARP request & replies (spoofing data)
	/// All IP's & MAC's has the same lenght so it will be easy to do it
	/// IF THERE'S NO CHECKSUM AT ETH LAYER

	const struct iphdr* const ip = (const struct iphdr*)(content + sizeof(*eth));
	PRINT_IPHDR(logfd, *ip);

	size_t iphl = (ip->ihl * 4);
	size_t transport_len = 0;

	switch (ip->protocol)
	{
		case IPPROTO_TCP:
			if (contentlen < sizeof(*eth) + iphl + sizeof(struct tcphdr))
			{
				PRINT_END_PACKET(logfd, contentlen);
				return ;
			}
			const struct tcphdr* const tcp = (const struct tcphdr*)(content + sizeof(*eth) + iphl);
			PRINT_TCPHDR(logfd, *tcp);
			transport_len = tcp->doff;
			break ;

		case IPPROTO_UDP:
			if (contentlen < sizeof(*eth) + iphl + sizeof(struct updhdr*))
			{
				PRINT_END_PACKET(logfd, contentlen);
				return ;
			}
			const struct udphdr* const udp = (const struct udphdr*)(content + sizeof(*eth) + iphl);
			PRINT_UDPHDR(logfd, *udp);
			transport_len = udp->len;
			break ;

		case IPPROTO_ICMP:
			PRINT_END_PACKET(logfd, contentlen);
			return ;

		default:
			;
	}

	if (transport_len)
	{
		const size_t metadatalen = sizeof(*eth) + iphl + transport_len;
		uint8_t* payload = content + metadatalen;
		PRINT_PAYLOAD(logfd, payload, contentlen - metadatalen);
	}

	PRINT_END_PACKET(logfd, contentlen);
}