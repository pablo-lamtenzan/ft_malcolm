
# include <inttypes.h>
# include <fcntl.h>
# include <unistd.h>
# include <sys/types.h>
# include <stdio.h>
# include <stdbool.h>
# include <netdb.h>
# include <netdb.h>
# include <netinet/if_ether.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <netinet/ip_icmp.h>

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
\t-res2 (uint16_t:2): %hhu\n\
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
		(tcp).res2,																	\
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
		sizeof(udp),																	\
		(udp).source,																\
		(udp).dest,																	\
		(udp).len,																	\
		(udp).check)																\
)

# define PRINT_ICMPHDR(fd, icp) (													\
		dprintf(fd, "\n*** ICMP HEADER (%lu)***\n\
\t-type (uint8_t): %hhu\n\
\t-code (uint8_t): %hhu\n\
\t-checksum (unt16_t): %hu\n\
\t-id | __glibbc_reserved (uint16_t): %hu\n\
\t-sequence | mtu (uint16_t): %hu\n",												\
		sizeof(icp),																\
		(icp).type,																	\
		(icp).code,																	\
		(icp).checksum,																\
		(icp).un.echo.id,																	\
		(icp).un.echo.sequence)																\
)

# define PRINT_PAYLOAD(fd, payload, payloadlen)										\
		for (ssize_t i = 0 ; i < (payloadlen) ; i++)								\
			dprintf((fd), "[%5ld]={dec: %3hhd, udec: %3hhu, hex: %2x, ascii: %c}\n",\
			i, (payload)[i], (payload)[i], (payload)[i],(payload)[i]);				\
			write((fd), "\nraw data: ", sizeof("\nraw data: ") - 1);				\
			write((fd), (payload), (payloadlen));									\
			write((fd), "\n", sizeof("\n") - 1);

# define PRINT_START_PACKET(fd, count, len) (										\
		dprintf(fd, "############ START PACKET #%lu (%ld) ############\n\n", count, len)	\
)

# define PRINT_END_PACKET(fd, count, len) (												\
		dprintf(fd, "\n\n############ END PACKET #%lu (%ld) ############\n\n", count, len)	\
)

void log_content(uint8_t* const content, ssize_t contentlen, bool isstdout)
{
	static bool openonce = false;
	static uint64_t count = 0;

	int logfd;

	printf(".");
	fflush(stdout);

	if (isstdout == false)
	{
		if (openonce == false)
		{
			if ((logfd = open(DEFAULTLOGNAME, O_CREAT | O_WRONLY | O_APPEND)) < 0)
				return ;
			openonce = true;
		}
	}
	else
		logfd = STDOUT_FILENO;

	PRINT_START_PACKET(logfd, ++count, contentlen);

	if (contentlen < sizeof(struct ethhdr))
	{
		PRINT_END_PACKET(logfd, count, contentlen);
		return ;
	}

	const struct ethhdr* const eth = (const struct ethhdr*)content;
	PRINT_ETHHDR(logfd, *eth);

	if (contentlen < sizeof(*eth) + sizeof(struct iphdr)
	|| eth->h_proto != ntohs(ETH_P_IP))
	{
		PRINT_END_PACKET(logfd, count, contentlen);
		return ;
	}

	const struct iphdr* const ip = (const struct iphdr*)(content + sizeof(*eth));
	PRINT_IPHDR(logfd, *ip);

	size_t iphl = (ip->ihl * 4);
	size_t transport_len = 0;

	switch (ip->protocol)
	{
		case IPPROTO_TCP:
			if (contentlen < sizeof(*eth) + iphl + sizeof(struct tcphdr))
			{
				PRINT_END_PACKET(logfd, count, contentlen);
				return ;
			}
			const struct tcphdr* const tcp = (const struct tcphdr*)(content + sizeof(*eth) + iphl);
			PRINT_TCPHDR(logfd, *tcp);
			transport_len = tcp->doff * 4;
			break ;

		case IPPROTO_UDP:
			if (contentlen < sizeof(*eth) + iphl + sizeof(struct udphdr))
			{
				PRINT_END_PACKET(logfd, count, contentlen);
				return ;
			}
			const struct udphdr* const udp = (const struct udphdr*)(content + sizeof(*eth) + iphl);
			PRINT_UDPHDR(logfd, *udp);
			transport_len = sizeof(*udp);
			break ;

		case IPPROTO_ICMP:
			if (contentlen < sizeof(*eth) + iphl + sizeof(struct icmphdr))
			{
				PRINT_END_PACKET(logfd, count, contentlen);
				return ;
			}
			const struct icmphdr* const icp = (const struct icmphdr*)(content + sizeof(*eth) + iphl);
			PRINT_ICMPHDR(logfd, *icp);
			PRINT_END_PACKET(logfd, count, contentlen);
			return ;

		default:
			return ;
	}

	if (transport_len)
	{
		const size_t metadatalen = sizeof(*eth) + iphl + transport_len;
		uint8_t* payload = content + metadatalen;
		PRINT_PAYLOAD(logfd, payload, contentlen - metadatalen);
	}

	if (isstdout == false)
	{
		close(logfd);
		openonce = false;
	}
	PRINT_END_PACKET(logfd, count, contentlen);
}
