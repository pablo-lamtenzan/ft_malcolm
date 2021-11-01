
# include <proginfo.h>
# include <arp.h>

# include <inttypes.h>
# include <netinet/if_ether.h>

# include <string.h> ///TODO: Must use mine

///TODO: Set bits in MAC's for multicast

static err_t   send_arp(int fd, const struct sockaddr* dest, const struct ether_arp* earp, bool multicast)
{
    uint8_t buff[sizeof(*earp)] = {0};

    struct ether_arp* earp_buffptr = (struct ether_arp*)buff;
    *earp_buffptr = *earp;
	earp_buffptr->arp_tha[0] = multicast;

    const ssize_t sentbytes = sendto(fd, buff, sizeof(*earp), 0, dest, sizeof(*dest));

    if (sentbytes < 0)
    {
        ///TODO: Print error
        return INVSYSCALL;
    }

    return SUCCESS;
}

err_t   send_arp_request_to_target(const proginfo_t* const info, bool multicast)
{
    struct ether_arp earp = (struct ether_arp){
        .arp_hrd = htons(HARWARE_TYPE),  
        .arp_pro = htons(ETH_P_IP),
        .arp_hln = SIZEOFMAC,
        .arp_pln = SIZEOFIP,
        .arp_op = htons(ARP_REQUEST),
    };

    memcpy(erap.arp_sha, info->mymachine.mac, SIZEOFMAC);
    memcpy(erap.arp_spa, info->mymachine.ip, SIZEOFIP);
    memcpy(earp.arp_tha, info->target.mac, SIZEOFMAC);
    memcpy(earp.arp_tpa, info->target.ip, SIZEOFIP);

    return send_arp(info->socksend, (const struct sockaddr*)&info->target.addr,
	(const struct ether_arp*)&earp, multicast);
}

err_t   send_arp_request_to_router(const proginfo_t* const info, bool multicast)
{
    struct ether_arp earp = (struct ether_arp){
        .arp_hrd = htons(HARWARE_TYPE),  
        .arp_pro = htons(ETH_P_IP),
        .arp_hln = SIZEOFMAC,
        .arp_pln = SIZEOFIP,
        .arp_op = htons(ARP_REQUEST),
    };

    memcpy(erap.arp_sha, info->mymachine.mac, SIZEOFMAC);
    memcpy(erap.arp_spa, info->mymachine.ip, SIZEOFIP);
    memcpy(earp.arp_tha, info->router.mac, SIZEOFMAC);
    memcpy(earp.arp_tpa, info->router.ip, SIZEOFIP);

    return send_arp(info->socksend, (const struct sockaddr*)&info->target.addr,
	(const struct ether_arp*)&earp, multicast);
}

err_t   send_arp_reply_to_target(const proginfo_t* const info, bool multicast)
{
    struct ether_arp earp = (struct ether_arp){
        .arp_hrd = htons(HARWARE_TYPE),  
        .arp_pro = htons(ETH_P_IP),
        .arp_hln = SIZEOFMAC,
        .arp_pln = SIZEOFIP,
        .arp_op = htons(ARP_REPLY),
    };

    memcpy(erap.arp_sha, info->mymachine.mac, SIZEOFMAC);
    memcpy(erap.arp_spa, info->mymachine.ip, SIZEOFIP);
    memcpy(earp.arp_tha, info->target.mac, SIZEOFMAC);
    memcpy(earp.arp_tpa, info->target.ip, SIZEOFIP);

    return send_arp(info->socksend, (const struct sockaddr*)&info->target.addr,
	(const struct ether_arp*)&earp, multicast);
}

err_t   send_arp_request_to_router(const proginfo_t* const info, bool multicast)
{
    struct ether_arp earp = (struct ether_arp){
        .arp_hrd = htons(HARWARE_TYPE),  
        .arp_pro = htons(ETH_P_IP),
        .arp_hln = SIZEOFMAC,
        .arp_pln = SIZEOFIP,
        .arp_op = htons(ARP_REPLY),
    };

    memcpy(erap.arp_sha, info->mymachine.mac, SIZEOFMAC);
    memcpy(erap.arp_spa, info->mymachine.ip, SIZEOFIP);
    memcpy(earp.arp_tha, info->router.mac, SIZEOFMAC);
    memcpy(earp.arp_tpa, info->router.ip, SIZEOFIP);

    return send_arp(info->socksend, (const struct sockaddr*)&info->target.addr,
	(const struct ether_arp*)&earp, multicast);
}

err_t	reset_arp_target(const proginfo_t* const info, bool multicast)
{
    struct ether_arp earp = (struct ether_arp){
        .arp_hrd = htons(HARWARE_TYPE),  
        .arp_pro = htons(ETH_P_IP),
        .arp_hln = SIZEOFMAC,
        .arp_pln = SIZEOFIP,
        .arp_op = htons(ARP_REPLY),
    };

	memcpy(erap.arp_sha, info->router.mac, SIZEOFMAC);
    memcpy(erap.arp_spa, info->router.ip, SIZEOFIP);
    memcpy(earp.arp_tha, info->target.mac, SIZEOFMAC);
    memcpy(earp.arp_tpa, info->target.ip, SIZEOFIP);

    return send_arp(info->socksend, (const struct sockaddr*)&info->target.addr,
	(const struct ether_arp*)&earp, multicast);
}

err_t	reset_arp_router(const proginfo_t* const info, bool multicast)
{
    struct ether_arp earp = (struct ether_arp){
        .arp_hrd = htons(HARWARE_TYPE),  
        .arp_pro = htons(ETH_P_IP),
        .arp_hln = SIZEOFMAC,
        .arp_pln = SIZEOFIP,
        .arp_op = htons(ARP_REPLY),
    };

	memcpy(erap.arp_sha, info->target.mac, SIZEOFMAC);
    memcpy(erap.arp_spa, info->target.ip, SIZEOFIP);
    memcpy(earp.arp_tha, info->router.mac, SIZEOFMAC);
    memcpy(earp.arp_tpa, info->router.ip, SIZEOFIP);

    return send_arp(info->socksend, (const struct sockaddr*)&info->target.addr,
	(const struct ether_arp*)&earp, multicast);
}
