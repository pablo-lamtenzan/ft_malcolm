
# include <ft_malcolm.h>

# include <netinet/if_ether.h>
# include <sys/socket.h>
# include <arpa/inet.h>

err_t init_rawsock(proginfo_t* const info, bool extended)
{
    if ((info->socksend = socket(AF_INET, SOCK_RAW, htons(ETH_P_ARP))) < 0
    || (info->sockrecv = socket(AF_INET, SOCK_RAW, htons(extended ? ETH_P_ALL : ETH_P_ARP))) < 0)
    {
        ///TODO: Some error mesage
        return INVSYSCALL;
    }

    return SUCCESS;
}
