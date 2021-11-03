
# include <ft_malcolm.h>

# include <netinet/if_ether.h>
# include <sys/socket.h>
# include <arpa/inet.h>

err_t init_rawsock(proginfo_t* const info, bool extended)
{
    if ((info->sockarp = socket(AF_INET, SOCK_RAW, htons(ETH_P_ARP))) < 0
    || (extended && (info->sockip = socket(AF_INET, SOCK_RAW, htons(ETH_P_IP))) < 0))
    {
        PRINT_ERROR(MSG_ERROR_SYSCALL, "socket");
        return INVSYSCALL;
    }

    return SUCCESS;
}
