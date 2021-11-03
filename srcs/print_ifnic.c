
# include <ft_err.h>
# include <ftlibc.h>

# include <ifaddrs.h>

err_t printf_ifnic()
{
    err_t st = SUCCESS;

    struct ifaddrs *ifap = (void*)0;

    if (getifaddrs(&ifap) < 0)
    {
        PRINT_ERROR(MSG_ERROR_SYSCALL, "getifaddrs");
        st = INVSYSCALL;
        goto error;
    }

    const char* ptr = NULL;
    for (struct ifaddrs* i = ifap ; i != 0 ; i = i->ifa_next)
    {
        static const char eth0[] = "eth0";

        if (ft_strncmp(eth0, i->ifa_name, sizeof(eth0) - 1) == 0)
        {
            ptr = i->ifa_name;
            break ;
        }
    }

    if (ptr)
        printf("Found available interface: %s\n", ptr);
    else
    {
        PRINT_ERROR("%s", MSG_ERROR_IFETH0_NOT_FOUND);
        st = INVIF;
    }

    freeifaddrs(ifap);
error:
    return SUCCESS;
}
