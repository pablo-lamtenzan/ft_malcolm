
# include <ft_err.h>
# include <sys/types.h>
# include <ifaddrs.h>



# include <string.h> /// TODO: Use mine

err_t printf_ifnic()
{
    struct ifaddrs *ifap = (void*)0;

    if (getifaddrs(&ifap) < 0)
    {
        ///TODO: Print some error
        return INVSYSCALL;
    }

    const char* ptr = NULL;
    for (struct ifaddrs* i = ifap ; i != 0 ; i = i->ifa_next)
    {
        static const char eth0[] = "eth0";

        if (strncmp(eth0, i->ifa_name, sizeof(eth0) - 1) == 0)
        {
            ptr = i->ifa_name;
            break ;
        }
    }

    printf("Found available interface: %s\n", ptr ? ptr : "(none)");
    /// If found == (none) there's a problem ...

    freeifaddrs(ifap);
    return SUCCESS;
}
