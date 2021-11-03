
# include <ft_malcolm.h>
# include <arpa/inet.h>

err_t   parse_args(int ac, const char* av[], proginfo_t* const info)
{
    err_t st = SUCCESS;

    if (ac - 1 < MINARGNUM)
	{
       PRINT_ERROR("%s", MSG_USAGE);
		st = INVARG;
        goto error;
	}

    for (size_t i = 0 ; i < MINARGNUM ; i++)
    {
        if (i % 2 == 0)
        {
            ///TODO: Check for valid ip address
            if (0/* error */)
            {
                PRINT_ERROR(MSG_ERROR_INVIP, av[i]);
                st = INVARG;
                goto error;
            }
        }
        else
        {
            ///TODO: Check for valid mac address
            if (0/* error */)
            {
                PRINT_ERROR(MSG_ERROR_INVMAC, av[i]);
                st = INVARG;
                goto error;
            }
        }
    }

    (*(struct sockaddr_in*)&info->target.addr) = (struct sockaddr_in){
        .sin_family = AF_INET,
        .sin_addr = inet_addr(av[2]),
    };

    info->mymachine.ip = av[0];
    info->mymachine.mac = av[1];
    info->target.ip = av[2];
    info->target.mac = av[3];

error:
    return st;
}
