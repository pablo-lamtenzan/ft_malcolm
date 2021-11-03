
# include <ft_malcolm.h>
# include <ftlibc.h>

# include <arpa/inet.h>

# define STDOUTOPT "--stdout"

# define ISDIGIT(x) ((x) >= '0' && (x) <= '9')
# define ISHEX(x) ( ( ((x) >= 'a' && (x) <= 'f') || ((x) >= 'A' && (x) <= 'F') ) || ISDIGIT(x))
# define ISCOLON(x) ((x) == ':')
# define ISVALIDMAC(mac) (					\
	ISHEX((mac)[0]) && ISHEX((mac)[1])		\
	&& ISCOLON((mac)[3])					\
	&& ISHEX((mac)[4])	&& ISHEX((mac)[5])	\
	&& ISCOLON((mac)[6])					\
	&& ISHEX((mac)[7]) && ISHEX((mac)[8])	\
	&& ISCOLON((mac)[9])					\
	&& ISHEX((mac)[10]) && ISHEX((mac)[11])	\
	&& ISCOLON((mac)[12])					\
	&& ISHEX((mac)[13])	&& ISHEX((mac)[14])	\
	&& ISCOLON((mac)[15])					\
	&& ISHEX((mac)[16]) && ISHEX((mac)[17])	\
)

err_t   parse_args(int ac, const char* av[], proginfo_t* const info)
{
    err_t st = SUCCESS;
	in_addr_t ip;

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
            if ((ip = inet_addr(av[i])) < 0)
            {
                PRINT_ERROR(MSG_ERROR_INVIP, av[i]);
                st = INVARG;
                goto error;
            }
        }
        else
        {
            if (ISVALIDMAC(av[i]) == false)
            {
                PRINT_ERROR(MSG_ERROR_INVMAC, av[i]);
                st = INVARG;
                goto error;
            }
        }
    }

    (*(struct sockaddr_in*)&info->target.addr) = (struct sockaddr_in){
        .sin_family = AF_INET,
        .sin_addr = ip,
    };

    info->mymachine.ip = av[0];
    info->mymachine.mac = av[1];
    info->target.ip = av[2];
    info->target.mac = av[3];

error:
    return st;
}

err_t   parse_optional_args(const char* av[], proginfo_t* const info, bool* const isstdout)
{
    err_t st = SUCCESS;
	in_addr_t ip;

    if (*av && (ip = inet_addr(*av)) < 0)
    {
    	PRINT_ERROR(MSG_ERROR_INVIP, *av);
    	st = INVARG;
    	goto error;
    }
	if (*(++av) == 0 || ISVALIDMAC(*av) == false)
	{
		PRINT_ERROR(MSG_ERROR_INVMAC, *av == 0 ? "(not provided)" : *av);
		st = INVARG;
		goto error;
	}
	if (*(++av) && ft_strncmp(STDOUTOPT, *av, sizeof(STDOUTOPT)) == 0)
		*isstdout = true;
	else if (*av)
	{
		PRINT_ERROR(__progname ": unkown option: %s, do you mean: `%s\' instead ?\n", *av, STDOUTOPT);
		st = INVARG;
		goto error;
	}

    (*(struct sockaddr_in*)&info->router.addr) = (struct sockaddr_in){
        .sin_family = AF_INET,
        .sin_addr = ip,
    };

error:
	return st;
}
