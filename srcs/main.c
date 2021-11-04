
# include <ft_malcolm.h>
# include <arp.h>

# include <unistd.h>
# include <stdlib.h>
# include <signal.h>

# define ROOT_UID 0

volatile sig_atomic_t	unpoison = 0;
const proginfo_t*		ginfoptr;

//__attribute__ ((nonreturn))
static void terminate()
{
	if (unpoison != 0)
	{
		reset_arp_router(ginfoptr);
		reset_arp_target(ginfoptr);
	}
	close(ginfoptr->sockarp);
	close(ginfoptr->sockip);
	exit(EXIT_SUCCESS);
}

int	main(int ac, const char* av[])
{
	err_t		st = SUCCESS;
	proginfo_t	info = {0};

	if (getuid() != ROOT_UID)
	{
		PRINT_ERROR("%s", MSG_ERROR_NEED_PRIV);
		st = INVPRIV;
		goto error;
	}

	if ((st = parse_args(ac, ++av, &info)) != SUCCESS)
		goto error;
	av += MINARGNUM;
	if ((st = init_rawsock(&info, av != NULL)) != SUCCESS)
		goto error;

	ginfoptr = (const proginfo_t*)&info;
	if (signal(SIGINT, &terminate) == SIG_ERR
	|| signal(SIGTERM, &terminate) == SIG_ERR
	|| signal(SIGHUP, &terminate) == SIG_ERR)
	{
		PRINT_ERROR(MSG_ERROR_SYSCALL, "signal");
		st = INVSYSCALL;
		goto error;
	}

	if (av == NULL)
		st = mandatory_requests((const proginfo_t*)&info);
	else
		st = man_in_the_middle(av, (const proginfo_t*)&info, &unpoison);
error:
	terminate();
	return st;
}
