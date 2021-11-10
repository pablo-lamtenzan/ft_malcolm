
# include <ft_malcolm.h>
# include <arp.h>

# include <unistd.h>
# include <stdlib.h>
# include <signal.h>

///TODO: Forbiden function (by 42's subject) if_nametoindex in send_arp.c 

///TODO: In bonus do a interface selector as argument
///MAYBE: Need to bind to the selected interface with setsockopt
///DOC: https://stackoverflow.com/questions/14478167/bind-socket-to-network-interface

///NOTES:
// 1) To perform an ARP Request an IP (key) and a mac address (src) are required.
// 2) Linux Kernel won't listen to ARP Replies that wasn't trigerred by an ARP request, but is possible to
//	  make a target accept incoming replies by sending them a request previously. 
// 3) To perfrom an ARP Reply an arbitrary IP (key) and a arbitrary mac address (value) are needed,
//	  whether the reply is accepted those value will be set in destination host's ARP table.
// 4) Kernel updates constantly its ARP table by sending unicast/broadcast request to avoid corruption.

# define ROOT_UID 0

volatile sig_atomic_t	unpoison = 0;
const proginfo_t*		ginfoptr;

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
		goto end;
	}

	if ((st = parse_args(ac, ++av, &info)) != SUCCESS)
		goto end;
	av += MINARGNUM;
	if ((st = init_rawsock(&info, av != NULL)) != SUCCESS)
		goto free_end;

	ginfoptr = (const proginfo_t*)&info;
	if (signal(SIGINT, &terminate) == SIG_ERR
	|| signal(SIGTERM, &terminate) == SIG_ERR
	|| signal(SIGHUP, &terminate) == SIG_ERR)
	{
		PRINT_ERROR(MSG_ERROR_SYSCALL, "signal");
		st = INVSYSCALL;
		goto free_end;
	}

	if (*av == NULL)
		st = mandatory_requests((const proginfo_t*)&info);
	else
		st = man_in_the_middle(av, (const proginfo_t*)&info, &unpoison);
free_end:
	terminate();
end:
	return st;
}
