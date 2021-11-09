
# include <ft_malcolm.h>
# include <arp.h>

# include <unistd.h>
# include <stdlib.h>
# include <signal.h>

///TODO: Clear unused/commened + end TODO's accross the code
///TODO: Forbiden function if_nametoindex in send_arp.c 

///TODO: In bonus do a interface selector as argument

///NOTES:
// 1) To perform an ARP Request only is needed target's IP (someone need to answer to the broadcast request) and my MAC address which's will receive a reply
// 2) To perform an ARP Reply i need an arbitrary src's MAC & src's IP
// 3) If both of the networks have each other in their ARP tables, for some reason they (SOMETIMES) receiv/send requets/replies which have a different destination
// but after waiting some time the behaviour remains as default.
// 4) Src's ARP table must contain target IP & MAC, target's ARP table must contain whatever is on srcs IP & MAC.

// 5) Linux kernel won't listen to an unsolicited ARP reply, but a spoofed ARP request can be used to trick it and make it listen to the reply

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
