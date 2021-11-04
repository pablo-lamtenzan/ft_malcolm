INCDIR	=	includes
SRCDIR	=	srcs

HDRS	=\
$(addprefix includes/,\
	arp.h\
	ft_err.h\
	ftlibc.h\
	ft_malcolm.h\
	proginfo.h\
)
SRCS	=\
$(addprefix srcs/,\
	$(addprefix ftlibc/,\
		memcpy.c\
		memset.c\
		strncmp.c\
	)\
	init_rawsock.c\
	main.c\
	mandatory_requests.c\
	man_in_the_middle.c\
	packetlogger.c\
	parse.c\
	print_ifnic.c\
	send_arp.c\
)
