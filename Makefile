NAME		=		ft_ping
OBJDIR		=		bin_objs
CC			=		/usr/bin/gcc
RM			=		/bin/rm

include				srcs.mk

CFLAGS		=		-Wall -Wextra -Werror
IFLAGS		=		-I$(INCDIR)

OBJS		=		$(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))

# all:				$(NAME)

# $(NAME):			$(OBJS)
# 	@echo LINK $@
# 	$(CC) $(OBJS) $(CFLAGS) -o $@

# $(OBJDIR):
# 	mkdir -p $@

# $(OBJDIR)/%.o:		$(SRCDIR)/%.c $(HDRS) $(OBJDIR)
# 	@mkdir -p '$(@D)'
# 	@echo CC $<
# 	@$(CC) $(CFLAGS) $(IFLAGS) -c -o $@ $<

# clean:
# 	@echo RM $(OBJDIR)
# 	@$(RM) -rf $(OBJDIR)

# fclean:				clean
# 	@echo RM $(NAME)
# 	@$(RM) -f $(NAME)

# re:					fclean all

# .PHONY:				clean fclean

# $(VERBOSE).SILENT:

all: $(NAME)
	@:

$(NAME) : $(OBJDIR) $(OBJS)
	gcc -o $(NAME) $(CFLAGS) $(OBJS)

$(OBJDIR):
	mkdir -p $@

$(OBJDIR)/%.o : srcs/%.c
	mkdir -p $(shell dirname $@)
	gcc -c -o $@  -I./includes $<

clean:
	rm -rf $(OBJDIR)

fclean: clean
	rm -rf $(NAME)

re: fclean all
