# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: lumenthi <lumenthi@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2017/12/22 14:06:43 by lumenthi          #+#    #+#              #
#    Updated: 2021/02/02 14:58:34 by lumenthi         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

.PHONY : all clean fclean re run

NAME = infect

LINKER = ld
LINKER_FLAGS = --omagic # Make .text segment RWE to simulate .data env for our virus
COMPILER = nasm
COMPILER_FLAGS = -f elf64

GREEN = '\033[4;32m'
RED = '\033[4;31m'
BLANK = '\033[0m'
YELLOW = '\033[4;33m'
CYAN = '\033[4;38;5;51m'

TICK = '\033[1;32m~\033[0m'
CROSS = '\033[1;31mx\033[0m'

###### FOLDERS ######

SRCDIR = sources
OBJDIR = objs

###### SOURCES ######

SRCS = virus.s
SOURCES = $(addprefix $(SRCDIR)/, $(SRCS))

#####################

###### OBJECTS ######

OBJS = $(addprefix $(OBJDIR)/, $(SRCS:.s=.o))

#####################

###### TEST TARGET ######

TARGET = bu_ls
TEST_FOLDER = tests

#########################

all: $(NAME)

$(NAME): $(OBJS)
	$(LINKER) $(LINKER_FLAGS) -o $(NAME) $(OBJS)
	@ printf " %b | Compiled %b%b%b\n" $(TICK) $(GREEN) $(NAME) $(BLANK)

$(OBJS): $(OBJDIR)/%.o: $(SRCDIR)/%.s
	mkdir -p $(OBJDIR)
	$(COMPILER) $(COMPILER_FLAGS) -o $@ $<

clean:
	@ test -d $(OBJDIR) && \
	rm -rf $(OBJDIR) && \
	printf " %b | " $(TICK) && \
	printf "Removed %bobjects%b folders\n" $(YELLOW) $(BLANK) \
	|| (printf " %b | " $(CROSS) && \
	printf "No %bobjects%b folders\n" $(YELLOW) $(BLANK))

fclean: clean
	@ test -f $(NAME) && \
	rm -rf $(NAME) && \
	printf " %b | " $(TICK) && \
	printf "Removed %b%b%b binary\n" $(RED) $(NAME) $(BLANK) \
	|| (printf " %b | " $(CROSS) && \
	printf "No %b%b%b binary\n" $(RED) $(NAME) $(BLANK))

re: fclean all

run: $(NAME)
	@ cp $(TEST_FOLDER)/$(TARGET) target
	@ strace ./$(NAME)

c:
	cp $(TEST_FOLDER)/$(TARGET) target
	gcc -o c_infect $(SRCDIR)/inject.c
	strace ./c_infect
	./target
