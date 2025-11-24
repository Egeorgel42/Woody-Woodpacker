CC = gcc
ASM = nasm

LIB = libasm/libasm.a libft/libft.a
LIBDIR = libasm libft

_pos = $(if $(findstring $1,$2),$(call _pos,$1,\
       $(wordlist 2,$(words $2),$2),x $3),$3)
pos = $(words $(call _pos,$1,$2))

SRC = src/main.c \
	src/elf_parsing.c \
	src/msg.c \

OBJ = ${SRC:.c=.o}

CFLAGS = -Wall -Wextra -Werror -g -z noexecstack
CLIBS = -L./libasm -lasm -L./libft -lft
NAME = woody_woodpacker

all: $(NAME)

$(NAME): $(LIB) $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(CLIBS) -o $(NAME)

$(LIB):
	make -C $(word $(call pos, $@, $(LIB)), $(LIBDIR));

%.o : %.s
	$(ASM) -f elf64 -o $@ $<

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ)
	for lib in $(LIBDIR); do \
		make clean -C $$lib;\
	done

fclean:
	rm -f $(OBJ)
	rm -f $(NAME)
	for lib in $(LIBDIR); do \
		make fclean -C $$lib;\
	done

re: fclean all

.PHONY: clean fclean re