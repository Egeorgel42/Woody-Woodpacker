C = clang
ASM = nasm
LIB = ./libasm/libasm.a

SRC = main.c \

OBJ = ${SRC:.c=.o}

CFLAGS = -Wall -Wextra -Werror -g -fsanitize=address
CLIBS = -L. -lasm
NAME = woody_woodpacker

all: $(NAME)

$(NAME): $(LIB) $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(CLIBS) -o $(NAME)

$(LIB):
	make -C libasm

%.o : %.s
	$(ASM) -f elf64 -o $@ $<

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ)
	make clean -C libasm

fclean: clean
	rm -f $(NAME)
	make fclean -C libasm

re: fclean all

.PHONY: clean fclean re