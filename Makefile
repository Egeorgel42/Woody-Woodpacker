CC = gcc
ASM = nasm

ROOT_DIR := $(shell git rev-parse --show-toplevel)

LIB = Libft/libft.a
LIBDIR = Libft

PAYLOAD_DIR = $(ROOT_DIR)/Payload

PAYLOAD32 = $(PAYLOAD_DIR)/payload32.bin
PAYLOAD64 = $(PAYLOAD_DIR)/payload64.bin
PAYLOAD32SRC = $(PAYLOAD_DIR)/XTEA_decrypt_32.s
PAYLOAD64SRC = $(PAYLOAD_DIR)/XTEA_decrypt_64.s

PAYLOADFLAGS = -f bin

SRC = src/main.c \
	src/elf_parsing.c \
	src/elf32_parsing.c \
	src/elf64_parsing.c \
	src/payload_insert.c \
	src/payload_insert32.c \
	src/payload_insert64.c \
	src/msg.c \
	src/encrypt_engine.c \
	Payload/XTEA_encrypt.c \

OBJ = ${SRC:.c=.o}

CFLAGS = -Wall -Wextra -Werror -g -I include -D PAYLOAD_DIR=\"$(PAYLOAD_DIR)\"
CLIBS = -L./Libft -lft
NAME = woody_woodpacker

all: $(NAME)

$(NAME): $(LIB) $(OBJ) $(PAYLOAD32) $(PAYLOAD64)
	$(CC) $(CFLAGS) $(OBJ) $(CLIBS) -o $(NAME)

$(PAYLOAD32):
	$(ASM) $(PAYLOADFLAGS) $(PAYLOAD32SRC) -o $(PAYLOAD32)

$(PAYLOAD64):
	$(ASM) $(PAYLOADFLAGS) $(PAYLOAD64SRC) -o $(PAYLOAD64)

$(LIB):
	make -C $(LIBDIR);

%.o : %.s
	$(ASM) -f elf64 -o $@ $<

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ)
	rm -f woody
	for lib in $(LIBDIR); do \
		make clean -C $$lib;\
	done

fclean:
	rm -f $(OBJ)
	rm -f woody
	rm -f $(NAME)
	rm -f $(PAYLOAD32) $(PAYLOAD64)
	for lib in $(LIBDIR); do \
		make fclean -C $$lib;\
	done

re: fclean all

.PHONY: clean fclean re