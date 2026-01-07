CC = gcc
ASM = nasm

LIB = libasm/libasm.a Libft/libft.a
LIBDIR = libasm Libft

PAYLOAD32 = Payload/payload32.bin
PAYLOAD64 = Payload/payload64.bin
PAYLOAD32SRC = Payload/XTEA_decrypt_32.s
PAYLOAD64SRC = Payload/XTEA_decrypt_64.s

PAYLOADFLAGS = -f bin

_pos = $(if $(findstring $1,$2),$(call _pos,$1,\
       $(wordlist 2,$(words $2),$2),x $3),$3)
pos = $(words $(call _pos,$1,$2))

SRC = src/main.c \
	src/elf_parsing.c \
	src/elf32_parsing.c \
	src/elf64_parsing.c \
	src/utils.c \
	src/payload_insert.c \
	src/payload_insert32.c \
	src/payload_insert64.c \
	src/msg.c \
	src/encrypt_engine.c \
	Payload/XTEA_encrypt.c \

OBJ = ${SRC:.c=.o}

CFLAGS = -Wall -Wextra -Werror -g -z noexecstack -I include
CLIBS = -L./libasm -lasm -L./Libft -lft
NAME = woody_woodpacker

all: $(NAME)

$(NAME): $(LIB) $(OBJ) $(PAYLOAD32) $(PAYLOAD64)
	$(CC) $(CFLAGS) $(OBJ) $(CLIBS) -o $(NAME)

$(PAYLOAD32):
	$(ASM) $(PAYLOADFLAGS) $(PAYLOAD32SRC) -o $(PAYLOAD32)

$(PAYLOAD64):
	$(ASM) $(PAYLOADFLAGS) $(PAYLOAD32SRC) -o $(PAYLOAD64)

$(LIB):
	make -C $(word $(call pos, $@, $(LIB)), $(LIBDIR));

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