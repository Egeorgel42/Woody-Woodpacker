ASM = nasm
LIB = libasm.a

LIBSRC = ft_strlen.s \
ft_strcpy.s \
ft_strcmp.s \
ft_write.s \
ft_read.s \
ft_strdup.s

LIBOBJ = ${LIBSRC:.s=.o}

all: $(LIB)

$(LIB): $(LIBOBJ)
	ar rcs $(LIB) $(LIBOBJ)

%.o : %.s
	$(ASM) -f elf64 -o $@ $<

clean:
	rm -f $(LIBOBJ)

fclean: clean
	rm -f $(LIB)

re: fclean all

.PHONY: clean fclean re