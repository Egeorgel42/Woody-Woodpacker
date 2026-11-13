#ifndef TERMINAL_OUTPUT_H
#define TERMINAL_OUTPUT_H
#include "compiler.h"

#include <stdio.h>
#include <stdlib.h>

#define STRINGIFY_HELPER(x) #x
#define STRINGIFY(x) STRINGIFY_HELPER(x)

#define PROGRAM_NAME "ft_ping: "
#define PROGRAM_PREFIX_MESSAGE    PROGRAM_NAME __FILE__ ", " STRINGIFY(__LINE__) ": "

#define HELP_MESSAGE \
"\n\
Usage:\n\
    " PROGRAM_NAME " <executable> [encoding]\n"

#define	ERR_MMAP    PROGRAM_PREFIX_MESSAGE "mmap error: %s\n"
#define	ERR_STAT    PROGRAM_PREFIX_MESSAGE "stat error: %s\n"
#define	ERR_NCODE   PROGRAM_PREFIX_MESSAGE "Invalid code section\n"
#define	ERR_NELF    PROGRAM_PREFIX_MESSAGE "Invalid ELF file\n"
#define	ERR_NEXEC   PROGRAM_PREFIX_MESSAGE "File is not executable\n"
#define	ERR_OSABI   PROGRAM_PREFIX_MESSAGE "Unsupported OS ABI\n"
#define	ERR_CAVE    PROGRAM_PREFIX_MESSAGE "Couldn't find any code caves big enough for payload in executable\n"
#define	ERR_ELFHDR  PROGRAM_PREFIX_MESSAGE "Invalid ELF header\n"
#define	ERR_ENDIAN  PROGRAM_PREFIX_MESSAGE "Invalid endianness\n"
#define	ERR_OPEN    PROGRAM_PREFIX_MESSAGE "Open error: %s\n"
#define	ERR_READ    PROGRAM_PREFIX_MESSAGE "Error during read operation: %s\n"
#define	ERR_WRITE   PROGRAM_PREFIX_MESSAGE "Error during write operation: %s\n"
#define	ERR_MALLOC  PROGRAM_PREFIX_MESSAGE "Memory allocation failed: %s\n"
#define	ERR_LSEEK   PROGRAM_PREFIX_MESSAGE "lseek error: %s\n"
#define ERR_ASSERT  PROGRAM_PREFIX_MESSAGE "Assertion failed: %s\n"

#define print_message(format, ...)                  \
    fprintf(stdout, (char const*)format, ##__VA_ARGS__);

#define error(format, ...) {                        \
    fprintf(stderr, (char const*)format, ##__VA_ARGS__);         \
    exit(1);                                        \
    COMPILER_UNREACHABLE();                         \
}

#define error_if(condition, format, ...) {			\
    if (BRANCH_UNLIKELY(condition)) {				\
        error(format, ##__VA_ARGS__);				\
    }}

#if defined(NDEBUG)
	#define libassert(condition, msg) (void)0;
#else
	#define libassert(condition, msg) error_if(!(condition), ERR_ASSERT, msg);
#endif

#endif