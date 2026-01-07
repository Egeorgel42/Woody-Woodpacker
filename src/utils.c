#include "woody.h"

void	freeall(unsigned int argsnbr, ...)
{
	va_list args;
	va_start(args, argsnbr);
	for (unsigned int i = 0; i < argsnbr; i++)
	{
		void *addr = va_arg(args, void *);
		if (addr)
			free(addr);
	}
	va_end(args);
}