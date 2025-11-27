/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_fprintf.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: egeorgel <egeorgel@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/20 14:34:25 by egeorgel          #+#    #+#             */
/*   Updated: 2023/02/04 19:15:33 by egeorgel         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdarg.h>
#include <unistd.h>
#include "libft.h"
#include "ft_printf.h"

static void	ft_putnbr_base(long long nbr, char *base, int *count, int fd)
{
	if (nbr < 0)
	{
		nbr *= -1;
		ft_putchar_printf('-', fd, count);
	}
	if ((unsigned long long)nbr < ft_strlen(base))
		ft_putchar_printf(base[nbr], fd, count);
	else
	{
		ft_putnbr_base((unsigned long long)nbr / ft_strlen(base),
			base, count, fd);
		ft_putnbr_base((unsigned long long)nbr % ft_strlen(base),
			base, count, fd);
	}
}

static void	ft_putnbr_ubase(unsigned long long nbr,
		char *base, int *count, int fd)
{
	ft_putstr_printf("0x", fd, count);
	if ((unsigned long long) nbr < ft_strlen(base))
		ft_putchar_printf(base[nbr], fd, count);
	else
	{
		ft_putnbr_ubase((unsigned long long) nbr / ft_strlen(base),
			base, count, fd);
		ft_putnbr_ubase((unsigned long long) nbr % ft_strlen(base),
			base, count, fd);
	}
}

static void	fill(int fd, const char *str, va_list args, int *count)
{
	if (str[count[1]] == '%')
		ft_putchar_printf('%', fd, count);
	if (str[count[1]] == 'c')
		ft_putchar_printf(va_arg(args, int), fd, count);
	else if (str[count[1]] == 's')
		ft_putstr_printf(va_arg(args, char *), fd, count);
	else if (str[count[1]] == 'p')
		ft_putnbr_ubase(va_arg(args, unsigned long long),
			"0123456789abcdef", count, fd);
	else if (str[count[1]] == 'i' || str[count[1]] == 'd')
		ft_putnbr_base(va_arg(args, int), "0123456789", count, fd);
	else if (str[count[1]] == 'u')
		ft_putnbr_base(va_arg(args, unsigned int), "0123456789", count, fd);
	else if (str[count[1]] == 'x')
		ft_putnbr_base(va_arg(args, unsigned int),
			"0123456789abcdef", count, fd);
	else if (str[count[1]] == 'X')
		ft_putnbr_base(va_arg(args, unsigned int),
			"0123456789ABCDEF", count, fd);
}

int	ft_fprintf(int fd, const char *str, ...)
{
	va_list	args;
	int		count[2];

	count[1] = -1;
	*count = 0;
	va_start(args, str);
	while (str[++count[1]])
	{
		if (str[count[1]] != '%')
			ft_putchar_printf(str[count[1]], fd, count);
		else if (str[count[1]++ + 1])
			fill(fd, str, args, count);
	}
	va_end(args);
	return (*count);
}
