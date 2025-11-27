/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: egeorgel <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/20 14:34:25 by egeorgel          #+#    #+#             */
/*   Updated: 2022/12/01 21:04:39 by egeorgel         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <unistd.h>
#include "libft.h"
#include "ft_printf.h"

static void	ft_putnbr_base(long long nbr, char *base, int sign, int *count)
{
	if (nbr < 0 && sign == 3)
		sign = 1;
	else if (sign == 3)
	{
		ft_putchar_printf(' ', 1, count);
		sign = 0;
	}
	if (nbr < 0 && sign == 0)
		nbr *= -1;
	else if (nbr < 0 && sign == 1)
	{
		nbr *= -1;
		ft_putchar_printf('-', 1, count);
	}
	if ((unsigned long long)nbr < ft_strlen(base))
		ft_putchar_printf(base[nbr], 1, count);
	else
	{
		ft_putnbr_base((unsigned long long)nbr / ft_strlen(base),
			base, sign, count);
		ft_putnbr_base((unsigned long long)nbr % ft_strlen(base),
			base, sign, count);
	}
}

static void	ft_putnbr_ubase(unsigned long long nbr,
		char *base, int sign, int *count)
{
	if (sign == 2)
	{
		ft_putstr_printf("0x", 1, count);
		sign = 0;
	}
	if ((unsigned long long) nbr < ft_strlen(base))
		ft_putchar_printf(base[nbr], 1, count);
	else
	{
		ft_putnbr_base((unsigned long long) nbr / ft_strlen(base),
			base, sign, count);
		ft_putnbr_base((unsigned long long) nbr % ft_strlen(base),
			base, sign, count);
	}
}

static int	fill(const char *str, va_list args, int i, int *count)
{
	if (str[i] == '%')
		ft_putchar_printf('%', 1, count);
	if (str[i] == 'c')
		ft_putchar_printf(va_arg(args, int), 1, count);
	else if (str[i] == 's')
		ft_putstr_printf(va_arg(args, char *), 1, count);
	else if (str[i] == 'p')
		ft_putnbr_ubase(va_arg(args, unsigned long long),
			"0123456789abcdef", 2, count);
	else if (str[i] == 'i' || str[i] == 'd')
		ft_putnbr_base(va_arg(args, int), "0123456789", 1, count);
	else if (str[i] == 'u')
		ft_putnbr_base(va_arg(args, unsigned int), "0123456789", 0, count);
	else if (str[i] == 'x')
		ft_putnbr_base(va_arg(args, unsigned int),
			"0123456789abcdef", 0, count);
	else if (str[i] == 'X')
		ft_putnbr_base(va_arg(args, unsigned int),
			"0123456789ABCDEF", 0, count);
	return (i);
}

int	ft_printf(const char *str, ...)
{
	va_list	args;
	int		count[1];
	int		i;

	i = -1;
	*count = 0;
	va_start(args, str);
	while (str[++i])
	{
		if (str[i] != '%')
			ft_putchar_printf(str[i], 1, count);
		else if (str[i++ + 1])
			i = fill(str, args, i, count);
	}
	va_end(args);
	return (*count);
}
