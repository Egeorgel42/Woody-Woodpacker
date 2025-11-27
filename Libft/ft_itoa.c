/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: egeorgel <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/14 15:50:29 by egeorgel          #+#    #+#             */
/*   Updated: 2022/11/16 16:00:30 by egeorgel         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "libft.h"

static	long	power_ten(long nbr, long power)
{
	while (power > 1)
	{
		nbr *= 10;
		power--;
	}
	return (nbr);
}

static	long	int_size(long n)
{
	int	i;

	i = 0;
	while (n > 9)
	{
		n = n / 10;
		i++;
	}
	return (i + 1);
}

char	*ft_itoa(int n)
{
	int		i;
	long	nbr;
	long	int_s;
	char	*str;
	int		sign;

	i = -1;
	sign = 0;
	nbr = (long)n;
	if (nbr < 0)
	{
		nbr *= -1;
		sign = 1;
	}
	int_s = int_size(nbr);
	str = malloc(sizeof(char) * (int_s + sign + 1));
	if (!str)
		return (0);
	if (sign == 1)
		str[++i] = '-';
	while (++i < int_s + sign)
		str[i] = nbr / power_ten(1, int_s - i + sign) % 10 + '0';
	str[i] = '\0';
	return (str);
}
