/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf_utils.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: egeorgel <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/25 16:16:18 by egeorgel          #+#    #+#             */
/*   Updated: 2022/12/01 21:03:23 by egeorgel         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <unistd.h>
#include "ft_printf.h"

void	ft_putstr_printf(char *s, int fd, int *count)
{
	int	i;

	i = 0;
	if (!s)
	{
		write (fd, "(null)", 6);
		*count += 6;
		return ;
	}
	while (s[i])
	{
		write (fd, &s[i], 1);
		i++;
		(*count)++;
	}
}

void	ft_putchar_printf(char c, int fd, int *count)
{
	write(fd, &c, 1);
	(*count)++;
}
