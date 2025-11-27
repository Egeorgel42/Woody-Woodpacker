/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memset.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: egeorgel <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/07 13:50:45 by egeorgel          #+#    #+#             */
/*   Updated: 2022/11/16 16:25:36 by egeorgel         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "libft.h"

void	*ft_memset(void *s, int c, size_t len)
{
	unsigned long	i;
	unsigned char	*dst;

	i = 0;
	dst = s;
	while (i < len)
	{
		*dst = (unsigned char) c;
		dst++;
		i++;
	}
	return (s);
}
