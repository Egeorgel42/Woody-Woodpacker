/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: egeorgel <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/09 11:00:03 by egeorgel          #+#    #+#             */
/*   Updated: 2022/11/16 17:43:26 by egeorgel         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include "libft.h"

size_t	ft_strlcpy(char *dst, const char *src, size_t dst_size)
{
	unsigned int	src_size;
	unsigned int	i;

	i = 0;
	src_size = ft_strlen(src);
	if (src_size < dst_size)
	{
		while (i < src_size)
		{
			dst[i] = src[i];
			i++;
		}
		dst[i] = '\0';
	}
	else if (dst_size > 0)
	{
		while (i < dst_size - 1)
		{
			dst[i] = src[i];
			i++;
		}
		dst[i] = '\0';
	}
	return (src_size);
}
