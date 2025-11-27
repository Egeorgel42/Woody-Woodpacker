/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_calloc.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: egeorgel <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/11 16:43:47 by egeorgel          #+#    #+#             */
/*   Updated: 2022/11/22 17:08:45 by egeorgel         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "libft.h"

void	*ft_calloc(size_t count, size_t size)
{
	void	*m;

	if (count >= SIZE_MAX || size >= SIZE_MAX)
		return (0);
	m = (void *)malloc(count * size);
	if (!m)
		return (0);
	ft_bzero(m, count * size);
	return (m);
}
