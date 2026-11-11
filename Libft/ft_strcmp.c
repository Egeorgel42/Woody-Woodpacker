/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strcmp.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: egeorgel <egeorgel@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/02/09 21:43:49 by egeorgel          #+#    #+#             */
/*   Updated: 2023/07/21 23:57:05 by egeorgel         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int	ft_strcmp(const char *str, const char *cmp)
{
	int	i = 0;

	if (!str || !cmp)
		return (false);
	int size_delta = ft_strlen(str) - ft_strlen(cmp);
	if (size_delta != 0)
		return size_delta;
	while (str[i] && str[i] == cmp[i])
	{
		i++;
	}
	return (str[i] - cmp[i]);
}
