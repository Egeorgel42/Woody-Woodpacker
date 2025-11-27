/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_substr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: egeorgel <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/11 17:34:17 by egeorgel          #+#    #+#             */
/*   Updated: 2022/11/19 17:38:44 by egeorgel         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "libft.h"

char	*ft_substr(char const *s, unsigned int start, size_t len)
{
	char			*str;
	unsigned int	size;
	unsigned int	i;

	if (!s)
		return (0);
	i = 0;
	size = ft_strlen(s);
	if (start >= size)
		str = malloc(sizeof(char));
	else if (size > len)
		str = malloc(sizeof(char) * (len + 1));
	else
		str = malloc(sizeof(char) * (size + 1));
	if (!str)
		return (0);
	while (i < len && start + i < size)
	{
		str[i] = s[start + i];
		i++;
	}
	str[i] = '\0';
	return (str);
}
