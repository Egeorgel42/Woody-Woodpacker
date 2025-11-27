/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: egeorgel <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/12 14:05:37 by egeorgel          #+#    #+#             */
/*   Updated: 2022/11/16 18:31:31 by egeorgel         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "libft.h"

char	*ft_strtrim(char const *s1, char const *set)
{
	int		i;
	int		size;
	int		start;
	int		end;
	char	*str;

	if (!s1)
		return (0);
	i = -1;
	start = 0;
	size = ft_strlen(s1);
	while (s1[start] && ft_strchr(set, s1[start]))
		start++;
	end = size;
	while (end > start && ft_strchr(set, s1[end - 1]))
		end--;
	str = malloc(sizeof(char) * (end - start + 1));
	if (!str)
		return (0);
	while (start + (++i) < end)
		str[i] = s1[start + i];
	str[i] = '\0';
	return (str);
}
