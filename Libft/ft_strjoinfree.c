/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoinfree.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: egeorgel <egeorgel@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/02/04 22:20:33 by egeorgel          #+#    #+#             */
/*   Updated: 2023/04/21 20:15:43 by egeorgel         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void	ft_strjoin_free(char *s1, char *s2, bool free_s1, bool free_s2)
{
	if (free_s1 && s1)
		free(s1);
	if (free_s2 && s2)
		free(s2);
}

static char	*join(char *s1, char *s2)
{
	char	*str;
	size_t	i;
	size_t	j;

	str = (char *)malloc(ft_strlen(s1) + ft_strlen(s2) + 1);
	if (!str)
		return (NULL);
	i = -1;
	j = 0;
	while (s1[++i])
		str[j++] = s1[i];
	i = -1;
	while (s2[++i])
		str[j++] = s2[i];
	str[j] = 0;
	return (str);
}

char	*ft_strjoinfree(char *s1, char *s2, bool free_s1, bool free_s2)
{
	char	*str;

	if (!s1 && !s2)
		return (NULL);
	if (!s1 && s2)
		str = ft_strdup(s2);
	else if (s1 && !s2)
		str = ft_strdup(s1);
	else
		str = join(s1, s2);
	if (!str)
		return (NULL);
	ft_strjoin_free(s1, s2, free_s1, free_s2);
	return (str);
}
