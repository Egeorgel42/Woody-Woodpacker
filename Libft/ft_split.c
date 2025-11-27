/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_split.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: egeorgel <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/13 13:45:45 by egeorgel          #+#    #+#             */
/*   Updated: 2022/11/16 17:37:37 by egeorgel         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "libft.h"

static int	word_number(char const *s, char c)
{
	int	i;
	int	count;

	i = 0;
	count = 0;
	while (s[i])
	{
		while (s[i] && s[i] == c)
			i++;
		if (s[i] && s[i] != c)
			count++;
		while (s[i] && s[i] != c)
			i++;
	}
	return (count);
}

static	int	word_size(char const *s, char c, int start)
{
	int	i;

	i = 0;
	while (s[start + i] && s[start + i] != c)
		i++;
	return (i);
}

static char	*fill(char *tab, char *s, int i, char c)
{
	int	z;

	z = 0;
	while (s[i] && s[i] != c)
	{
		tab[z] = s[i];
		i++;
		z++;
	}
	tab[z] = '\0';
	return (tab);
}

char	**ft_split(char const *s, char c)
{
	int		i;
	int		j;
	char	**tab;

	if (!s)
		return (0);
	i = 0;
	j = -1;
	tab = malloc(sizeof(char *) * (word_number(s, c) + 1));
	if (!tab)
		return (0);
	while (++j < word_number(s, c) && s[i])
	{
		while (s[i] && s[i] == c)
			i++;
		tab[j] = malloc(sizeof(char) * (word_size(s, c, i) + 1));
		if (!tab[j])
			return (0);
		tab[j] = fill(tab[j], (char *)s, i, c);
		i += word_size(s, c, i);
	}
	tab[j] = NULL;
	return (tab);
}
