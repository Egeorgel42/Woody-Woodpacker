/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line_utils.c                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: egeorgel <egeorgel@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/26 20:07:47 by egeorgel          #+#    #+#             */
/*   Updated: 2023/02/10 02:09:07 by egeorgel         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "get_next_line.h"
#include <stdlib.h>

static char	*str_rem_fill(char *str, char *s)
{
	int	i;
	int	j;

	i = 0;
	j = 0;
	while (str[i] && str[i] != '\n')
		i++;
	if (str[i] == '\n')
		i++;
	while (str[i])
	{
		s[j] = str[i];
		i++;
		j++;
	}
	s[j] = '\0';
	return (s);
}

char	*str_rem(char *str)
{
	char	*s;
	int		i;
	int		j;

	i = 0;
	j = 0;
	while (str[i] && str[i] != '\n')
		i++;
	if (str[i] == '\n')
		i++;
	while (str[i++])
		j++;
	if (j == 0)
	{
		free(str);
		return (0);
	}
	s = malloc(j + 1);
	if (!s)
		return (0);
	s = str_rem_fill(str, s);
	free(str);
	return (s);
}

char	*get_read_fill(char *str, char *s, int read_res)
{
	if (read_res == 0)
	{
		free(s);
		return (str);
	}
	else if (read_res == -1)
	{
		free(s);
		free(str);
		return (0);
	}
	s[read_res] = '\0';
	str = strjoin(str, s);
	free(s);
	return (str);
}
