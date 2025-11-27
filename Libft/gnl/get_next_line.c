/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: egeorgel <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/27 18:40:47 by egeorgel          #+#    #+#             */
/*   Updated: 2022/12/02 19:28:56 by egeorgel         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "get_next_line.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

char	*strjoin(char *str, char *s)
{
	char	*res_s;
	int		i;
	int		j;

	i = 0;
	j = 0;
	if (!str)
		return (ft_strdup(s));
	while (str[i])
		i++;
	while (s[j])
		j++;
	res_s = malloc(i + j + 1);
	if (!res_s)
		return (0);
	i = -1;
	j = -1;
	while (str[++i])
		res_s[i] = str[i];
	while (s[++j])
		res_s[j + i] = s[j];
	res_s[j + i] = '\0';
	free(str);
	return (res_s);
}

static int	is_n(char *str)
{
	int	i;
	int	j;

	i = 0;
	j = 0;
	if (!str)
		return (0);
	while (str[i] && str[i] != '\n')
		i++;
	if (str[i] == '\n')
		j++;
	if (j)
		return (1);
	return (0);
}

static char	*get_read(int fd, char *str)
{
	int		read_res;
	char	*s;

	read_res = BUFFER_SIZE;
	while (read_res == BUFFER_SIZE && is_n(str) == 0)
	{
		s = malloc(BUFFER_SIZE + 1);
		if (!s)
			return (0);
		read_res = read(fd, s, BUFFER_SIZE);
		str = get_read_fill(str, s, read_res);
		if (!str)
			return (0);
	}
	return (str);
}

static char	*sep_str(char *str)
{
	char	*s;
	int		i;

	i = 0;
	while (str[i] && str[i] != '\n')
		i++;
	if (str[i] == '\n')
		i++;
	s = malloc(i + 1);
	if (!s)
		return (0);
	i = 0;
	while (str[i] && str[i] != '\n')
	{
		s[i] = str[i];
		i++;
	}
	if (str[i] == '\n')
	{
		s[i] = '\n';
		i++;
	}
	s[i] = '\0';
	return (s);
}

char	*get_next_line(int fd)
{
	static char	*str;
	char		*s;

	str = get_read(fd, str);
	if (!str)
		return (0);
	s = sep_str(str);
	if (!s)
	{
		free(str);
		return (0);
	}
	str = str_rem(str);
	if (s[0] == '\0')
	{
		free(s);
		return (0);
	}
	return (s);
}
