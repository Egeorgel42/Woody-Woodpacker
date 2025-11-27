/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstlast.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: egeorgel <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/11/17 15:32:46 by egeorgel          #+#    #+#             */
/*   Updated: 2022/11/19 15:03:24 by egeorgel         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list	*ft_lstlast(t_list *lst)
{
	t_list	*buflst;

	if (!lst)
		return (NULL);
	while (lst)
	{
		buflst = lst;
		lst = lst->next;
	}
	return (buflst);
}
