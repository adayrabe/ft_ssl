/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   make_stack.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/14 14:38:04 by adayrabe          #+#    #+#             */
/*   Updated: 2018/09/14 14:38:09 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_md5_helper_functions.h"

static void		push(t_md5_stack **head, char *name,
	t_word			*(*f)(t_word *word))
{
	t_md5_stack *temp;

	temp = (t_md5_stack *)malloc(sizeof(t_md5_stack));
	temp->f = f;
	temp->name = ft_strdup(name);
	temp->next = *head;
	*head = temp;
}

t_md5_stack		*md5_make_stack(void)
{
	t_md5_stack *head;

	head = NULL;
	push(&head, NULL, NULL);
	push(&head, "md5", ssl_md5);
	push(&head, "sha224", ssl_sha224);
	push(&head, "sha256", ssl_sha256);
	push(&head, "sha384", ssl_sha384);
	push(&head, "sha512", ssl_sha512);
	return (head);
}