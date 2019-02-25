/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md_manage_stack.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/14 14:38:04 by adayrabe          #+#    #+#             */
/*   Updated: 2018/09/14 14:38:09 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_md_helper_functions.h"

static void		push(t_md_stack **head, char *name,
	t_word			*(*f)(t_word *word))
{
	t_md_stack *temp;

	temp = (t_md_stack *)malloc(sizeof(t_md_stack));
	temp->f = f;
	temp->name = ft_strdup(name);
	temp->next = *head;
	*head = temp;
}

void md_free_stack(t_md_stack **head)
{
	t_md_stack *temp;

	while (*head)
	{
		temp = (*head)->next;
		ft_strdel(&(*head)->name);
		free(*head);
		*head = temp;
	}
}

t_md_stack		*md_make_stack(void)
{
	t_md_stack *head;

	head = NULL;
	push(&head, NULL, NULL);
	push(&head, "md5", ssl_md5);
	push(&head, "sha224", ssl_sha224);
	push(&head, "sha256", ssl_sha256);
	push(&head, "sha384", ssl_sha384);
	push(&head, "sha512", ssl_sha512);
	push(&head, "sha1", ssl_sha1);
	return (head);
}
