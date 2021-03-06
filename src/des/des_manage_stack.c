/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_manage_stack.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/07 12:42:33 by adayrabe          #+#    #+#             */
/*   Updated: 2019/03/07 12:42:35 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_des_helper_functions.h"

static void		push(t_des_stack **head, char *name,
	void (*f)(t_word *ciphertext, t_des_flags *flags,
						size_t i, t_word *word))
{
	t_des_stack *temp;

	temp = (t_des_stack *)malloc(sizeof(t_des_stack));
	temp->f = f;
	temp->name = ft_strdup(name);
	temp->next = *head;
	*head = temp;
}

void			des_free_stack(t_des_stack **head)
{
	t_des_stack *temp;

	while (*head)
	{
		temp = (*head)->next;
		ft_strdel(&(*head)->name);
		free(*head);
		*head = temp;
	}
}

t_des_stack		*des_make_stack(void)
{
	t_des_stack *head;

	head = NULL;
	push(&head, NULL, NULL);
	push(&head, "des3-ofb", ssl_des3_ofb);
	push(&head, "des3-pcbc", ssl_des3_pcbc);
	push(&head, "des3-cbc", ssl_des3_cbc);
	push(&head, "des3-ecb", ssl_des3_ecb);
	push(&head, "des3", ssl_des3_cbc);
	push(&head, "des-cfb", ssl_des_cfb);
	push(&head, "des-ofb", ssl_des_ofb);
	push(&head, "des-pcbc", ssl_des_pcbc);
	push(&head, "des-cbc", ssl_des_cbc);
	push(&head, "des-ecb", ssl_des_ecb);
	push(&head, "des", ssl_des_cbc);
	push(&head, "base64", base64);
	return (head);
}
