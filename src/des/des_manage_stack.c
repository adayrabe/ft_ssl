#include "ssl_des_helper_functions.h"

static void		push(t_des_stack **head, char *name,
	unsigned long	(*f)(t_word *ciphertext, unsigned long prev,
			unsigned long curr, unsigned long key))
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
	push(&head, "des-ecb", ssl_des_ecb);
	push(&head, "des-cbc", ssl_des_cbc);
	push(&head, "des", ssl_des_cbc);
	push(&head, "des-cfb", ssl_des_cfb);
	return (head);
}
