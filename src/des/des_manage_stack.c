#include "ssl_des_helper_functions.h"

static void		push(t_des_stack **head, char *name,
	t_word			*(*f)(t_word *word))
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
	return (head);
}
