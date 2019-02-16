#include "ssl_des_helper_functions.h"
#include "ssl_md5_helper_functions.h"

static int		print_error(t_des_stack **head_des, t_md5_stack **head_md5, char *name)
{
	t_md5_stack *temp_md5;
	t_des_stack *temp_des;

	ft_printf("ft_ssl: Error: '%s' is an invalid command.\n\nStandart \
commands:\n\nMessage Digest commands:\n", name);
	temp_md5 = *head_md5;
	while (temp_md5->name != NULL)
	{
		ft_printf("%s\n", temp_md5->name);
		temp_md5 = temp_md5->next;
	}
	md5_free_stack(head_md5);
	ft_printf("\nCipher commands:\n\n");
	temp_des = (*head_des);
	while (temp_des->name)
	{
		ft_printf("%s\n", temp_des->name);
		temp_des = temp_des->next;
	}
	des_free_stack(head_des);
	// while ((*head)->name != NULL)
	// {
	// 	temp = (*head)->next;
	// 	ft_strdel(&((*head)->name));
	// 	free(*head);
	// 	*head = temp;
	// }
	// free(*head);
	return (0);
}

void	des_start_processing(int ac, char **av, char read_from_fd,
	t_md5_stack **head_md5)
{
	t_des_stack *head_des;
	t_des_stack *temp_des;

	head_des = des_make_stack();
	temp_des = head_des;
	while (temp_des->name != NULL && ft_strcmp(av[0], temp_des->name))
		temp_des = temp_des->next;
	if (temp_des->name == NULL && !(print_error(&head_des, head_md5, av[0])) && !read_from_fd)
		exit(0);
	if (temp_des->name == NULL)
		return ;
	md5_free_stack(head_md5);
	ac = 0;
}