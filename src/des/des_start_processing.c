#include "ssl_des_helper_functions.h"
#include "ssl_md_helper_functions.h"
#include <unistd.h>
#include <fcntl.h>

static int		print_error(t_des_stack **head_des, t_md_stack **head_md,
	char *name)
{
	t_md_stack	*temp_md;
	t_des_stack	*temp_des;

	ft_printf("ft_ssl: Error: '%s' is an invalid command.\n\nStandart \
commands:\n\nMessage Digest commands:\n", name);
	temp_md = *head_md;
	while (temp_md->name != NULL)
	{
		ft_printf("%s\n", temp_md->name);
		temp_md = temp_md->next;
	}
	md_free_stack(head_md);
	ft_printf("\nCipher commands:\n\n");
	temp_des = (*head_des);
	while (temp_des->name)
	{
		ft_printf("%s\n", temp_des->name);
		temp_des = temp_des->next;
	}
	des_free_stack(head_des);
	return (0);
}

static t_des_flags	init_flags(char read_from_fd, char *func_name, 
		void	(*f)(t_word *ciphertext, t_des_flags *flags,
					size_t i, t_word *word))
{
	t_des_flags res;

	res.base64 = 0;
	res.encrypt = 1;
	res.input_fd = 0;
	res.output_fd = 0;
	res.key1 = 0;
	res.key2 = 0;
	res.key3 = 0;
	res.key4 = 0;
	res.has_key = 0;
	res.pass = NULL;
	res.salt = 0;
	res.has_salt = 0;
	res.vector = 0;
	res.has_vector = 0;
	res.read_from_fd = read_from_fd;
	res.func_name = ft_strdup(func_name);
	res.function = f;
	res.prefix = ft_str_unsigned_new(0);
	return (res);
}

static void			des_start_function(t_des_flags flags)
{
	unsigned char	*word;
	size_t			length;
	t_word			*res;
	size_t			i;

	word = NULL;
	length = read_from_fd(flags.input_fd, &word);
	res = make_word(word, length);
	res = ssl_des(res, flags);
	ft_str_unsigned_del(&word);
	i = -1;
	if (flags.encrypt || flags.has_salt)
		while (++i < 16)
			ft_putchar_fd(flags.prefix[i], flags.output_fd);
	i = -1;
	while (++i < res->length)
	{
		ft_putchar_fd(res->word[i], flags.output_fd);
		((ft_strequ("base64", flags.func_name) || flags.base64) &&
			i % 64 == 63) ? ft_putchar_fd('\n', flags.output_fd) : 0;
	}
	(i % 64 != 0 && i && (ft_strequ("base64", flags.func_name) ||
		flags.base64)) ? ft_putchar_fd('\n', flags.output_fd) : 0;
	ft_str_unsigned_del(&(res->word));
	free(res);
}

void				des_start_processing(int ac, char **av, char read_from_fd,
	t_md_stack **head_md)
{
	t_des_stack	*head_des;
	t_des_stack	*temp_des;
	t_des_flags	flags;

	head_des = des_make_stack();
	temp_des = head_des;
	while (temp_des->name != NULL && ft_strcmp(av[0], temp_des->name))
		temp_des = temp_des->next;
	if (temp_des->name == NULL && !(print_error(&head_des, head_md, av[0])) && !read_from_fd)
		exit(0);
	if (temp_des->name == NULL)
		return ;
	md_free_stack(head_md);
	flags = init_flags(read_from_fd, temp_des->name, temp_des->f);
	des_free_stack(&head_des);
	if (!des_parce_arguments(&flags, av, ac))
		return ;
	ft_printf(" base64: %d\n encrypt: %d\n input_fd: %d\n output_fd: %d\n key1: %lx\n key2: %lx\n key3: %lx\n key4: %lx\n has_key: %d\n pass: %s\n salt: %lx\n has_salt: %d\n vector: %lx\n has_vector: %d\n func_name: %s\n",
		flags.base64, flags.encrypt, flags.input_fd,
		flags.output_fd, flags.key1, flags.key2, flags.key3, flags.key4, flags.has_key, flags.pass, flags.salt, flags.has_salt,
		flags.vector, flags.has_vector, flags.func_name);
	des_start_function(flags);
	ft_strdel(&(flags.pass));
	ft_strdel(&(flags.func_name));
	ft_str_unsigned_del(&(flags.prefix));
	(flags.input_fd) ? close(flags.input_fd) : 0;
	(flags.output_fd) ? close(flags.output_fd) : 0;
}
