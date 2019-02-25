#include "ssl_des_helper_functions.h"
#include "ssl_md5_helper_functions.h"
#include <unistd.h>

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
	return (0);
}

void add_salt(t_des_flags *flags)
{
	char temp[9];
	int i;

	if (!flags->encrypt)
	{
		read(flags->input_fd, temp, 8);
		temp[8] = '\0';
		ft_printf("%s\n", temp);
		if (!ft_strequ(temp, "Salted__"))
			print_flag_error(flags, 10);
	}
	if (!flags->has_salt)
	{
		if (flags->encrypt)
			(flags->salt = random());
		else
		{
			read(flags->input_fd, temp, 8);
			i = -1;
			while (++i < 8)
				flags->salt = flags->salt * 16 + temp[i];
		}
	}
}

void		des_parce_arguments(t_des_flags *flags, char **av, int ac)
{
	int i;

	i = 0;
	while (++i < ac)
		if (av[i][0] == '-')
			des_parce_flags(flags, av, ac, &i);
		else if (flags->read_from_fd == 0)
			exit(0);
		else
			return ;
	add_salt(flags);
	(flags->has_key && !flags->has_vector && !flags->pass &&
	(ft_strequ(flags->func_name, "des") ||
	ft_strequ(flags->func_name, "des-cbc"))) ? print_flag_error(flags, 9) : 0;
	if (!flags->has_key && !flags->pass)
	{
		flags->pass = ft_strdup(getpass("enter des-ecb encryption password:"));
		(!ft_strequ(getpass("Verifying - enter des-ecb encryption \
password:"), flags->pass)) ? print_flag_error(flags, 8) : 0;
	}
	if (!flags->has_key)
		flags->key = pbkdf(flags->pass, flags->salt, 1000);
	if (!flags->has_vector)
		;
}

t_des_flags init_flags(char read_from_fd, char *func_name, 
	t_word *(*f)(t_word *word))
{
	t_des_flags res;

	res.base64 = 0;
	res.encrypt = 1;
	res.input_fd = 0;
	res.output_fd = 0;
	res.key = 0;
	res.has_key = 0;
	res.pass = NULL;
	res.salt = 0;
	res.has_salt = 0;
	res.vector = 0;
	res.has_vector = 0;
	res.read_from_fd = read_from_fd;
	res.func_name = ft_strdup(func_name);
	res.function = f;
	return (res);
}

void			des_start_processing(int ac, char **av, char read_from_fd,
	t_md5_stack **head_md5)
{
	t_des_stack *head_des;
	t_des_stack *temp_des;
	t_des_flags	flags;

	head_des = des_make_stack();
	temp_des = head_des;
	while (temp_des->name != NULL && ft_strcmp(av[0], temp_des->name))
		temp_des = temp_des->next;
	if (temp_des->name == NULL && !(print_error(&head_des, head_md5, av[0])) && !read_from_fd)
		exit(0);
	if (temp_des->name == NULL)
		return ;
	md5_free_stack(head_md5);
	flags = init_flags(read_from_fd, temp_des->name, temp_des->f);
	des_free_stack(&head_des);
	des_parce_arguments(&flags, av, ac);
	ft_printf(" base64: %d\n encrypt: %d\n input_fd: %d\n output_fd: %d\n key: %lx\n has_key: %d\n pass: %s\n salt: %lx\n has_salt: %d\n vector: %lx\n has_vector: %d\n func_name: %s\n",
		flags.base64, flags.encrypt, flags.input_fd,
		flags.output_fd, flags.key, flags.has_key, flags.pass, flags.salt, flags.has_salt,
		flags.vector, flags.has_vector, flags.func_name);
	ft_strdel(&(flags.pass));
}