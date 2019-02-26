#include "ssl_des_helper_functions.h"
#include <unistd.h>

static void			add_salt(t_des_flags *flags)
{
	char	temp[9];
	int		i;

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

static unsigned long	make_key(char *pass, unsigned long salt)
{
	unsigned char	*temp;
	unsigned int	i;
	t_word			*res;
	unsigned long	key;

	temp = ft_str_unsigned_new(ft_strlen(pass) + 8);
	i = -1;
	while (++i < ft_strlen(pass))
		temp[i] = pass[i];
	while (++i <= ft_strlen(pass) + 8)
	{
		temp[ft_strlen(pass) + 8 + ft_strlen(pass)- i] = salt % 256;
		salt /= 256;
	}
	res = ssl_md5(make_word(temp, ft_strlen(pass) + 8));
	i = -1;
	key = 0;
	while (++i < 8)
		key = key * 256 + res->word[i];
	ft_str_unsigned_del(&(res->word));
	free(res);
	return (key);
}

static unsigned long	make_vector(char *pass, unsigned long salt)
{
	unsigned char	*temp;
	unsigned int	i;
	t_word			*res;
	unsigned long	key;

	temp = ft_str_unsigned_new(ft_strlen(pass) + 8);
	i = -1;
	while (++i < ft_strlen(pass))
		temp[i] = pass[i];
	while (++i <= ft_strlen(pass) + 8)
	{
		temp[ft_strlen(pass) + 8 + ft_strlen(pass)- i] = salt % 256;
		salt /= 256;
	}
	res = ssl_md5(make_word(temp, ft_strlen(pass) + 8));
	i = -1;
	key = 0;
	while (++i < 8)
		key = key * 256 + res->word[res->length - 8 + i];
	ft_str_unsigned_del(&(res->word));
	free(res);
	return (key);
}

void					des_parce_arguments(t_des_flags *flags, char **av, int ac)
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
	(!flags->has_key) ? (flags->key = make_key(flags->pass, flags->salt)) : 0;
	if (!flags->has_vector)
		flags->vector = make_vector(flags->pass, flags->salt);
}