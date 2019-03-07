#include "ssl_des_helper_functions.h"
#include <unistd.h>
#include <fcntl.h>

static void			add_salt(t_des_flags *flags)
{
	unsigned char	temp[9];
	int		i;
	int		len;
	int		temp_fd;
	
	if (!flags->encrypt && !flags->has_key)
	{
		read(flags->input_fd, temp, 8);
		temp[8] = '\0';
		if (!ft_strequ((char *)temp, "Salted__"))
			print_flag_error(flags, 10);
	}
	if (!flags->has_salt)
	{
		if (flags->encrypt)
		{
			temp_fd = open("/dev/random", O_RDONLY);
			read(temp_fd, temp, 8);
			i = -1;
			while (++i < 8)
				flags->salt = flags->salt * 256 + temp[i];
			close(temp_fd);
		}
		else
		{
			len = read(flags->input_fd, temp, 8);
			(len < 8) ? print_flag_error(flags, 12) : 0;
			i = -1;
			while (++i < 8)
				flags->salt = flags->salt * 256 + temp[i];
		}
	}
}

t_word *make_keys(unsigned char *pass, unsigned long salt, unsigned long len)
{
	unsigned char	*temp;
	unsigned int	i;
	t_word			*res;

	temp = ft_str_unsigned_new(len + 8);
	i = -1;
	while (++i < len)
		temp[i] = pass[i];
	while (++i <= len + 8)
	{
		temp[len + 8 +  len - i] = salt % 256;
		salt /= 256;
	}
	res = ssl_md5(make_word(temp, len + 8));
	return (res);
}

void add_prefix(t_des_flags *flags, unsigned long salt)
{
	unsigned char *temp;
	int i;

	ft_str_unsigned_concat(&(flags->prefix), (unsigned char *)"Salted__", 0, 8);
	temp = ft_str_unsigned_new(8);
	i = -1;
	while (++i < 8)
	{
		temp[7 - i] = salt % 256;
		salt /= 256;
	}
	ft_str_unsigned_concat(&(flags->prefix), temp, 8, 8);
	ft_str_unsigned_del(&temp);
}

void	add_keys(char *pass, unsigned long salt, t_des_flags *flags)
{
	unsigned char	*temp;
	unsigned int	i;
	t_word			*res;
	unsigned char	*temp2;

	res = make_keys((unsigned char *)pass, salt, ft_strlen(pass));
	temp2 = res->word;
	temp = NULL;
	ft_str_unsigned_concat(&temp, res->word, 0, 16);
	free(res);
	ft_str_unsigned_concat(&temp, (unsigned char *)pass, 16, ft_strlen(pass));
	res = make_keys(temp, salt, ft_strlen(pass) + 16);
	i = -1;
	while (++i < 8)
	{
		flags->key1 = flags->key1 * 256 + temp2[i];
		flags->key2 = flags->key2 * 256 + temp2[res->length - 8 + i];
		flags->key3 = flags->key3 * 256 + res->word[i];
		flags->key4 = flags->key4 * 256 + res->word[res->length - 8 + i];
	}
	ft_str_unsigned_del(&temp2);
	ft_str_unsigned_del(&(res->word));
	add_prefix(flags, salt);
	free(res);
}

bool					des_parce_arguments(t_des_flags *flags, char **av,
	int ac)
{
	int i;

	i = 0;
	while (++i < ac)
		if (!des_parce_flags(flags, av, ac, &i))
			return (0);
	if (!flags->has_key && !ft_strequ("base64", flags->func_name))
		add_salt(flags);
	(flags->has_key && !flags->has_vector && !flags->pass &&
	!ft_strequ("base64", flags->func_name) && 
	!ft_strequ(flags->func_name, "des-ecb") &&
	!ft_strequ("des3-ecb", flags->func_name)) ? print_flag_error(flags, 9) : 0;
	if (!flags->has_key && !flags->pass &&
		!ft_strequ("base64", flags->func_name))
	{
		flags->pass = ft_strdup(getpass("enter des encryption password:"));
		(flags->encrypt && !ft_strequ(getpass("Verifying - enter des\
 encryption password:"), flags->pass)) ? print_flag_error(flags, 8) : 0;
	}
	if (!flags->has_key && !ft_strequ("base64", flags->func_name))
		(add_keys(flags->pass, flags->salt, flags));
	if (!flags->has_vector && !ft_strequ("base64", flags->func_name))
		(ft_strnequ("des3", flags->func_name, 4)) ?
			(flags->vector = flags->key4) : (flags->vector = flags->key2);
	return (1);
}