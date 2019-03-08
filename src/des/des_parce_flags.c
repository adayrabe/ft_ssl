/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_parce_flags.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/07 12:51:05 by adayrabe          #+#    #+#             */
/*   Updated: 2019/03/07 12:51:07 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_des_helper_functions.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static void				get_fd(t_des_flags *flags, char **av, int ac, int *i)
{
	char c;

	c = av[*i][1];
	(*i)++;
	if (*i == ac)
		print_flag_error(flags, 1);
	if (c == 'i')
	{
		flags->input_fd = open(av[*i], O_RDONLY, 0644);
		if (flags->input_fd < 0 || read(flags->input_fd, 0, 0) < 0)
		{
			ft_printf("%s: %s\n", av[*i], strerror(errno));
			close(flags->input_fd);
			exit(0);
		}
	}
	else
		flags->output_fd = open(av[*i], O_WRONLY | O_CREAT | O_TRUNC, 0644);
}

static unsigned long	make_num(char *str, char *error)
{
	unsigned int	j;
	unsigned long	num;

	j = -1;
	num = 0;
	while (++j < 16 && !(*error))
	{
		if (j >= ft_strlen(str))
			num = num * 16;
		else if (str[j] >= '0' && str[j] <= '9')
			num = num * 16 + str[j] - '0';
		else if (str[j] >= 'A' && str[j] <= 'F')
			num = num * 16 + str[j] - 'A' + 10;
		else if (str[j] >= 'a' && str[j] <= 'f')
			num = num * 16 + str[j] - 'a' + 10;
		else
		{
			*error = 1;
			return (0);
		}
	}
	if (ft_strlen(str) > 16)
		*error = 2;
	return (num);
}

static void				get_number(t_des_flags *flags, char **av, int ac,
	int *i)
{
	char			c;
	unsigned long	num;
	char			error;

	c = av[*i][1];
	(*i)++;
	(*i == ac) ? print_flag_error(flags, 3) : 0;
	error = 0;
	num = make_num(av[*i], &error);
	if (c == 'k' && ++flags->has_key)
		(error == 1) ? print_flag_error(flags, 4) : (flags->key1 = num);
	if (c == 'k' && ft_strnequ("des3", flags->func_name, 4))
	{
		(ft_strlen(av[*i]) > 16) ? (flags->key2 = make_num(&av[*i][16], &error))
		: (flags->key2 = make_num(NULL, &error));
		(error == 1) ? print_flag_error(flags, 4) : 0;
		(ft_strlen(av[*i]) > 32) ? (flags->key3 = make_num(&av[*i][32], &error))
		: (flags->key3 = make_num(NULL, &error));
		(error == 1) ? print_flag_error(flags, 4) : 0;
	}
	(c == 's' && error == 2) ? print_flag_error(flags, 14) : 0;
	if (c == 's' && ++flags->has_salt)
		(error == 1) ? print_flag_error(flags, 5) : (flags->salt = num);
	if (c == 'v' && ++flags->has_vector)
		(error == 1) ? print_flag_error(flags, 6) : (flags->vector = num);
}

bool					des_parce_flags(t_des_flags *flags, char **av, int ac,
	int *i)
{
	if (ft_strlen(av[*i]) != 2 || av[*i][0] != '-')
		return (print_flag_error(flags, 0));
	if (av[*i][1] == 'd')
		flags->encrypt = 0;
	else if (av[*i][1] == 'e')
		flags->encrypt = 1;
	else if (av[*i][1] == 'i' || av[*i][1] == 'o')
		get_fd(flags, av, ac, i);
	else if (ft_strequ(flags->func_name, "base64"))
		print_flag_error(flags, 0);
	else if (av[*i][1] == 'a')
		flags->base64 = 1;
	else if (av[*i][1] == 'k' || av[*i][1] == 's' || av[*i][1] == 'v')
		get_number(flags, av, ac, i);
	else if (av[*i][1] == 'p')
	{
		(*i)++;
		(*i == ac) ? print_flag_error(flags, 7) : 0;
		flags->pass = ft_strdup(av[*i]);
	}
	else
		return (print_flag_error(flags, 0));
	return (1);
}
