/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5_parce_flags.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/17 17:47:29 by adayrabe          #+#    #+#             */
/*   Updated: 2018/09/17 17:47:31 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_functions.h"
#include "ssl_md5_helper_functions.h"

t_word	*make_word(unsigned char *word, size_t length)
{
	t_word	*res;

	res = (t_word *)malloc(sizeof(t_word));
	res->word = word;
	res->length = length;
	return (res);
}

static void		print_result(t_word *word)
{
	unsigned long i;

	i = -1;
	while (++i < word->length)
		ft_printf("%.2x", word->word[i]);
}

static void		parce_s_flag(t_md5_flags *flags, char **av, int *i, int *j)
{
	t_word *word;

	if (av[*i][*j + 1])
	{
		(!flags->flag_q && !flags->flag_r) ? ft_printf("%s (\"%s\") = ",
			ft_str_to_upper(flags->name), &av[*i][*j + 1]) : 0;
		word = make_word((unsigned char *)&av[*i][*j + 1],
			ft_strlen(&av[*i][*j + 1]));
		print_result(word = flags->f(word));
		if (!flags->flag_q && flags->flag_r)
			ft_printf(" \"%s\"", &av[*i][*j + 1]);
		*j = *j + (int)ft_strlen(&av[*i][*j + 1]);
	}
	else
	{
		word = make_word((unsigned char *)av[++(*i)], ft_strlen(av[*i]));
		if (!flags->flag_q && !flags->flag_r)
			ft_printf("%s (\"%s\") = ", ft_str_to_upper(flags->name), av[*i]);
	 print_result(word = flags->f(word));
		if (!flags->flag_q && flags->flag_r)
			ft_printf(" \"%s\"", av[*i]);
		(*j) = (int)ft_strlen(av[*i]) - 1;
	}
	free(word);
	ft_printf("\n");
}

void			md5_from_fd(t_md5_flags *flags, int fd, char *name)
{
	unsigned char	*line;
	size_t			length;
	t_word			*word;

	(fd != 0 && !flags->flag_r && !flags->flag_q) ?
			ft_printf("%s (%s) = ", ft_str_to_upper(flags->name), name) : 0;
	if (fd == 0 && (flags->flag_p > 1))
	{
		word = make_word((unsigned char *)"", 0);
		print_result(word = flags->f(word));
		ft_printf("\n");
		free(word);
		return ;
	}
	line = ft_str_unsigned_new(0);
	(length = read_from_fd(fd, &line));
	(fd == 0 && flags->flag_p) ? (ft_printf("%s", line)) : 0;
	word = make_word(line, length);
	print_result(word = flags->f(word));
	(fd != 0 && flags->flag_r && !flags->flag_q) ? ft_printf(" %s", name) : 0;
	ft_printf("\n");
	free(word);
	ft_str_unsigned_del(&line);
}

int				md5_parce_flags(t_md5_flags *flags, char **av, int ac, int *i)
{
	int j;

	j = 0;
	while (++j && av[*i][j])
	{
		if (av[*i][j] != 's' && av[*i][j] != 'q' &&
			av[*i][j] != 'r' && av[*i][j] != 'p' && av[*i][j] != 'b')
		{
			ft_printf("%s: illegal option -- %c\nAvailable flags:\n-p: echo STD\
IN to STDOUT and append cheksum to STDOUT\n-q: quiet mode\n-r: reverse format\n\
-s: print the sum of a string\n-b: print in binary\n", flags->name, av[*i][j]);
			if (!flags->read_from_fd)
				return (-1);
			else
				return (-2);
		}
		(av[*i][j] == 'q') ? flags->flag_q = 1 : 0;
		(av[*i][j] == 'r') ? flags->flag_r = 1 : 0;
		(av[*i][j] == 'b') ? flags->flag_b = 1 : 0;
		(av[*i][j] == 'p' && ++flags->flag_p) ? md5_from_fd(flags, 0, NULL) : 0;
		if (av[*i][j] == 's' && (flags->write_from_stdin = 1))
			(*i == ac - 1 && !av[*i][j + 1]) ? (ft_printf("%s: option requires \
an argument -- s\n", flags->name)) : parce_s_flag(flags, av, i, &j);
	}
	return (0);
}
