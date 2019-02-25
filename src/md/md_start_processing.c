/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_md_start_processing.c                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/17 19:02:44 by adayrabe          #+#    #+#             */
/*   Updated: 2018/10/17 19:02:45 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <fcntl.h>
#include "ssl_functions.h"
#include "ssl_md_helper_functions.h"
#include <unistd.h>
#include <errno.h>

static t_md_flags	*create_flag(t_word			*(*f)(t_word *word),
	char *name)
{
	t_md_flags *flags;

	flags = (t_md_flags *)malloc(sizeof(t_md_flags));
	flags->f = f;
	flags->name = ft_strdup(name);
	flags->flag_q = 0;
	flags->flag_r = 0;
	flags->flag_p = 0;
	flags->write_from_stdin = 0;
	flags->flag_b = 0;
	flags->read_from_fd = 0;
	return (flags);
}

static void		read_from_files(int i, char **av, int ac, t_md_flags *flags)
{
	int fd;

	while (i < ac && ++flags->write_from_stdin)
	{
		fd = open(av[i], O_RDONLY);
		if (fd < 0 || read(fd, 0, 0) < 0)
			ft_printf("%s: %s: %s\n",
			ft_str_tolower(flags->name), av[i], strerror(errno));
		else
			md_from_fd(flags, fd, av[i]);
		i++;
		close(fd);
	}
}

static void		md_parce_args(t_md_flags *flags, char **av, int ac)
{
	int i;
	int temp;

	i = 0;
	while (++i < ac)
		if (av[i][0] == '-' && av[i][1])
		{
			temp = md_parce_flags(flags, av, ac, &i);
			if (temp == -1)
				exit(0);
			if (temp == -2)
				return ;
		}
		else
		{
			read_from_files(i, av, ac, flags);
			break ;
		}
	if (flags->write_from_stdin == 0 && (flags->flag_p == 0 || flags->flag_q
		|| flags->flag_r))
		md_from_fd(flags, 0, NULL);
}

void			md_start_processing(int ac, char **av, char read_from_fd)
{
	t_md_flags		*flags;
	t_md_stack		*head;
	t_md_stack		*temp;

	head = md_make_stack();
	temp = head;
	while (temp->name != NULL && ft_strcmp(av[0], temp->name))
		temp = temp->next;
	if (temp->name == NULL)
	{
		des_start_processing(ac, av, read_from_fd, &head);
		if (!read_from_fd)
			exit(0);
		else
			return ;
	}
	flags = create_flag(temp->f, temp->name);
	flags->read_from_fd = read_from_fd;
	md_free_stack(&head);
	md_parce_args(flags, av, ac);
	ft_strdel(&flags->name);
	free(flags);
}
