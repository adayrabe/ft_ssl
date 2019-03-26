/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/14 14:38:04 by adayrabe          #+#    #+#             */
/*   Updated: 2018/09/14 14:38:09 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <fcntl.h>
#include "ssl_functions.h"
#include "ssl_md_helper_functions.h"
#include <unistd.h>
#include <errno.h>

static void		delete_args(int ac, char ***av, char **line)
{
	int i;

	i = 0;
	while (i < ac)
	{
		ft_strdel(&av[0][i]);
		i++;
	}
	free(*av);
	ft_strdel(line);
}

static void		read_from_stdin(void)
{
	char	*line;
	int		i;
	char	**argv;
	int		argc;

	ft_printf("ft_ssl>");
	while (get_next_line(0, &line))
	{
		if ((i = -1) && line && !ft_strcmp(line, "exit"))
			exit(0);
		(line) ? argv = ft_strsplit(line, ' ') : 0;
		argc = 0;
		while (line && line[++i])
			if ((line[i] == ' ' && line[i + 1] != ' ' && line[i + 1])
				|| (i == 0 && line[i] != ' '))
				argc++;
		line[0] ? md_start_processing(argc, argv, 1) : 0;
		delete_args(argc, &argv, &line);
		ft_printf("ft_ssl>");
	}
}

int				main(int ac, char **av)
{
	if (ac < 2)
		read_from_stdin();
	else
		md_start_processing(ac - 1, &av[1], 0);
	return (0);
}
