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
#include "ssl_md5_helper_functions.h"
#include <unistd.h>
#include <errno.h>

int				main(int ac, char **av)
{
	char	*line;
	char	**argv;
	int		argc;
	int		i;

	if (ac < 2)
	{
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
			line[0] ? start_md5_processing(argc, argv, 1) : 0;
			ft_strdel(&line);
			ft_printf("ft_ssl>");
		}
	}
	(ac >= 2) ? start_md5_processing(ac - 1, &av[1], 0) : 0;
	return (0);
}
