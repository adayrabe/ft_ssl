/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_start_processing.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/07 12:55:21 by adayrabe          #+#    #+#             */
/*   Updated: 2019/03/07 12:55:26 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_des_helper_functions.h"
#include "ssl_md_helper_functions.h"
#include <unistd.h>
#include <fcntl.h>

static int			print_error(t_des_stack **head_des, t_md_stack **head_md,
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
		void (*f)(t_word *ciphertext, t_des_flags *flags,
				size_t i, t_word *word))
{
	t_des_flags res;

	res.base64 = 0;
	res.encrypt = 1;
	res.input_fd = 0;
	res.output_fd = 1;
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

t_word				*ssl_des(t_word *word, t_des_flags flags)
{
	size_t			i;
	unsigned char	*ciphertext;
	t_word			*temp;

	ciphertext = ft_str_unsigned_new(0);
	temp = make_word(ciphertext, 0);
	i = 0;
	(flags.base64 && !flags.encrypt) ? do_base64_decrypt(word, &flags) : 0;
	while (i <= word->length)
	{
		if (i == word->length && !flags.encrypt)
			break ;
		(ft_strequ("base64", flags.func_name)) ? (i = word->length) : 0;
		flags.function(temp, &flags, i, word);
		i += 8;
	}
	(flags.base64 && flags.encrypt) ? base64(temp, &flags, 0, temp) : 0;
	if (!ft_strequ("base64", flags.func_name) && !flags.encrypt &&
		!ft_strequ("des-cfb", flags.func_name) && !ft_strequ("des-ofb",
		flags.func_name) && !ft_strequ("des3-ofb", flags.func_name))
		(temp->word[temp->length - 1] < 1 || temp->word[temp->length - 1] > 8) ?
		print_flag_error(&flags, 13) : (temp->length -=
			temp->word[temp->length - 1]);
	free(word);
	return (temp);
}

static void			des_start_function(t_des_flags flags, size_t i,
	size_t length)
{
	unsigned char	*word;
	t_word			*res;

	word = NULL;
	length = read_from_fd(flags.input_fd, &word);
	res = make_word(word, length);
	res = ssl_des(res, flags);
	ft_str_unsigned_del(&word);
	if ((i = -1) && flags.prefix[0] && !flags.base64 &&
		(flags.encrypt || flags.has_salt))
	{
		while (++i < 16)
			ft_putchar_fd(flags.prefix[i], flags.output_fd);
	}
	i = -1;
	while (++i < res->length)
	{
		ft_putchar_fd(res->word[i], flags.output_fd);
		((ft_strequ("base64", flags.func_name) || flags.base64) && i % 64 == 63
		&& flags.encrypt) ? ft_putchar_fd('\n', flags.output_fd) : 0;
	}
	(flags.encrypt && i % 64 != 0 && i && (ft_strequ("base64", flags.func_name)
		|| flags.base64)) ? ft_putchar_fd('\n', flags.output_fd) : 0;
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
	if (temp_des->name == NULL && !(print_error(&head_des, head_md, av[0])) &&
		!read_from_fd)
		exit(0);
	if (temp_des->name == NULL)
		return ;
	md_free_stack(head_md);
	flags = init_flags(read_from_fd, temp_des->name, temp_des->f);
	des_free_stack(&head_des);
	if (!des_parce_arguments(&flags, av, ac))
		return ;
	des_start_function(flags, 0, 0);
	ft_strdel(&(flags.pass));
	ft_strdel(&(flags.func_name));
	ft_str_unsigned_del(&(flags.prefix));
	(flags.input_fd) ? close(flags.input_fd) : 0;
	(flags.output_fd != 1) ? close(flags.output_fd) : 0;
}
