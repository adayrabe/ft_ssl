/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/07 12:58:39 by adayrabe          #+#    #+#             */
/*   Updated: 2019/03/07 12:58:40 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_des_helper_functions.h"

void		des3_block(t_word *temp, t_des_flags flags, size_t i, t_word *word)
{
	t_word			*temp1;
	unsigned char	*c1;
	size_t			temp_len;

	flags.key4 = flags.key1;
	(!flags.encrypt) ? (flags.key1 = flags.key3) : 0;
	c1 = ft_str_unsigned_new(0);
	temp1 = make_word(c1, 0);
	ssl_des_ecb(temp1, &flags, i, word);
	flags.encrypt = !flags.encrypt;
	flags.key1 = flags.key2;
	temp_len = temp1->length;
	ssl_des_ecb(temp1, &flags, 0, temp1);
	c1 = temp1->word;
	temp1->word = ft_str_unsigned_new(8);
	i = -1;
	while (++i < temp_len)
		temp1->word[i] = c1[8 + i];
	ft_str_unsigned_del(&c1);
	flags.encrypt = !flags.encrypt;
	flags.key1 = flags.key3;
	(!flags.encrypt) ? (flags.key1 = flags.key4) : 0;
	ssl_des_ecb(temp, &flags, 0, temp1);
	ft_str_unsigned_del(&(temp1)->word);
	free(temp1);
}

void		des3_cbc(t_word *ciphertext, t_des_flags *flags, size_t i,
	t_word *word)
{
	unsigned long	res;
	unsigned long	temp;
	t_word			*temp_word;
	unsigned char	*temp_message;

	res = make_message(word->word, word->length, i);
	temp = res;
	if (flags->encrypt)
		res = res ^ flags->vector;
	temp_message = ft_str_unsigned_new(0);
	temp_word = make_word(temp_message, 0);
	add_ciphertext(temp_word, res);
	des3_block(ciphertext, *flags, 0, temp_word);
	res = make_message(ciphertext->word, ciphertext->length,
		ciphertext->length - 8);
	if (!flags->encrypt)
	{
		res = flags->vector ^ res;
		ciphertext->length -= 8;
		add_ciphertext(ciphertext, res);
	}
	(flags->encrypt) ? (flags->vector = res) :
		(flags->vector = temp);
	ft_str_unsigned_del(&(temp_word->word));
	free(temp_word);
}

t_word		*ssl_des(t_word *word, t_des_flags flags)
{
	size_t			i;
	unsigned char	*ciphertext;
	t_word			*temp;

	i = 0;
	ciphertext = ft_str_unsigned_new(0);
	temp = make_word(ciphertext, 0);
	if (flags.base64 && !flags.encrypt)
		base64(word, &flags, 0, word);
	while (i <= word->length)
	{
		if (i == word->length && !flags.encrypt)
			break ;
		(ft_strnequ("des3", flags.func_name, 4)) ? des3_cbc(temp, &flags, i,
			word) : flags.function(temp, &flags, i, word);
		i += 8;
	}
	(flags.base64 && flags.encrypt) ? base64(temp, &flags, 0, temp) : 0;
	if (!flags.encrypt && !ft_strequ("des-cfb", flags.func_name) && !ft_strequ
("des-ofb", flags.func_name))
		(temp->word[temp->length - 1] < 1 || temp->word[temp->length - 1] > 8) ?
		print_flag_error(&flags, 13) : (temp->length -=
			temp->word[temp->length - 1]);
	free(word);
	return (temp);
}
