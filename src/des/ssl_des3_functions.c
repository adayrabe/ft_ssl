/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des3_functions.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/07 12:58:39 by adayrabe          #+#    #+#             */
/*   Updated: 2019/03/07 12:58:40 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_des_helper_functions.h"

static void				ssl_des3_block(t_word *temp, t_des_flags flags,
	size_t i, t_word *word)
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

void					ssl_des3_ecb(t_word *ciphertext, t_des_flags *flags,
	size_t i, t_word *word)
{
	ssl_des3_block(ciphertext, *flags, i, word);
}

void					ssl_des3_cbc(t_word *ciphertext, t_des_flags *flags,
	size_t i, t_word *word)
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
	ssl_des3_ecb(ciphertext, flags, 0, temp_word);
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

static unsigned long	des_ofb_help(t_des_flags *flags, t_word *temp_word)
{
	t_word			*temp_word2;
	unsigned char	*temp_message2;
	unsigned long	res;

	temp_message2 = ft_str_unsigned_new(0);
	temp_word2 = make_word(temp_message2, 0);
	ssl_des3_block(temp_word2, *flags, 0, temp_word);
	res = make_message(temp_word2->word, temp_word2->length, 0);
	ft_str_unsigned_del(&(temp_word2->word));
	free(temp_word2);
	return (res);
}

void					ssl_des3_ofb(t_word *ciphertext, t_des_flags *flags,
	size_t i, t_word *word)
{
	unsigned long	res;
	bool			enc;
	t_word			*temp_word;
	unsigned char	*temp_message;

	enc = flags->encrypt;
	flags->encrypt = 1;
	if (i == word->length && enc)
		return ;
	temp_message = ft_str_unsigned_new(0);
	temp_word = make_word(temp_message, 0);
	add_ciphertext(temp_word, flags->vector);
	res = des_ofb_help(flags, temp_word);
	flags->vector = res;
	res = make_message(word->word, word->length, i);
	res = res ^ flags->vector;
	add_ciphertext(ciphertext, res);
	if (ciphertext->length > word->length)
		ciphertext->length = word->length;
	flags->encrypt = enc;
	ft_str_unsigned_del(&(temp_word->word));
	free(temp_word);
}
