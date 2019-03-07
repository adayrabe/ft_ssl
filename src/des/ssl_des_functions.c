/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_des_functions.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/07 13:03:43 by adayrabe          #+#    #+#             */
/*   Updated: 2019/03/07 13:03:44 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_des_helper_funstions.h"

void	ssl_des_ecb(t_word *ciphertext, t_des_flags *flags,
	size_t i, t_word *word)
{
	unsigned long res;

	if (!flags->encrypt && word->length % 8 != 0)
	{
		ft_str_unsigned_del(&(ciphertext->word));
		free(ciphertext);
		ft_str_unsigned_del(&(word->word));
		free(word);
		print_flag_error(flags, 11);
	}
	res = make_message(word->word, word->length, i);
	res = code_block(res, flags->key1, flags->encrypt);
	add_ciphertext(ciphertext, res);
	flags->vector = res;
}

void	ssl_des_cbc(t_word *ciphertext, t_des_flags *flags,
	size_t i, t_word *word)
{
	unsigned long res;
	unsigned long temp;

	if (!flags->encrypt && word->length % 8 != 0)
	{
		ft_str_unsigned_del(&(ciphertext->word));
		free(ciphertext);
		ft_str_unsigned_del(&(word->word));
		free(word);
		print_flag_error(flags, 11);
	}
	res = make_message(word->word, word->length, i);
	temp = res;
	if (flags->encrypt)
		res = res ^ flags->vector;
	res = code_block(res, flags->key1, flags->encrypt);
	if (!flags->encrypt)
		res = flags->vector ^ res;
	add_ciphertext(ciphertext, res);
	if (flags->encrypt)
		flags->vector = res;
	else
		flags->vector = temp;
}

void	ssl_des_cfb(t_word *ciphertext, t_des_flags *flags,
	size_t i, t_word *word)
{
	unsigned long	res;
	unsigned long	temp;
	bool			enc;

	res = 0;
	enc = flags->encrypt;
	flags->encrypt = 1;
	if (i == word->length && enc)
		return ;
	res = make_message(word->word, word->length, i);
	flags->vector = code_block(flags->vector, flags->key1, flags->encrypt);
	if (!enc)
		temp = res;
	res = res ^ flags->vector;
	add_ciphertext(ciphertext, res);
	if (ciphertext->length > word->length)
		ciphertext->length = word->length;
	if (enc)
		flags->vector = res;
	else
		flags->vector = temp;
	flags->encrypt = enc;
}

void	ssl_des_ofb(t_word *ciphertext, t_des_flags *flags,
	size_t i, t_word *word)
{
	unsigned long	res;
	bool			enc;

	enc = flags->encrypt;
	flags->encrypt = 1;
	if (i == word->length && enc)
		return ;
	res = make_message(word->word, word->length, i);
	flags->vector = code_block(flags->vector, flags->key1, flags->encrypt);
	res = res ^ flags->vector;
	add_ciphertext(ciphertext, res);
	if (ciphertext->length > word->length)
		ciphertext->length = word->length;
	flags->encrypt = enc;
}
