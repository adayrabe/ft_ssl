/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   base64_encode.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/07 12:37:45 by adayrabe          #+#    #+#             */
/*   Updated: 2019/03/07 12:37:46 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_des_helper_functions.h"

static char				convert_encode(size_t number)
{
	if (number < 26)
		return ('A' + number);
	if (number < 52)
		return ('a' + number - 26);
	if (number < 62)
		return ('0' + number - 52);
	if (number == 62)
		return ('+');
	return ('/');
}

static void				transform_encode(unsigned char **line, size_t i,
	unsigned char *word, size_t len)
{
	size_t	temp;
	int		pad;

	pad = 0;
	temp = word[i];
	(i + 1 < len && ++pad) ? (temp = temp * 256 + word[i + 1]) : (temp *= 4);
	(i + 2 < len && pad++) ? (temp = temp * 256 + word[i + 2]) : (temp *= 4);
	if (pad == 2)
	{
		line[0][i / 3 * 4 + 3] = convert_encode(temp % 64);
		temp /= 64;
	}
	else
		line[0][i / 3 * 4 + 3] = '=';
	if (pad != 0)
	{
		line[0][i / 3 * 4 + 2] = convert_encode(temp % 64);
		temp /= 64;
	}
	else
		line[0][i / 3 * 4 + 2] = '=';
	line[0][i / 3 * 4 + 1] = convert_encode(temp % 64);
	temp /= 64;
	line[0][i / 3 * 4] = convert_encode(temp % 64);
}

static unsigned char	*ssl_base64_encode(unsigned char *word, size_t length)
{
	unsigned char	*res;
	size_t			i;
	size_t			len;

	i = 0;
	len = (length + 2) / 3 * 4;
	res = ft_str_unsigned_new(len);
	while (i < length)
	{
		transform_encode(&res, i, word, length);
		i += 3;
	}
	return (res);
}

void					base64(t_word *ciphertext, t_des_flags *flags,
	size_t i, t_word *word)
{
	unsigned char *res;

	i = 0;
	if (flags->encrypt)
	{
		res = ssl_base64_encode(word->word, word->length);
		ciphertext->length = (word->length + 2) / 3 * 4;
	}
	else
	{
		res = ssl_base64_decode(word->word, word->length);
		ciphertext->length = word->length / 4 * 3;
	}
	ciphertext->word = res;
}
