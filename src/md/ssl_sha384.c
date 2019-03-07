/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_sha384.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/18 13:49:13 by adayrabe          #+#    #+#             */
/*   Updated: 2018/09/18 13:49:14 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_md_helper_functions.h"

static unsigned long	*sha384_init_hash_values(void)
{
	unsigned long *hash_values;

	hash_values = (unsigned long *)malloc(8 * sizeof(unsigned long));
	hash_values[0] = 0xcbbb9d5dc1059ed8;
	hash_values[1] = 0x629a292a367cd507;
	hash_values[2] = 0x9159015a3070dd17;
	hash_values[3] = 0x152fecd8f70e5939;
	hash_values[4] = 0x67332667ffc00b31;
	hash_values[5] = 0x8eb44a8768581511;
	hash_values[6] = 0xdb0c2e0d64f98fa7;
	hash_values[7] = 0x47b5481dbefa4fa4;
	return (hash_values);
}

t_word					*ssl_sha384(t_word *word)
{
	unsigned long	*hash_values;
	int				i;
	unsigned char	*res;
	int				j;

	hash_values = sha384_init_hash_values();
	hash_values = sha512_start_processing(word, hash_values);
	res = ft_str_unsigned_new(48);
	i = -1;
	while (++i < 6)
	{
		j = 8;
		while (--j >= 0)
		{
			res[i * 8 + j] = hash_values[i] % 256;
			hash_values[i] /= 256;
		}
	}
	free(hash_values);
	free(word);
	return (make_word(res, 48));
}
