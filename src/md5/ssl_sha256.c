/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_sha256.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/06 11:53:39 by adayrabe          #+#    #+#             */
/*   Updated: 2018/09/06 11:53:40 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_functions.h"
#include "ssl_md5_helper_functions.h"

unsigned long		rot_r(unsigned long value, int amount, int bits)
{
	return ((value >> amount) | (value << (bits - amount)));
}

static unsigned int	*sha256_init_hash_values(void)
{
	unsigned int *hash_values;

	hash_values = (unsigned int *)malloc(8 * sizeof(unsigned int));
	hash_values[0] = 0x6a09e667;
	hash_values[1] = 0xbb67ae85;
	hash_values[2] = 0x3c6ef372;
	hash_values[3] = 0xa54ff53a;
	hash_values[4] = 0x510e527f;
	hash_values[5] = 0x9b05688c;
	hash_values[6] = 0x1f83d9ab;
	hash_values[7] = 0x5be0cd19;
	return (hash_values);
}

t_word				*ssl_sha256(t_word *word)
{
	unsigned int	*hash_values;
	int				i;
	unsigned char *res;
	int j;


	hash_values = sha256_init_hash_values();
	hash_values = sha256_start_processing(word, hash_values);
	res = ft_str_unsigned_new(32);
	i = -1;
	while(++i < 8)
	{
		j = 4;
		while (--j >= 0)
		{
			res[i * 4 + j] = hash_values[i] % 256;
			hash_values[i] /= 256;
		}
	}
	// i = -1;
	// while (++i < 32)
	// 	ft_printf("%.2x", res[i]);
	free(hash_values);
	free(word);
	return (make_word(res, 32));
}
