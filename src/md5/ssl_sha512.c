/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_sha512.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/18 13:50:27 by adayrabe          #+#    #+#             */
/*   Updated: 2018/09/18 13:50:28 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_functions.h"
#include "ssl_md5_helper_functions.h"

static unsigned long	*sha512_init_hash_values(void)
{
	unsigned long *hash_values;

	hash_values = (unsigned long *)malloc(8 * sizeof(unsigned long));
	hash_values[0] = 0x6a09e667f3bcc908;
	hash_values[1] = 0xbb67ae8584caa73b;
	hash_values[2] = 0x3c6ef372fe94f82b;
	hash_values[3] = 0xa54ff53a5f1d36f1;
	hash_values[4] = 0x510e527fade682d1;
	hash_values[5] = 0x9b05688c2b3e6c1f;
	hash_values[6] = 0x1f83d9abfb41bd6b;
	hash_values[7] = 0x5be0cd19137e2179;
	return (hash_values);
}

t_word				*ssl_sha512(t_word *word)
{
	unsigned long	*hash_values;
	int				i;
	unsigned char	*res;
	int j;

	hash_values = sha512_init_hash_values();
	hash_values = sha512_start_processing(word, hash_values);
	res = ft_str_unsigned_new(64);
	i = -1;
	while(++i < 8)
	{
		j = 8;
		while (--j >= 0)
		{
			res[i * 8 + j] = hash_values[i] % 256;
			hash_values[i] /= 256;
		}
	}
	// i = -1;
	// while (++i < 64)
	// 	ft_printf("%.2x", res[i]);
	free(hash_values);
	free(word);
	return (make_word(res, 64));
}
