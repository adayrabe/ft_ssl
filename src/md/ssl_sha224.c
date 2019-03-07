/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_sha224.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/17 17:40:22 by adayrabe          #+#    #+#             */
/*   Updated: 2018/09/17 17:40:23 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_functions.h"
#include "ssl_md_helper_functions.h"

static unsigned int	*sha224_init_hash_values(void)
{
	unsigned int *hash_values;

	hash_values = (unsigned int *)malloc(8 * sizeof(unsigned int));
	hash_values[0] = 0xc1059ed8;
	hash_values[1] = 0x367cd507;
	hash_values[2] = 0x3070dd17;
	hash_values[3] = 0xf70e5939;
	hash_values[4] = 0xffc00b31;
	hash_values[5] = 0x68581511;
	hash_values[6] = 0x64f98fa7;
	hash_values[7] = 0xbefa4fa4;
	return (hash_values);
}

t_word				*ssl_sha224(t_word *word)
{
	unsigned int	*hash_values;
	int				i;
	unsigned char	*res;
	int				j;

	hash_values = sha224_init_hash_values();
	hash_values = sha256_start_processing(word, hash_values);
	res = ft_str_unsigned_new(28);
	i = -1;
	while (++i < 7)
	{
		j = 4;
		while (--j >= 0)
		{
			res[i * 4 + j] = hash_values[i] % 256;
			hash_values[i] /= 256;
		}
	}
	free(hash_values);
	free(word);
	return (make_word(res, 28));
}
