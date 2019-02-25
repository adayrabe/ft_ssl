/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_sha256_functions.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/17 17:40:14 by adayrabe          #+#    #+#             */
/*   Updated: 2018/09/17 17:40:15 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_md5_helper_functions.h"

static unsigned int k_arr[64] = (unsigned int[64])
	{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
		0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
		0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
		0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
		0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
		0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

static void		sha256_append_w_arr(unsigned int **w_arr)
{
	int				i;
	unsigned int	s0;
	unsigned int	s1;

	i = 16;
	while (i < 64)
	{
		s0 = rot_r(w_arr[0][i - 15], 7, 32) ^
			rot_r(w_arr[0][i - 15], 18, 32) ^ w_arr[0][i - 15] >> 3;
		s1 = rot_r(w_arr[0][i - 2], 17, 32) ^
			rot_r(w_arr[0][i - 2], 19, 32) ^ w_arr[0][i - 2] >> 10;
		w_arr[0][i] = w_arr[0][i - 16] + s0 + w_arr[0][i - 7] + s1;
		i++;
	}
}

static int		sha256_init_w_arr(t_word *word, unsigned int **w_arr,
			int append_one, size_t *processed_amount)
{
	size_t			curr_length;
	int				i;
	int				j;
	size_t			last_byte;

	curr_length = word->length - (*processed_amount);
	i = 0;
	last_byte = 0;
	while (i < 16 && ++i && !(j = 0))
		while (j < 4 && ++j)
		{
			w_arr[0][i - 1] = (w_arr[0][i - 1] << 8) + word->word[0];
			(last_byte < curr_length && ++last_byte) ? (word->word++) : 0;
		}
	(*processed_amount) += last_byte;
	if (curr_length < 64 && append_one != 1)
		w_arr[0][last_byte / 4] +=
					(size_t)ft_pow(2, (4 - last_byte % 4) * 8 - 1);
	if (curr_length < 56)
	{
		w_arr[0][14] = (word->length * 8) >> 32;
		w_arr[0][15] = (word->length * 8) % ft_pow(2, 31);
	}
	sha256_append_w_arr(w_arr);
	return ((curr_length < 64) + (curr_length < 56));
}

static void		sha256_main_loop(unsigned int **temp,
	 unsigned int *w_arr)
{
	int				i;
	unsigned int	temp1;
	unsigned int	temp2;

	i = 0;
	while (i < 64)
	{
		temp1 = temp[0][7] + (rot_r(temp[0][4], 6, 32) ^
			rot_r(temp[0][4], 11, 32) ^ rot_r(temp[0][4], 25, 32));
		temp1 += ((temp[0][4] & temp[0][5]) ^ (~temp[0][4] & temp[0][6]));
		temp1 += k_arr[i] + w_arr[i];
		temp2 = rot_r(temp[0][0], 2, 32) ^ rot_r(temp[0][0], 13, 32) ^
		rot_r(temp[0][0], 22, 32);
		temp2 += (temp[0][0] & temp[0][1]) ^ (temp[0][0] & temp[0][2]) ^
		(temp[0][1] & temp[0][2]);
		temp[0][7] = temp[0][6];
		temp[0][6] = temp[0][5];
		temp[0][5] = temp[0][4];
		temp[0][4] = temp[0][3] + temp1;
		temp[0][3] = temp[0][2];
		temp[0][2] = temp[0][1];
		temp[0][1] = temp[0][0];
		temp[0][0] = temp1 + temp2;
		i++;
	}
}

unsigned int	*sha256_start_processing(t_word *word,
	unsigned int *hash_values)
{
	unsigned int	*temp_values;
	unsigned int	*w_arr;
	int				i;
	int				done_w_arr;
	size_t			processed_amount;

	done_w_arr = 0;
	processed_amount = 0;
	temp_values = (unsigned int *)malloc(8 * sizeof(unsigned int));
	w_arr = (unsigned int *)malloc(64 * sizeof(unsigned int));
	while (done_w_arr != 2)
	{
		i = 0;
		while (i < 8 && ++i)
			temp_values[i - 1] = hash_values[i - 1];
		done_w_arr = sha256_init_w_arr(word, &w_arr, done_w_arr,
			&processed_amount);
		sha256_main_loop(&temp_values, w_arr);
		i = 0;
		while (i < 8 && ++i)
			hash_values[i - 1] += temp_values[i - 1];
	}
	free(temp_values);
	free(w_arr);
	return (hash_values);
}
