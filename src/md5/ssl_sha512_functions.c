/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_sha512_functions.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/18 13:50:40 by adayrabe          #+#    #+#             */
/*   Updated: 2018/09/18 13:50:40 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_md5_helper_functions.h"

static unsigned long k_arr[80] = {
0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static void		sha512_append_w_arr(unsigned long **w_arr)
{
	int				i;
	unsigned long	s0;
	unsigned long	s1;

	i = 16;
	while (i < 80)
	{
		s0 = rot_r(w_arr[0][i - 15], 1, 64) ^
			rot_r(w_arr[0][i - 15], 8, 64) ^ w_arr[0][i - 15] >> 7;
		s1 = rot_r(w_arr[0][i - 2], 19, 64) ^
			rot_r(w_arr[0][i - 2], 61, 64) ^ w_arr[0][i - 2] >> 6;
		w_arr[0][i] = w_arr[0][i - 16] + s0 + w_arr[0][i - 7] + s1;
		i++;
	}
}

static int		sha512_init_w_arr(t_word *word, unsigned long **w_arr,
		int append_one, size_t *processed_amount)
{
	unsigned long	curr_length;
	int				i;
	int				j;
	size_t			last_byte;

	curr_length = word->length / 8 - (*processed_amount);
	i = 0;
	last_byte = 0;
	while (i < 16 && ++i && !(j = 0))
		while (j < 8 && ++j)
		{
			w_arr[0][i - 1] = (w_arr[0][i - 1] << 8) + word->word[0];
			(last_byte < curr_length && ++last_byte) ? (word->word++) : 0;
		}
	(*processed_amount) += last_byte;
	if (curr_length < 128 && append_one != 1)
		w_arr[0][last_byte / 8] += ft_pow(2, (8 - last_byte % 8) * 8 - 1);
	if (curr_length < 112)
	{
		w_arr[0][14] = ((word->length) >> 63) >> 1;
		w_arr[0][15] = word->length % ft_pow(2, 63);
		ft_printf("%lu\n", w_arr[0][14]);
	}
	sha512_append_w_arr(w_arr);
	return ((curr_length < 128) + (curr_length < 112));
}

static void		sha512_main_loop(unsigned long **temp,
	unsigned long *w_arr)
{
	int				i;
	unsigned long	temp1;
	unsigned long	temp2;

	i = 0;
	while (i < 80)
	{
		temp1 = temp[0][7] + (rot_r(temp[0][4], 14, 64) ^
			rot_r(temp[0][4], 18, 64) ^ rot_r(temp[0][4], 41, 64));
		temp1 += ((temp[0][4] & temp[0][5]) ^ (~temp[0][4] & temp[0][6]));
		temp1 += k_arr[i] + w_arr[i];
		temp2 = rot_r(temp[0][0], 28, 64) ^ rot_r(temp[0][0], 34, 64) ^
		rot_r(temp[0][0], 39, 64);
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

unsigned long	*sha512_start_processing(t_word *word,
	unsigned long *hash_values)
{
	unsigned long	*temp_values;
	unsigned long	*w_arr;
	int				i;
	int				done_w_arr;
	size_t			processed_amount;

	done_w_arr = 0;
	processed_amount = 0;
	temp_values = (unsigned long *)malloc(8 * sizeof(unsigned long));
	w_arr = (unsigned long *)malloc(80 * sizeof(unsigned long));
	while (done_w_arr != 2)
	{
		i = 0;
		while (i < 8 && ++i)
			temp_values[i - 1] = hash_values[i - 1];
		done_w_arr = sha512_init_w_arr(word, &w_arr, done_w_arr,
					&processed_amount);
		sha512_main_loop(&temp_values, w_arr);
		i = 0;
		while (i < 8 && ++i)
			hash_values[i - 1] += temp_values[i - 1];
	}
	free(temp_values);
	free(w_arr);
	return (hash_values);
}
