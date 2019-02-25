/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_md5.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/06 11:15:38 by adayrabe          #+#    #+#             */
/*   Updated: 2018/09/06 11:15:40 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_functions.h"
#include "ssl_md_helper_functions.h"

// static int			*md5_init_s_arr(void)
// {
// 	int *s_arr;
// 	int *temp;
// 	int i;

// 	s_arr = (int *)malloc(sizeof(int) * 64);
// 	temp = (int[64]){7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
// 					5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
// 					4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
// 					6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
// 	i = 0;
// 	while (i < 64 && ++i)
// 		s_arr[i - 1] = temp[i - 1];
// 	return (s_arr);
// }

// static unsigned int	*md5_init_k_arr(void)
// {
// 	unsigned int	*k_arr;
// 	unsigned int	*temp;
// 	int				i;

// 	temp = (unsigned int[64])
// 	{
// 		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
// 		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
// 		0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
// 		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453,
// 		0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
// 		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681,
// 		0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
// 		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5,
// 		0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
// 		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0,
// 		0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
// 	};
// 	k_arr = (unsigned int *)malloc(64 * sizeof(unsigned int));
// 	i = 0;
// 	while (i < 64 && ++i)
// 		k_arr[i - 1] = temp[i - 1];
// 	return (k_arr);
// }

static unsigned int k_arr [64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
    0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453,
    0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681,
    0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5,
    0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0,
    0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};
static int s_arr [64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};


// static void			print_result(unsigned int *hash_values, t_flags *flags)
// {
// 	int i;
// 	int j;

// 	i = -1;
// 	while (++i < 4 && (j = 1))
// 		while (j < 5)
// 		{
// 			if (flags->flag_b == 0)
// 				ft_printf("%.2x", hash_values[i] % 256);
// 			else
// 				ft_printf("%.8b", hash_values[i] % 256);
// 			hash_values[i] /= 256;
// 			j++;
// 		}
// }

static unsigned int	assign_f(unsigned int *temp_vars, int i,
	unsigned int *m_arr)
{
	unsigned int	f;
	int				g;

	g = 0;
	f = 0;
	if (i >= 0 && i <= 15 && (g = i) != -1)
		f = (temp_vars[1] & temp_vars[2]) | ((~temp_vars[1]) & temp_vars[3]);
	if (i >= 16 && i <= 31 && (g = (5 * i + 1) % 16) != -1)
		f = (temp_vars[3] & temp_vars[1]) | ((~temp_vars[3]) & temp_vars[2]);
	if (i >= 32 && i <= 47 && (g = (3 * i + 5) % 16) != -1)
		f = temp_vars[1] ^ temp_vars[2] ^ temp_vars[3];
	if (i >= 48 && i <= 63 && (g = (7 * i) % 16) != -1)
		f = temp_vars[2] ^ (temp_vars[1] | (~temp_vars[3]));
	f = f + temp_vars[0] + k_arr[i] + m_arr[g];
	return (f);
}

static void			md5_main_loop(unsigned int **temp_vars,
	unsigned int *m_arr)
{
	int				i;
	unsigned int	f;

	i = 0;
	while (i < 64)
	{
		f = assign_f(temp_vars[0], i, m_arr);
		temp_vars[0][0] = temp_vars[0][3];
		temp_vars[0][3] = temp_vars[0][2];
		temp_vars[0][2] = temp_vars[0][1];
		temp_vars[0][1] = temp_vars[0][1] +
		((f << s_arr[i]) | f >> (32 - s_arr[i]));
		i++;
	}
}

static int			md5_init_m_arr(t_word *word, unsigned int **m_arr,
	int append_one, size_t *processed_amount)
{
	int		i;
	int		j;
	size_t	last;
	size_t	curr_length;

	i = -1;
	curr_length = word->length - (*processed_amount);
	last = 0;
	while (++i < 16 && !(j = 0) &&
		!(m_arr[0][i] = 0))
		while (j < 4 && ++j)
		{
			m_arr[0][i] = (word->word[0] << (8 * (j - 1))) + m_arr[0][i];
			(last < curr_length && ++last) ? (word->word++) : 0;
		}
	(*processed_amount) += last;
	if (curr_length < 64 && append_one != 1)
		m_arr[0][last / 4] += (size_t)ft_pow(2, (last % 4 + 1) * 8 - 1);
	if (curr_length < 56)
	{
		m_arr[0][14] = (word->length * 8) % ft_pow(2, 31);
		m_arr[0][15] = (word->length * 8) >> 32;
		return (2);
	}
	return (curr_length < 64);
}

unsigned int		*md5_start(t_word *word,
				unsigned int *hash_values)
{
	unsigned int	*temp_vars;
	int				i;
	unsigned int	*m_arr;
	int				done_with_m_arr;
	size_t			processed_amount;

	done_with_m_arr = 0;
	processed_amount = 0;
	temp_vars = (unsigned int *)malloc(4 * sizeof(unsigned int));
	m_arr = (unsigned int *)malloc(16 * sizeof(unsigned int));
	while (done_with_m_arr != 2)
	{
		i = 0;
		while (i < 4 && ++i)
			temp_vars[i - 1] = hash_values[i - 1];
		(done_with_m_arr = md5_init_m_arr(word, &m_arr,
			done_with_m_arr, &processed_amount));
		md5_main_loop(&temp_vars, m_arr);
		i = 0;
		while (i < 4 && ++i)
			hash_values[i - 1] += temp_vars[i - 1];
	}
	free(temp_vars);
	free(m_arr);
	return (hash_values);
}

t_word *ssl_md5(t_word *word)
{

	unsigned int	*hash_values;
	unsigned char	*res;
	int				i;
	int				j;

	hash_values = (unsigned int *)malloc(4 * sizeof(unsigned int));
	hash_values[0] = 0x67452301;
	hash_values[1] = 0xefcdab89;
	hash_values[2] = 0x98badcfe;
	hash_values[3] = 0x10325476;
	hash_values = md5_start(word, hash_values);
	i = -1;
	res = ft_str_unsigned_new(16);
	while (++i < 4 && (j = 1))
		while (j < 5)
		{
			res[i * 4 + j - 1] = hash_values[i] % 256;
			hash_values[i] /= 256;
			j++;
		}
	// i = -1;
	// while (++i < 16)
	// 	ft_printf("%.2x", res[i]);
	free(hash_values);
	free(word);
	return (make_word(res, 16));
}
