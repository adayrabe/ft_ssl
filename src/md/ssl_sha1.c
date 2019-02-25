#include "ssl_md_helper_functions.h"

static void		sha1_append_w_arr(unsigned int **w_arr)
{
	int				i;
	unsigned int	temp;

	i = 16;
	while (i < 80)
	{
		temp = (w_arr[0][i - 3] ^ w_arr[0][i - 8] ^ w_arr[0][i - 14] ^
			w_arr[0][i - 16]);
		w_arr[0][i] = (temp << 1) | (temp >> (32 - 1));
		i++;
	}
}

static int		sha1_init_w_arr(t_word *word, unsigned int **w_arr,
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
	sha1_append_w_arr(w_arr);
	return ((curr_length < 64) + (curr_length < 56));
}

static void		sha1_main_loop(unsigned int **temp,
	 unsigned int *w_arr)
{
	int				i;
	unsigned int	f;
	unsigned int	k;
	unsigned int	temp_var;

	i = -1;
	while (++i < 80)
	{
		if (i >= 0 && i <= 19 && (k = 0x5A827999))
			f = (temp[0][1] & temp[0][2]) | ((~temp[0][1]) & temp[0][3]);
		else if (i >= 20 && i<= 39 && (k = 0x6ED9EBA1))
			f = temp[0][1] ^ temp[0][2] ^ temp[0][3];
		else if (i >= 40 && i <= 59 && (k = 0x8F1BBCDC))
			f = (temp[0][1] & temp[0][2]) | (temp[0][1] & temp[0][3]) |
		(temp[0][2] & temp[0][3]);
		else if (i >= 60 && i <= 79 && (k = 0xCA62C1D6))
			f = temp[0][1] ^ temp[0][2] ^ temp[0][3];
		temp_var = ((temp[0][0] << 5) | (temp[0][0] >> (32 - 5))) + f + temp[0][4]
			+ k + w_arr[i];
		temp[0][4] = temp[0][3];
		temp[0][3] = temp[0][2];
		temp[0][2] = (temp[0][1] << 30) | (temp[0][1] >> (32 - 30));
		temp[0][1] = temp[0][0];
		temp[0][0] = temp_var;
	}
}

unsigned int	*sha1_start_processing(t_word *word,
	unsigned int *hash_values)
{
	unsigned int	*temp_values;
	unsigned int	*w_arr;
	int				i;
	int				done_w_arr;
	size_t			processed_amount;

	done_w_arr = 0;
	processed_amount = 0;
	temp_values = (unsigned int *)malloc(5 * sizeof(unsigned int));
	w_arr = (unsigned int *)malloc(80 * sizeof(unsigned int));
	while (done_w_arr != 2)
	{
		i = 0;
		while (i < 5 && ++i)
			temp_values[i - 1] = hash_values[i - 1];
		done_w_arr = sha1_init_w_arr(word, &w_arr, done_w_arr,
			&processed_amount);
		sha1_main_loop(&temp_values, w_arr);
		i = 0;
		while (i < 5 && ++i)
			hash_values[i - 1] += temp_values[i - 1];
	}
	free(temp_values);
	free(w_arr);
	return (hash_values);
}

t_word				*ssl_sha1(t_word *word)
{
	unsigned int	*hash_values;
	int				i;
	unsigned char *res;
	int j;


	hash_values = (unsigned int *)malloc(5 * sizeof(unsigned int));
	hash_values[0] = 0x67452301;
	hash_values[1] = 0xEFCDAB89;
	hash_values[2] = 0x98BADCFE;
	hash_values[3] = 0x10325476;
	hash_values[4] = 0xC3D2E1F0;
	hash_values = sha1_start_processing(word, hash_values);
	res = ft_str_unsigned_new(20);
	i = -1;
	while(++i < 5 && (j = 4))
		while (--j >= 0)
		{
			res[i * 4 + j] = hash_values[i] % 256;
			hash_values[i] /= 256;
		}
	free(hash_values);
	free(word);
	return (make_word(res, 20));
}