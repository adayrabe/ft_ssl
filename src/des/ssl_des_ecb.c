#include "ssl_des_helper_functions.h"

unsigned long make_message(unsigned char *str, unsigned long length, size_t i)
{
	unsigned long res;
	int temp;
	size_t difference;

	res = 0;
	temp = 0;
	difference = 0;
	if (i + 8 > length)
		difference = i + 8 - length;
	while (temp < 8)
	{
		if (i < length)
			res = res * 256 + str[i];
		else
			res = res *  256 + difference; //right one
				// res = res *  256 ; // to check online

		i++;
		temp++;
	}
	return (res);
}

unsigned long	ssl_des_ecb(t_word *ciphertext, unsigned long prev,
	unsigned long curr, unsigned long key)
{
	unsigned char	*temp;
	int				i;
	unsigned long	t;

	temp = ft_str_unsigned_new(8);
	curr = encode_block(curr, key);
	i = -1;
	t = curr;
	while (++i < 8)
	{
		temp[7 - i] = t % 256;
		t /= 256;
	}
	prev = 0;
	ft_str_unsigned_concat(&(ciphertext->word), temp, ciphertext->length, 8);
	ciphertext->length += 8;
	ft_str_unsigned_del(&temp);
	return(curr);
}

unsigned long	ssl_des_cbc(t_word *ciphertext, unsigned long vector,
	unsigned long curr, unsigned long key)
{
	int				i;
	unsigned char	*temp;
	unsigned long	t;

	temp = ft_str_unsigned_new(8);
	curr = curr ^ vector;
	curr = encode_block(curr, key);
	// ft_printf("%lx\n", curr);
	i = -1;
	t = curr;
	while (++i < 8)
	{
		temp[7 - i] = t % 256;
		t /= 256;
	}
	ft_str_unsigned_concat(&(ciphertext->word), temp, ciphertext->length, 8);
	ciphertext->length += 8;
	ft_str_unsigned_del(&temp);
	return (curr);
}

unsigned long	ssl_des_cfb(t_word *ciphertext, unsigned long vector,
	unsigned long curr, unsigned long key)
{
	int				i;
	unsigned char	*temp;
	unsigned long	t;

	temp = ft_str_unsigned_new(8);
	vector = encode_block(vector, key);
	curr = curr ^ vector;
	i = -1;
	t = curr;
	while (++i < 8)
	{
		temp[7 - i] = t % 256;
		t /= 256;
	}
	ft_str_unsigned_concat(&(ciphertext->word), temp, ciphertext->length, 8);
	ciphertext->length += 8;
	ft_str_unsigned_del(&temp);
	return (curr);
}

t_word		*ssl_des(t_word *word, unsigned long key,
	unsigned long (*f)(t_word *ciphertext, unsigned long prev,
						unsigned long curr, unsigned long key),
	unsigned long vector)
{
	unsigned long	prev;
	unsigned long	curr;
	size_t			i;
	unsigned char	*ciphertext;
	t_word			*temp;

	i = 0;
	ciphertext = NULL;
	curr = vector;
	ciphertext = ft_str_unsigned_new(0);
	temp = make_word(ciphertext, 0);
	while (i <= word->length)
	{
		prev = curr;
		curr = make_message(word->word, word->length, i);
		// curr = encode_block(curr, key);
		curr = f(temp, prev, curr, key);
		ft_printf("CURR: %lx\n", curr);
		i += 8;
	}
	ciphertext = temp->word;
	i = temp->length;
	// ft_printf("%d\n", i);
	free(temp);
	free(word);
	return(make_word(ciphertext, i));
}
