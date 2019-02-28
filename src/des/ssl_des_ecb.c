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

void add_ciphertext(t_word *ciphertext, unsigned long num)
{
	unsigned char	*temp;
	int i;

	temp = ft_str_unsigned_new(8);
	i = -1;
	while (++i < 8)
	{
		temp[7 - i] = num % 256;
		num /= 256;
	}
	ft_str_unsigned_concat(&(ciphertext->word), temp, ciphertext->length, 8);
	ciphertext->length += 8;
	ft_str_unsigned_del(&temp);

}

void	ssl_des_ecb(t_word *ciphertext, t_des_flags *flags,
	size_t i, t_word *word)
{
	unsigned long res;

	res = make_message(word->word, word->length, i);
	res = code_block(res, flags->key, flags->encrypt);
	add_ciphertext(ciphertext, res);
	flags->vector = res;
}

void	ssl_des_cbc(t_word *ciphertext, t_des_flags *flags,
	size_t i, t_word *word)
{
	unsigned long res;
	unsigned long temp;

	res = make_message(word->word, word->length, i);
	temp = res;
	// res = i;
	if (flags->encrypt)
		res = res ^ flags->vector;
	res = code_block(res, flags->key, flags->encrypt);
	if (!flags->encrypt)
		res = flags->vector ^ res;
	add_ciphertext(ciphertext, res);
	if (flags->encrypt)
		flags->vector = res;
	else
		flags->vector = temp;
}

void	ssl_des_cfb(t_word *ciphertext, t_des_flags *flags,
	size_t i, t_word *word)
{
	unsigned long res;
	unsigned long temp;

	res = 0;
	if (i == word->length)
		return ;
	res = make_message(word->word, word->length, i);
	flags->vector = code_block(flags->vector, flags->key, flags->encrypt);
	if (!flags->encrypt)
		temp = res;
	res = res ^ flags->vector;
	add_ciphertext(ciphertext, res);
	if (ciphertext->length > word->length)
		ciphertext->length = word->length;
	if (flags->encrypt)
		flags->vector = res;
	else
		flags->vector = temp;

	// unsigned long res;

	// res = code_block(flags->vector, flags->key, flags->encrypt);
	// res = curr ^ res;
	// add_ciphertext(ciphertext, res);
	// flags->vector = res;
}

void	ssl_des_ofb(t_word *ciphertext, t_des_flags *flags,
	size_t i, t_word *word)
{
	unsigned long res; 

	res = make_message(word->word, word->length, i);
	flags->vector = code_block(flags->vector, flags->key, flags->encrypt);
	res = res ^ flags->vector;
	add_ciphertext(ciphertext, res);
}

t_word		*ssl_des(t_word *word, t_des_flags flags)
{
	size_t			i;
	unsigned char	*ciphertext;
	t_word			*temp;
	// unsigned long curr;

	i = 0;
	ciphertext = NULL;
	// ft_printf("%s\n", (char *)word->word);
	// curr = vector;
	ciphertext = ft_str_unsigned_new(0);
	temp = make_word(ciphertext, 0);
	while (i <= word->length)
	{
		if (i == word->length && !flags.encrypt)
			break ;
		// prev = curr;
		// curr = make_message(word->word, word->length, i);
		// curr = encode_block(curr, key);
		flags.function(temp, &flags, i,  word);
		// add_ciphertext(temp, curr);
		i += 8;
	}
	ciphertext = temp->word;
	i = temp->length;
	// ft_printf("%d\n", i);
	free(temp);
	free(word); 
	return(make_word(ciphertext, i));
}
