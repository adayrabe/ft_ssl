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
	// ft_str_unsigned_del(&(ciphertext->word));
	// ft_str_unsigned_concat(&(ciphertext->word), temp, 0, 8);
	ft_str_unsigned_concat(&(ciphertext->word), temp, ciphertext->length, 8);
	ciphertext->length += 8;
	ft_str_unsigned_del(&temp);

}

void	ssl_des_ecb(t_word *ciphertext, t_des_flags *flags,
	size_t i, t_word *word)
{
	unsigned long res;

	// ft_printf("KEY: %lx\n", flags->key1);
	if (!flags->encrypt && word->length % 8 != 0)
	{
		ft_str_unsigned_del(&(ciphertext->word));
		free(ciphertext);
		ft_str_unsigned_del(&(word->word));
		free(word);
		print_flag_error(flags, 11);
	}
	res = make_message(word->word, word->length, i);
	res = code_block(res, flags->key1, flags->encrypt);
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
	// ft_printf("VECTOR: %lx\n", flags->vector);
	if (flags->encrypt)
		res = res ^ flags->vector;
	res = code_block(res, flags->key1, flags->encrypt);
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
	unsigned long	res;
	unsigned long	temp;
	bool			enc;

	res = 0;
	enc = flags->encrypt;
	flags->encrypt = 1;
	if (i == word->length && enc)
		return ;
	res = make_message(word->word, word->length, i);
	flags->vector = code_block(flags->vector, flags->key1, flags->encrypt);
	if (!enc)
		temp = res;
	res = res ^ flags->vector;
	add_ciphertext(ciphertext, res);
	if (ciphertext->length > word->length)
		ciphertext->length = word->length;
	if (enc)
		flags->vector = res;
	else
		flags->vector = temp;
	flags->encrypt = enc;
}

void	ssl_des_ofb(t_word *ciphertext, t_des_flags *flags,
	size_t i, t_word *word)
{
	unsigned long	res;
	bool			enc;

	enc = flags->encrypt;
	flags->encrypt = 1;
	if (i == word->length && enc)
		return ;
	res = make_message(word->word, word->length, i);
	flags->vector = code_block(flags->vector, flags->key1, flags->encrypt);
	res = res ^ flags->vector;
	add_ciphertext(ciphertext, res);
	if (ciphertext->length > word->length)
		ciphertext->length = word->length;
	flags->encrypt = enc;
}

void des3_block(t_word *temp, t_des_flags flags, size_t i, t_word *word)
{
	unsigned long t;
	size_t l;
	t_word *temp1;
	unsigned char *c1;
	size_t temp_len;

	t = flags.key1;
 	(!flags.encrypt) ? (flags.key1 = flags.key3) : 0; 
 	c1 = ft_str_unsigned_new(0);
 	temp1 = make_word(c1, 0);
	ssl_des_ecb(temp1, &flags, i, word);
	flags.encrypt = !flags.encrypt;
	flags.key1 = flags.key2;
	temp_len = temp1->length;
	ssl_des_ecb(temp1, &flags, 0, temp1);
	c1 = temp1->word;
	temp1->word = ft_str_unsigned_new(8);
	l = -1;
	while (++l < temp_len)
		temp1->word[l] = c1[8 + l];
	ft_str_unsigned_del(&c1);
	flags.encrypt = !flags.encrypt;
	flags.key1 = flags.key3;
	(!flags.encrypt) ? (flags.key1 = t) : 0;
	ssl_des_ecb(temp, &flags, 0, temp1);
	ft_str_unsigned_del(&(temp1)->word);
	free(temp1);
}
void des3_cbc(t_word *ciphertext, t_des_flags *flags, size_t i, t_word *word)
{
	unsigned long res;
	unsigned long temp;
	t_word *temp_word;
	unsigned char *temp_message;

	res = make_message(word->word, word->length, i);
	ft_printf("\n vector: %lx\n", flags->vector);
	temp = res;
	// if (flags->encrypt)
		res = res ^ flags->vector;
			// ft_printf("\nRES: %lx\n", res);

	temp_message = ft_str_unsigned_new(0);
	temp_word = make_word(temp_message, 0);
	add_ciphertext(temp_word, res);
	ft_printf("CIPHERTEXT BEFORE: \n");
	int l;
	l = -1;
	while (++l < 8)
		ft_printf("%x ", ciphertext->word[ciphertext->length - 8 + l]);
	ft_printf("TEMP BEFORE: \n");
	l = -1;
	while (++l < 8)
		ft_printf("%x ", temp_word->word[l]);
	des3_block(ciphertext, *flags, i, temp_word);
	ft_printf("CIPHERTEXT after: \n");
	l = -1;
	while (++l < 8)
		ft_printf("%x ", ciphertext->word[ciphertext->length - 8 + l]);
	res = make_message(ciphertext->word, ciphertext->length, ciphertext->length - 8);
	// if (!flags->encrypt)
		// res = flags->vector ^ res;
	// add_ciphertext(ciphertext, res);
	// if (flags->encrypt)
	ft_printf("\nlength: %d\n", ciphertext->length);
	l = -1;
	while (++l < 8)
		ft_printf("%x", ciphertext->word[ciphertext->length - 8 + l]);
	flags->vector = res;
	ft_str_unsigned_del(&(temp_word->word));
	free(temp_word);
	// else
	// 	flags->vector = temp;
}

t_word		*ssl_des(t_word *word, t_des_flags flags)
{
	size_t			i;
	unsigned char	*ciphertext;
	t_word			*temp;

	i = 0;
	ciphertext = ft_str_unsigned_new(0);
	temp = make_word(ciphertext, 0);
	if (flags.base64 && !flags.encrypt)
		base64(word, &flags, 0, word);
	while (i <= word->length)
	{
		if (i == word->length && !flags.encrypt)
			break ;
		(ft_strnequ("des3", flags.func_name, 4)) ? des3_block(temp, flags, i, word) :
			flags.function(temp, &flags, i,  word);
		// temp->length += 8;
		i += 8;
	}
	if (flags.base64 && flags.encrypt)
		base64(temp, &flags, 0, temp);
	ciphertext = temp->word;
	i = temp->length;
	free(temp);
	free(word);
	// size_t l;
	// ft_printf("\n");
	// l = -1;
	// while (++l < i)
	// 	ft_printf("%x ", ciphertext[l]);
	return(make_word(ciphertext, i));
}
