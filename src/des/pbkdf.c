#include "ssl_des_helper_functions.h"

// void do_xor(unsigned char **str, unsigned char a, t_word *key)
// {
// 	unsigned long i;

// 	i = -1;
// 	while (++i < 64)
// 		if (i > key->length)
// 			str[0][i] = a;
// 		else
// 			str[0][i] = key->word[i] ^ a;
// }

unsigned char *do_xor(unsigned char **str1, unsigned char *str2, unsigned int l1,
	unsigned int l2)
{
	unsigned long i;
	unsigned char *res;

	i = -1;
	res = ft_str_unsigned_new(l1);
	while (++i < l1)
		if (i > l2)
			res[i] = str1[0][i];
		else
			res[i] = str1[0][i] ^ str2[i];
	ft_str_unsigned_del(str1);
	return (res);
}

t_word *hmac(t_word *(*f)(t_word *word), t_word *key, t_word *message)
{
	unsigned char *o_key_pad;
	unsigned char *i_key_pad;
	t_word *temp;

	if (key->length > 64)
		(key = f(key));
	o_key_pad = ft_str_unsigned_new(64);
	o_key_pad = (unsigned char *) ft_strcpy((char *) o_key_pad, "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\");
	//do_xor(&o_key_pad, 0x5c, key);
	o_key_pad = do_xor(&o_key_pad, key->word, 64, key->length);
	i_key_pad = ft_str_unsigned_new(64);
	i_key_pad = (unsigned char *)ft_strcpy((char *) i_key_pad, "6666666666666666666666666666666666666666666666666666666666666666");
	// do_xor(&i_key_pad, 0x36, key);
	i_key_pad = do_xor(&i_key_pad, key->word, 64, key->length);
	ft_str_unsigned_concat(&i_key_pad, message->word, 64, message->length);
	temp = f(make_word(i_key_pad, 64 + message->length));
	free(message);
	ft_str_unsigned_concat(&o_key_pad, temp->word, 64, temp->length);
	temp = make_word(o_key_pad, 64 + temp->length);
	temp = f(temp);
	return (temp);
}

unsigned long pbkdf(char *pass, unsigned long salt, int c)
{
	t_word	*temp;
	t_word	*key;
	int		i;
	unsigned char *first;
	// t_word	*res;

	key = make_word((unsigned char *)pass, ft_strlen(pass));
	first = ft_str_unsigned_new(12);
	i = -1;
	while (++i < 8)
	{
		first[7 - i] = salt % 256;
		salt /= 256;
	}
	first[11] = 1;
	// temp = hmac(ssl_sha256, key, make_word(first, 12));
	temp = hmac(ssl_sha256, key, make_word((unsigned char *)"The quick brown fox jumps over the lazy dog", 43));
	i = -1;
	ft_printf("LENGTH: %d\n", temp->length);
	while (++i < (int)temp->length)
		ft_printf("%x", temp->word[i]);
	// c = 0;
	i = 1;
	c = 0;
	// res = hmac(ssl_sha256, key, make_word(first, 12));
	// 	ft_str_unsigned_del(&first);

	// while (++i <= c)
	// {
	// 	temp = hmac(ssl_sha256, key, temp);
	// 	res->word = do_xor(&(res->word), temp->word, res->length, temp->length);
	// }
	free(key);
	free(temp);
	return (0);
}