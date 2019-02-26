#include "ssl_des_helper_functions.h"

static unsigned char	*do_xor(unsigned char **str1, unsigned char *str2,
	unsigned int l1, unsigned int l2)
{
	unsigned long	i;
	unsigned char	*res;

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

static t_word			*hmac(t_word *(*f)(t_word *word), t_word *key,
	t_word *message)
{
	unsigned char	*o_key_pad;
	unsigned char	*i_key_pad;
	t_word			*temp;

	if (key->length > 64)
		(key = f(key));
	o_key_pad = ft_str_unsigned_new(64);
	o_key_pad = (unsigned char *) ft_strcpy((char *) o_key_pad, 
"\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\");
	o_key_pad = do_xor(&o_key_pad, key->word, 64, key->length);
	i_key_pad = ft_str_unsigned_new(64);
	i_key_pad = (unsigned char *)ft_strcpy((char *) i_key_pad,
	"6666666666666666666666666666666666666666666666666666666666666666");
	i_key_pad = do_xor(&i_key_pad, key->word, 64, key->length);
	ft_str_unsigned_concat(&i_key_pad, message->word, 64, message->length);
	temp = f(make_word(i_key_pad, 64 + message->length));
	ft_str_unsigned_del(&(message->word));
	free(message);
	ft_str_unsigned_concat(&o_key_pad, temp->word, 64, temp->length);
	temp = make_word(o_key_pad, 64 + temp->length);
	temp = f(temp);
	ft_str_unsigned_del(&o_key_pad);
	ft_str_unsigned_del(&i_key_pad);
	return (temp);
}

static unsigned long	make_key(t_word **word)
{
	unsigned long	res;
	int				i;

	res = 0;
	i = 0;
	while (i < 8)
	{
		res = res * 256 + (*word)->word[i];
		i++;
	}
	free(*word);
	*word = NULL;
	return (res);
}

static unsigned char	*make_first(unsigned long salt)
{
	unsigned char	*first;
	int				i;

	first = ft_str_unsigned_new(12);
	i = -1;
	while (++i < 8)
	{
		first[7 - i] = salt % 256;
		salt /= 256;
	}
	first[11] = 1;
	return(first);
}

unsigned long			pbkdf2(char *pass, unsigned long salt, int c)
{
	t_word			*temp;
	t_word			*key;
	int				i;
	unsigned char	*first;
	t_word			*res;

	key = make_word((unsigned char *)pass, ft_strlen(pass));
	first = make_first(salt);
	temp = hmac(ssl_sha1, key, make_word(first, 12));
	i = 1;
	first = make_first(salt);
	res = hmac(ssl_sha1, key, make_word(first, 12));
	while (++i <= c)
	{
		temp = hmac(ssl_sha1, key, temp);
		res->word = do_xor(&(res->word), temp->word, res->length, temp->length);
	}
	free(key);
	free(temp);
	return (make_key(&res));
}