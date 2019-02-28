#include "ssl_des_helper_functions.h"

static unsigned char	convert_decode(unsigned char number,
	unsigned char *word)
{
	if (number >= 'A' && number <= 'Z')
		return (number - 'A');
	if (number >= 'a' && number <= 'z')
		return (number + 26 - 'a');
	if (number >= '0' && number <= '9')
		return (number - '0' + 52);
	if (number == '+')
		return (62);
	if (number == '/')
		return (63);
	ft_printf("bad pattern: %s\n", word);
	exit(0);
	return (64);
}

static bool				transform_decode(unsigned char **line,
	unsigned char *word, size_t i)
{
	int temp;
	
	temp = (convert_decode(word[0], word) << 6) + convert_decode(word[1], word);
	line[0][i / 4 * 3] = temp >> 4;
	temp = temp % 16;
	if (word[2] != '=' && word[2])
	{
		temp = (temp << 6) + convert_decode(word[2], word);
		line[0][i / 4 * 3 + 1] = temp >> 2;
		temp = temp % 4;
	}
	else if (word[2] && word[3] != '"')
	{
		ft_printf("Invalid character in input stream\n");//check with zsh
		exit(0);
	}
	if (word[3] != '=' && word[3] && word[2])
	{
		temp = (temp << 6) + convert_decode(word[3], word);
		line[0][i / 4 * 3 + 2] = temp;
	}
	if (word[2] == '=' || word[3] == '=')
		return (1);
	return(0);
}

unsigned char			*ssl_base64_decode(unsigned char *word, size_t length)
{
	unsigned char *res;
	size_t i;
	unsigned char *temp;
	size_t j;
	bool done;
	
	i = 0;
	j = 0;
	done = 0;
	res = ft_str_unsigned_new(length / 4 * 3);
	temp = ft_str_unsigned_new(4);
	while (i < length && !done)
	{
		if (word[i] != ' '  && ++j)
			temp[(j - 1) % 4] = word[i];
		if (j % 4 == 0 && j)
		{
			done = transform_decode(&res, temp, j - 1);
			ft_str_unsigned_del(&temp);
			temp = ft_str_unsigned_new(4);
		}
		i++;
	}
	ft_str_unsigned_del(&temp);
	return (res);
}