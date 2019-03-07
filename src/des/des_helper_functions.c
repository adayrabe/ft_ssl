/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_helper_functions.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/03/07 12:54:52 by adayrabe          #+#    #+#             */
/*   Updated: 2019/03/07 12:54:53 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ssl_des_helper_functions.h"

static char		**make_error_messages(void)
{
	char **messages;

	messages = (char **)malloc(15 * sizeof(char *));
	messages[0] = ("ERROR - AVAILABLE FLAGS FOR DES AND BASE64:\n\
-d, decode mode\n-e, encode mode\n-i, input file\n-o, output file\n\
ONLY FOR DES MODE:\n-a, decode/encode the input/output in base64\n\
-k, key in hex is the next arguement\n-p, password in ascii is the next \
argument\n-s, the salt in hex is the next argument\n-v, initialization \
vector in hex is the next argument");
	messages[1] = "ERROR - NO ARGUMENT FOR FILE NAME";
	messages[2] = "ERROR - WRONG ARGUMENT FOR FILE NAME";
	messages[3] = "ERROR - NO ARGUMENT FOR num";
	messages[4] = "ERROR - NON-HEX DIGIT FOR KEY VALUE";
	messages[5] = "ERROR - NON-HEX DIGIT FOR SALT VALUE";
	messages[6] = "ERROR - NON-HEX DIGIT FOR VECTOR VALUE";
	messages[7] = "ERROR - NO ARGUMENT FOR PASSWORD";
	messages[8] = "ERROR - VERIFY FAILURE\nBAD PASSWORD READ";
	messages[9] = "ERROR - IV UNDEFINED";
	messages[10] = "ERROR - WRONG INPUT FILE (WRONG HEADER)";
	messages[11] = "ERROR - WRONG BLOCK SIZE FOR DES_ECB OR DES-CBC DECRYPTION";
	messages[12] = "ERROR -SMALL SALT IN INPUT FILE";
	messages[13] = "ERROR - WRONG ENDING BLOCK FOR DES-ECB OR DES-CBC DECRYPTIO\
N";
	return (messages);
}

bool			print_flag_error(t_des_flags *flags, int num)
{
	char **messages;

	messages = make_error_messages();
	ft_printf("%s\n", messages[num]);
	free(messages);
	ft_strdel(&(flags->func_name));
	ft_strdel(&(flags->pass));
	ft_str_unsigned_del(&(flags->prefix));
	(flags->input_fd) ? close(flags->input_fd) : 0;
	(flags->output_fd) ? close(flags->output_fd) : 0;
	if (!flags->read_from_fd)
		exit(0);
	return (0);
}

unsigned long	make_message(unsigned char *str, unsigned long length, size_t i)
{
	unsigned long	res;
	int				temp;
	size_t			difference;

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
			res = res * 256 + difference;
		i++;
		temp++;
	}
	return (res);
}

void			add_ciphertext(t_word *ciphertext, unsigned long num)
{
	unsigned char	*temp;
	int				i;

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