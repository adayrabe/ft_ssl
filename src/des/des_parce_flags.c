#include "ssl_des_helper_functions.h"
#include <errno.h>
# include <fcntl.h>

void print_flag_error(t_des_flags *flags, int num)
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
	messages[10] = "ERROR - WRONG INPUT FILE (WORNG HEADER)";
	ft_printf("%s\n", messages[num]);
	free(messages);
	ft_strdel(&(flags->func_name));
	ft_strdel(&(flags->pass));
	exit(0);
}

void get_fd(t_des_flags *flags, char **av, int ac, int *i)
{
	char c;

	c = av[*i][1];
	(*i)++;
	if (*i == ac)
		print_flag_error(flags, 1);
	if (c == 'i')
		flags->input_fd = open(av[*i], O_RDONLY);
	else
		flags->output_fd = open(av[*i], O_WRONLY | O_CREAT | O_TRUNC);
}

unsigned long make_num(char *str, bool *error)
{
	unsigned int j;
	unsigned long num;

	j = -1;
	num = 0;
	while (++j < 16 && !(*error))
	{
		if (j >= ft_strlen(str))
			num = num * 16;
		else if (str[j] >= '0' && str[j]<= '9')
			num = num * 16 + str[j] - '0';
		else if (str[j] >= 'A' && str[j] <= 'F')
			num = num * 16 + str[j] - 'A' + 10;
		else if (str[j] >= 'a' && str[j] <= 'f')
			num = num * 16 + str[j] - 'a' + 10;
		else
			*error = 1;
	}
	return (num);
}

void get_number(t_des_flags *flags, char **av, int ac, int *i)
{
	char c;
	unsigned long num;
	bool error;

	c = av[*i][1];
	(*i)++;
	(*i == ac) ? print_flag_error(flags, 3) : 0;
	error = 0;
	num = make_num(av[*i], &error);
	if (c == 'k' && ++flags->has_key)
		(error) ? print_flag_error(flags, 4) : (flags->key = num);
	if (c == 's' && ++flags->has_salt)
		(error) ? print_flag_error(flags, 5) : (flags->salt = num);
	if (c == 'v' && ++flags->has_vector)
		(error) ? print_flag_error(flags, 6) : (flags->vector = num);
}

void des_parce_flags(t_des_flags *flags, char **av, int ac, int *i)
{
	if (ft_strlen(av[*i]) != 2)
		print_flag_error(flags, 0);
	if (av[*i][1] == 'd')
		flags->encrypt = 0;
	else if (av[*i][1] == 'i' || av[*i][1] == 'o')
		get_fd(flags, av, ac, i);
	else if (ft_strequ(flags->func_name, "base64"))
		print_flag_error(flags, 0);
	else if (av[*i][1] == 'a')
		flags->base64 = 1;
	else if (av[*i][1] == 'k' || av[*i][1] == 's' || av[*i][1] == 'v')
		get_number(flags, av, ac, i);
	else if (av[*i][1] == 'p')
	{
		(*i)++;	
		(*i == ac) ? print_flag_error(flags, 7) : 0;
		flags->pass = ft_strdup(av[*i]);
		// flags->has_key = 0;
	}
	else
		print_flag_error(flags, 0);
}