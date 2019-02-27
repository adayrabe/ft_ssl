
#ifndef SSL_DES_HELPER_FUNCTIONS_H
# define SSL_DES_HELPER_FUNCTIONS_H
# include "ssl_functions.h"
# include <stdbool.h>

typedef struct	s_des_stack
{
	char				*name;
	unsigned long		(*f)(t_word *ciphertext, unsigned long prev,
			unsigned long curr, unsigned long key);
	struct s_des_stack	*next;
}				t_des_stack;

typedef struct	s_des_flags
{
	bool			base64;
	bool			encrypt;
	int				input_fd;
	int				output_fd;
	unsigned long	key;
	bool			has_key;
	char			*pass;
	unsigned long	salt;
	bool			has_salt;
	unsigned long	vector;
	bool			has_vector;
	char			*func_name;
	char			read_from_fd;
	unsigned long	(*function)(t_word *ciphertext, unsigned long prev,
			unsigned long curr, unsigned long key);
}				t_des_flags;

t_des_stack		*des_make_stack(void);
void			des_free_stack(t_des_stack **head);
void			des_parce_flags(t_des_flags *flags, char **av,
	int ac, int *i);
void			print_flag_error(t_des_flags *flags, int num);
unsigned long	pbkdf2(char *pass, unsigned long salt, int c);
void			des_parce_arguments(t_des_flags *flags, char **av, int ac);
unsigned long	ssl_des_ecb(t_word *ciphertext, unsigned long prev,
	unsigned long curr, unsigned long key);
unsigned long	ssl_des_cbc(t_word *ciphertext, unsigned long prev,
	unsigned long curr, unsigned long key);
unsigned long	ssl_des_cfb(t_word *ciphertext, unsigned long vector,
	unsigned long curr, unsigned long key);
unsigned long	encode_block(unsigned long m, unsigned long key);
#endif
