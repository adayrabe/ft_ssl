
#ifndef SSL_DES_HELPER_FUNCTIONS_H
# define SSL_DES_HELPER_FUNCTIONS_H
# include "ssl_functions.h"
# include <stdbool.h>

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
	void			(*function)(t_word *ciphertext, struct s_des_flags *flags,
						size_t i, t_word *word);
}				t_des_flags;

typedef struct	s_des_stack
{
	char				*name;
	void				(*f)(t_word *ciphertext, t_des_flags *flags,
							size_t i, t_word *word);
	struct s_des_stack	*next;
}				t_des_stack;


t_word			*ssl_des(t_word *word, t_des_flags flags);
t_des_stack		*des_make_stack(void);
void			des_free_stack(t_des_stack **head);
bool			des_parce_flags(t_des_flags *flags, char **av,
	int ac, int *i);
bool			print_flag_error(t_des_flags *flags, int num);
unsigned long	pbkdf2(char *pass, unsigned long salt, int c);
bool			des_parce_arguments(t_des_flags *flags, char **av, int ac);
void			ssl_des_ecb(t_word *ciphertext, t_des_flags *flags,
						size_t i, t_word *word);
void			ssl_des_cbc(t_word *ciphertext, t_des_flags *flags,
						size_t i, t_word *word);
void			ssl_des_cfb(t_word *ciphertext, t_des_flags *flags,
						size_t i, t_word *word);
void			ssl_des_ofb(t_word *ciphertext, t_des_flags *flags,
						size_t i, t_word *word);
void			base64(t_word *ciphertext, t_des_flags *flags,
						size_t i, t_word *word);
unsigned long	code_block(unsigned long m, unsigned long key, bool enc);
unsigned long	*get_subkeys(unsigned long key);
unsigned char	*ssl_base64_decode(unsigned char *word, size_t length);

#endif
