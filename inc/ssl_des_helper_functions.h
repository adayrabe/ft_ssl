# include "ssl_functions.h"
# include <stdbool.h>

typedef struct	s_des_stack
{
	char				*name;
	t_word				*(*f)(t_word *word);
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
	t_word			*(*function)(t_word *wprd);
}				t_des_flags;

t_des_stack		*des_make_stack(void);
void			des_free_stack(t_des_stack **head);
void			des_parce_flags(t_des_flags *flags, char **av,
	int ac, int *i);
void print_flag_error(t_des_flags *flags, int num);
unsigned long make_num(char *str, bool *error);
unsigned long pbkdf2(char *pass, unsigned long salt, int c);
