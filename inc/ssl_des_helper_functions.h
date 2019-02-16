# include "ssl_functions.h"

typedef struct s_des_stack
{
	char				*name;
	t_word				*(*f)(t_word *word);
	struct s_des_stack	*next;
}t_des_stack;

t_des_stack		*des_make_stack(void);
void des_free_stack(t_des_stack **head);