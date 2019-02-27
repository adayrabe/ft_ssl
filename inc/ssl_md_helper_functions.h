/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_md_helper_functions.h                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/17 17:40:40 by adayrabe          #+#    #+#             */
/*   Updated: 2018/09/17 17:40:41 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef SSL_MD_HELPER_FUNCTIONS_H
# define SSL_MD_HELPER_FUNCTIONS_H
# include "ssl_functions.h"

typedef struct			s_md_stack
{
	char				*name;
	t_word				*(*f)(t_word *word);
	struct s_md_stack	*next;

}						t_md_stack;

typedef struct	s_md_flags
{
	char			*name;
	t_word			*(*f)(t_word *word);
	char			flag_r;
	char			flag_q;
	int				flag_p;
	char			flag_b;
	char			write_from_stdin;
	char			read_from_fd;
}				t_md_flags;

unsigned int			*sha256_start_processing(t_word *word,
		unsigned int *hash_values);
unsigned long			rot_r(unsigned long value, int amount, int bits);
int						md_parce_flags(t_md_flags *flags, char **av, int ac, int *i);
void					md_from_fd(t_md_flags *flags, int fd, char *name);
unsigned long			*sha512_start_processing(t_word *word,
		unsigned long *hash_values);
t_md_stack				*md_make_stack(void);
void					des_start_processing(int ac, char **av,
	char read_from_fd, t_md_stack **head_md);
void					md_free_stack(t_md_stack **head);

#endif
