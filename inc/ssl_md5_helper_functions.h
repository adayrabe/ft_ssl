/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_helper_functions.h                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/17 17:40:40 by adayrabe          #+#    #+#             */
/*   Updated: 2018/09/17 17:40:41 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef SSL_MD5_HELPER_FUNCTIONS_H
# define SSL_MD5_HELPER_FUNCTIONS_H
# include "ssl_functions.h"

typedef struct			s_md5_stack
{
	char				*name;
	t_word				*(*f)(t_word *word);
	struct s_md5_stack	*next;

}						t_md5_stack;

unsigned int			*sha256_start_processing(t_word *word,
		unsigned int *hash_values);
unsigned long			rot_r(unsigned long value, int amount, int bits);
int						parce_flags(t_flags *flags, char **av, int ac, int *i);
void					from_fd(t_flags *flags, int fd, char *name);
unsigned long			*sha512_start_processing(t_word *word,
			unsigned long *hash_values);
t_md5_stack				*make_md5_stack(void);
t_word					*make_word(unsigned char *word, size_t length);

#endif
