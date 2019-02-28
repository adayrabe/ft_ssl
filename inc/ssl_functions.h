/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_functions.h                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: adayrabe <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/14 14:45:55 by adayrabe          #+#    #+#             */
/*   Updated: 2018/09/14 14:45:56 by adayrabe         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef SSL_FUNCTIONS_H
# define SSL_FUNCTIONS_H
# include "libft.h"

typedef struct	s_word
{
	unsigned char	*word;
	unsigned long	length;
}				t_word;

void			md_start_processing(int ac, char **av, char read_from_fd);
t_word			*ssl_md5(t_word *word);
t_word			*ssl_sha256(t_word *word);
t_word			*ssl_sha224(t_word *word);
t_word			*ssl_sha512(t_word *word);
t_word			*ssl_sha384(t_word *word);
t_word			*ssl_sha1(t_word *word);
t_word			*make_word(unsigned char *word, size_t length);
#endif
