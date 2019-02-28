// #include "ssl_des_helper_functions.h"

//  unsigned long permutate_back(unsigned long num, int *table, int length, int bits)
// {
// 	unsigned long	res;
// 	int				i;

// 	res = 0;
// 	i = -1;
// 	while (++i < length)
// 	{
// 		 res = res |  (num % 2 << (bits - table[length - i - 1]));
// 		 num /= 2;
// 	}
// 	return (res);
// }

// unsigned long	decode_block(unsigned long m, unsigned long key)
// {
// 	unsigned int	temp;
// 	unsigned long	*subkeys;
// 	unsigned int	l;
// 	unsigned int	r;
// 	unsigned long	ip_minus_one;

// 	res = 0;
// 	key = 0x133457799BBCDFF1;
// 	m = 0x85E813540F0AB405;
// 	subkeys = get_subkeys(key);
// 	ip_minus_one = permutate_back(m, g_ip_minus_one, 64, 64);
// 	l = (unsigned int)ip_minus_one;
// 	r = ip_minus_one >> 32;
// 	ft_printf("L: %x\n R: %x\n", l, r);
// 	ip = 0;
// 	while (++ip < 17)
// 	{
// 		temp = 
// 	}
// 	free(subkeys);
// 	return (res);
// }