# ft_ssl

	Usage: 
	./ft_ssl [Message Digest Commands [Messagge Digest flags]]
	or
	./ft_ssl [Cipher Commands [Cipher flags]]

	In case if there is no possible arguments, the arguments will be read form STDIN (as in OpenSSL).

	This project recreates the OpenSSL's behaviour of various functions. In the md folder will be Message Digest commands, in the des folder will be Cipher commands.

	The only available functions are: read, write, malloc, free, exit, strerr and fstat
	All the other functions are written only using these functions. Most of them are in my libftprintf folder (check my libftprintf project to see which functions I implemented there).

	Message Digest Commands available:
	md5
	sha-1
	sha-224
	sha-256
	sha-384
	sha-512
		
	Message Digest flags available:
	-p: echo STDIN to STDOUT and append cheksum to STDOUT
	-q: quiet mode
	-r: reverse format
	-s: print the sum of a string
	-b: print in binary

	Cipher commands available:
	base64
	des (the same as des-cbc)
	des-ecb
	des-cbc
	des-pcbc
	des-cfb
	des-ofb
	des3 (the same as des3-cbc)
	des3-ecb
	des3-cbc
	des3-pcbc
	des-ofb

	Cipher flags available (for base64 command):
	-d, decode mode
	-e, encode mode (default)
	-i, input file
	-o, output file

	Cipher flags available (for other commands)
	-a, decode/encode the input/output in base64, depending on the encrypt mode
	-d, decrypt mode
	-e, encrypt mode (default)
	-i, input file for message
	-k, key in hex is the next arguement. (Behave like openssl des -K)
	-o, output file for message
	-p, password in ascii is the next argument. (Behave like a modifiedd openssl des -pass)
	-s, the salt in hex is the next argument. (Behave like openssl des -S)
	-v, initialization vector in hex is the next argument. (Behave like openssl des -iv)

	Other functions available:
	pbkdf2 (for now works only for computing hashes of 16 bytes long, planning to make a proper pbkdf2 function in the future)
