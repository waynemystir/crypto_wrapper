
#include <openssl/rsa.h>

int generate_rsa_keypair(RSA **keypair,
	char **private_key,
	char **public_key,
	char *private_key_filepath,
	char *public_key_filepath);

void load_public_key_from_filepath(RSA **public_key, char *filepath);

void load_public_key_from_str(RSA **public_key, char *str);

void load_private_key_from_filepath(RSA **private_key, char *filepath);

void load_private_key_from_str(RSA **private_key, char *str);

void rsa_encrypt(RSA *pubic_key,
	const unsigned char *data,
	unsigned char *encrypted_data,
	int *result_len);

void rsa_decrypt(RSA *private_key,
	const unsigned char *encrypted_data,
	unsigned char *decrypted_data,
	int *result_len);

int aes_encrypt(unsigned char *plaintext,
	unsigned char *key,
	unsigned char *iv,
	unsigned char *ciphertext);

int aes_decrypt(unsigned char *ciphertext,
	int ciphertext_len,
	unsigned char *key,
	unsigned char *iv,
	unsigned char *plaintext);