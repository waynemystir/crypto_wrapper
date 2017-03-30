#include <stdio.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/err.h>

#include "crypto_wrapper.h"

#define NUM_BYTES_AES_KEY 256
#define NUM_BYTES_AES_IV 128

typedef struct some_struct {
	char memb_one[10];
	char memb_two[10];
	char memb_three[10];
	char memb_four[10];
} some_struct_t;

int main() {
	printf("crypto_wrapper_test main 0\n");

	char *private_key_str = NULL;
	char *public_key_str = NULL;
	generate_rsa_keypair(NULL, &private_key_str, &public_key_str, NULL, NULL);

	printf("security_test main 1 (%s) (%lu)\n", public_key_str, strlen(public_key_str));
	// printf("security_test main 2 (%s)\n", private_key_str);

	unsigned char rsa_plaintext[] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.";
	unsigned char rsa_encrypted_data[512];
	unsigned char rsa_decrypted_data[512];
	memset(rsa_encrypted_data, '\0', 512);
	memset(rsa_decrypted_data, '\0', 512);

	RSA *rsa_pub_key;
	load_public_key_from_str(&rsa_pub_key, public_key_str);
	int result_len = 0;
	printf("Attempting to encrypt (%lu) bytes\n", sizeof(rsa_plaintext));
	rsa_encrypt(rsa_pub_key, rsa_plaintext, sizeof(rsa_plaintext), rsa_encrypted_data, &result_len);
	printf("rsa_encrypted:(%s)(%d)\n", rsa_encrypted_data, result_len);

	RSA *rsa_priv_key;
	load_private_key_from_str(&rsa_priv_key, private_key_str);
	rsa_decrypt(rsa_priv_key, (const unsigned char*)rsa_encrypted_data, rsa_decrypted_data, &result_len);
	printf("rsa_decrypted:(%s)(%d)\n", rsa_decrypted_data, result_len);

	unsigned char symmetric_key[NUM_BYTES_AES_KEY];
	unsigned char iv[NUM_BYTES_AES_IV];
	memset(symmetric_key, '\0', NUM_BYTES_AES_KEY);
	memset(iv, '\0', NUM_BYTES_AES_IV);

	if (!RAND_bytes(symmetric_key, sizeof(symmetric_key))) {
		printf("RAND_bytes failed for symmetric_key\n");
		ERR_print_errors_fp(stdout);
	}

	if (!RAND_bytes(iv, sizeof(iv))) {
		printf("RAND_bytes failed for iv\n");
		ERR_print_errors_fp(stdout);
	}

	printf("symmetric key:\n");
	for (int j = 0; j < NUM_BYTES_AES_KEY; j++)
		printf("(%02X)", symmetric_key[j]);
	printf("\niv:\n");
	for (int k = 0; k < NUM_BYTES_AES_IV; k++)
		printf("(%02X)", iv[k]);
	printf("\n");

	unsigned char aes_plaintext[] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum";
	unsigned char ciphertext[512];
	memset(ciphertext, '\0', 512);
	int ciphertext_len = aes_encrypt(aes_plaintext, strlen((char*)aes_plaintext), symmetric_key, iv, ciphertext);

	printf("ciphertext (%s)\n(%d) (%lu) (%lu)\n",
		ciphertext,
		ciphertext_len,
		strlen((char*)ciphertext),
		sizeof(ciphertext));

	unsigned char aes_decryptedtext[512];
	memset(aes_decryptedtext, '\0', 512);
	int aes_plaintext_len = aes_decrypt(ciphertext, ciphertext_len, symmetric_key, iv, aes_decryptedtext);

	char substr_aes_decryptedtext[aes_plaintext_len+1];
	memcpy( substr_aes_decryptedtext, aes_decryptedtext, aes_plaintext_len);
	substr_aes_decryptedtext[aes_plaintext_len] = '\0';
	int first_index_aes_plaintext_null = 0;
	for (; first_index_aes_plaintext_null < 512; first_index_aes_plaintext_null++) {
		if (aes_decryptedtext[first_index_aes_plaintext_null] == '\0') break;
	}

	printf("aes_decrypt (%s) (%d) (%d)\n", substr_aes_decryptedtext, first_index_aes_plaintext_null, aes_plaintext_len);

	some_struct_t stct;
	strcpy(stct.memb_one, "str one");
	strcpy(stct.memb_two, "str two");
	strcpy(stct.memb_three, "str three");
	strcpy(stct.memb_four, "str four");

	int length = (int)sizeof(stct) + 16;
	unsigned char cipherstruct[length];
	memset(cipherstruct, '\0', length);
	int cipherstruct_len = aes_encrypt((unsigned char*)&stct, (int)sizeof(stct), symmetric_key, iv, cipherstruct);
	unsigned char decryptedstructbytes[length];
	memset(decryptedstructbytes, '\0', length);
	int decrypted_len = aes_decrypt(cipherstruct, cipherstruct_len, symmetric_key, iv, decryptedstructbytes);
	some_struct_t *decryptedstruct = (some_struct_t*)decryptedstructbytes;
	printf("decryptedstruct (%d)(%s)(%s)(%s)(%s)\n", decrypted_len, decryptedstruct->memb_one, decryptedstruct->memb_two, decryptedstruct->memb_three, decryptedstruct->memb_four);

	RSA_free(rsa_pub_key);
	RSA_free(rsa_priv_key);
	free(private_key_str);
	free(public_key_str);

	printf("\ncrypto_wrapper main 1\n");

	return 0;
}