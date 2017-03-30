#include <stdio.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/err.h>

#include "crypto_wrapper.h"

char asters[] = "**********************************************\n";

#define NUM_BITS_AES_KEY 256
#define NUM_BITS_IV_KEY 128
#define NUM_BYTES_AES_KEY NUM_BITS_AES_KEY/8
#define NUM_BYTES_AES_IV NUM_BITS_IV_KEY/8
#define AES_PADDING 16

int main() {
	printf("%scrypto_wrapper_test_2 First we generate an RSA keypair\n%s", asters, asters);

	char *private_key_str = NULL;
	char *public_key_str = NULL;
	generate_rsa_keypair(NULL, &private_key_str, &public_key_str, NULL, NULL);

	printf("security_test main 1 (%s)(%lu)(%lu)\n", public_key_str, strlen(public_key_str), strlen(private_key_str));

	printf("\n%scrypto_wrapper_test_2 Then we generate an AES key and initialization vector\n%s", asters, asters);

	unsigned char aes_key[NUM_BYTES_AES_KEY] = {0};
	unsigned char iv[NUM_BYTES_AES_IV] = {0};
	memset(aes_key, '\0', NUM_BYTES_AES_KEY);
	memset(iv, '\0', NUM_BYTES_AES_IV);

	if (!RAND_bytes(aes_key, sizeof(aes_key))) {
		printf("RAND_bytes failed for aes_key\n");
		ERR_print_errors_fp(stdout);
	}

	if (!RAND_bytes(iv, sizeof(iv))) {
		printf("RAND_bytes failed for iv\n");
		ERR_print_errors_fp(stdout);
	}

	// printf("AES key(%s)(%lu)(%d) iv(%s)(%lu)(%d)\n", aes_key, strlen((char*)aes_key), NUM_BYTES_AES_KEY,
	// 	iv, strlen((char*)iv), NUM_BYTES_AES_IV);

	printf("\n%scrypto_wrapper_test_2 Next we AES encrypt some text\n%s", asters, asters);

	unsigned char aes_plaintext[] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Is it beach weather yet?!? Come on already! Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem. Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur?";
	int aes_unencrypted_text_len = strlen((char*)aes_plaintext);
	unsigned char aes_ciphertext[aes_unencrypted_text_len + AES_PADDING];
	memset(aes_ciphertext, '\0', aes_unencrypted_text_len + AES_PADDING);
	int aes_ciphertext_len = aes_encrypt(aes_plaintext, strlen((char*)aes_plaintext), aes_key, iv, aes_ciphertext);

	printf("aes_ciphertext (%s)\n(%d) (%lu) (%lu)\n",
		aes_ciphertext,
		aes_ciphertext_len,
		strlen((char*)aes_ciphertext),
		sizeof(aes_ciphertext));

	printf("\n%scrypto_wrapper_test_2 Then we RSA encrypt the AES key\n%s", asters, asters);

	unsigned char rsa_encrypted_data[256];
	unsigned char rsa_decrypted_data[256];
	memset(rsa_encrypted_data, '\0', 256);
	memset(rsa_decrypted_data, '\0', 256);

	RSA *rsa_pub_key;
	load_public_key_from_str(&rsa_pub_key, public_key_str);
	int result_len = 0;
	printf("Attempting to encrypt (%lu) bytes\n", sizeof(aes_key));
	rsa_encrypt(rsa_pub_key, aes_key, sizeof(aes_key), rsa_encrypted_data, &result_len);
	printf("rsa_encrypted:(%s)(%d)\n", rsa_encrypted_data, result_len);

	printf("\n%scrypto_wrapper_test_2 Then we RSA DEcrypt the AES key\n%s", asters, asters);

	RSA *rsa_priv_key;
	load_private_key_from_str(&rsa_priv_key, private_key_str);
	rsa_decrypt(rsa_priv_key, (const unsigned char*)rsa_encrypted_data, rsa_decrypted_data, &result_len);
	printf("rsa_decrypted:(%s)(%d)\n", rsa_decrypted_data, result_len);

	printf("\n%sto_wrapper_test_2 Finally we AES decrypt the aes_ciphertext using the rsa_decrypted_data\n%s", asters, asters);

	unsigned char aes_decryptedtext[aes_unencrypted_text_len + AES_PADDING];
	memset(aes_decryptedtext, '\0', aes_unencrypted_text_len + AES_PADDING);
	int aes_decryptedtext_len = aes_decrypt(aes_ciphertext, aes_ciphertext_len, rsa_decrypted_data, iv, aes_decryptedtext);

	char aes_decryptedtext_substr[aes_decryptedtext_len+1];
	memcpy(aes_decryptedtext_substr, aes_decryptedtext, aes_decryptedtext_len);
	aes_decryptedtext_substr[aes_decryptedtext_len] = '\0';
	printf("\nThe AES decrypted text (%s)(%d)\n", aes_decryptedtext_substr, aes_decryptedtext_len);

	RSA_free(rsa_pub_key);
	RSA_free(rsa_priv_key);
	free(private_key_str);
	free(public_key_str);
	return 0;
}