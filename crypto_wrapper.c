#include <string.h>

#include <openssl/pem.h>
#include <openssl/err.h>

#include "crypto_wrapper.h"

//#define PADDING RSA_PKCS1_OAEP_PADDING
#define PADDING RSA_PKCS1_PADDING
//#define PADDING RSA_NO_PADDING

int generate_rsa_keypair(RSA **keypair,
	char **private_key,
	char **public_key,
	char *private_key_filepath,
	char *public_key_filepath) {

	RSA *kp = RSA_new();
	BIGNUM *exponent = BN_new();
	BN_set_word(exponent, RSA_F4);

	int res = RSA_generate_key_ex(kp, 2048, exponent, NULL);
	if (!res) {
		ERR_print_errors_fp(stderr);
		RSA_free(kp);
		BN_clear_free(exponent);
		CRYPTO_cleanup_all_ex_data();
		return -1;
	}

	// printf("kpkpkp:(%d)\n", RSA_size(kp));

	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(pri, kp, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(pub, kp);

	size_t pri_len = BIO_pending(pri);
	size_t pub_len = BIO_pending(pub);

	char *pri_key = malloc(pri_len + 1);
	char *pub_key = malloc(pub_len + 1);

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	if (private_key) {
		*private_key = malloc(pri_len + 1);
		strcpy(*private_key, pri_key);
	}

	if (public_key) {
		*public_key = malloc(pub_len + 1);
		strcpy(*public_key, pub_key);
	}

	if (private_key_filepath) {
		FILE *priv_file = fopen(private_key_filepath, "w+");
		if (priv_file) {
			fputs(pri_key, priv_file);
			fclose(priv_file);
		}
	}

	if (public_key_filepath) {
		FILE *publ_file = fopen(public_key_filepath, "w+");
		if (publ_file) {
			fputs(pub_key, publ_file);
			fclose(publ_file);
		}
	}

	if (keypair) *keypair = kp;
	else RSA_free(kp);
	BN_clear_free(exponent);
	BIO_free_all(pri);
	BIO_free_all(pub);
	free(pri_key);
	free(pub_key);
	CRYPTO_cleanup_all_ex_data();

	return 0;
}

char *read_file_to_str(char *filepath) {
	FILE *f = fopen(filepath, "r");
	if (f) {
		fseek(f, 0, SEEK_END);
		long fsize = ftell(f);
		fseek(f, 0, SEEK_SET);  //same as rewind(f);
		char *str = malloc(fsize + 1);
		fread(str, fsize, 1, f);
		str[fsize] = 0;
		fclose(f);
		return str;
	}
	return NULL;
}

unsigned char *read_file_to_bytes(char *filepath) {
	FILE *f = fopen(filepath, "r");
	if (f) {
		fseek(f, 0, SEEK_END);
		long fsize = ftell(f);
		fseek(f, 0, SEEK_SET);  //same as rewind(f);
		unsigned char *uca = malloc(fsize + 1);
		fread(uca, fsize, 1, f);
		uca[fsize] = 0;
		fclose(f);
		return uca;
	}
	return NULL;
}

void load_public_key_from_filepath(RSA **public_key, char *filepath) {
	char *r = read_file_to_str(filepath);
	if (r) load_public_key_from_str(public_key, r);
	free(r);
}

void load_public_key_from_str(RSA **public_key, char *str) {
	BIO* bio = BIO_new_mem_buf((void*)str, -1) ; // -1: assume string is null terminated
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL) ; // NO NL
	// Load the RSA key from the BIO
	RSA* rsa_pub_key = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
	if(!rsa_pub_key)
		printf("ERROR: Could not load PUBLIC KEY! PEM_read_bio_RSA_pub_key FAILED: %s\n",
			ERR_error_string(ERR_get_error(), NULL));

	if (public_key) *public_key = rsa_pub_key;
	BIO_free(bio);
	CRYPTO_cleanup_all_ex_data();
}

void load_private_key_from_filepath(RSA **private_key, char *filepath) {
	char *r = read_file_to_str(filepath);
	if (r) load_private_key_from_str(private_key, r);
	free(r);
}

void load_private_key_from_str(RSA **private_key, char *str) {
	BIO *bio = BIO_new_mem_buf( (void*)str, -1 );
	//BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // NO NL
 	RSA* rsa_priv_key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
 	if (!rsa_priv_key)
 		printf("ERROR: Could not load PRIVATE KEY! PEM_read_bio_RSAPrivateKey FAILED: %s\n",
 			ERR_error_string(ERR_get_error(), NULL));
 	BIO_free( bio ) ;
  	if (private_key) *private_key = rsa_priv_key;
  	CRYPTO_cleanup_all_ex_data();
}

void rsa_encrypt(RSA *public_key,
	const unsigned char* data,
	unsigned char *encrypted_data,
	int *result_len) {
	int rsa_len = RSA_size(public_key);
	int data_size = strlen((char*)data);
	memset(encrypted_data, '\0', rsa_len);
	*result_len = RSA_public_encrypt(data_size, (const unsigned char*)data, encrypted_data, public_key, PADDING);
	if (*result_len == -1)
		printf("ERROR: RSA_public_encrypt: %s\n", ERR_error_string(ERR_get_error(), NULL));
}

void rsa_decrypt(RSA *private_key,
	const unsigned char* encrypted_data,
	unsigned char *decrypted_data,
	int *result_len) {
	int rsa_len = RSA_size(private_key) ; // That's how many bytes the decrypted data would be
	memset(decrypted_data, '\0', rsa_len);
	*result_len = RSA_private_decrypt(rsa_len, encrypted_data, decrypted_data, private_key, PADDING);
	if (*result_len == -1)
		printf("ERROR: RSA_private_decrypt: %s\n", ERR_error_string(ERR_get_error(), NULL));
}

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int aes_encrypt(unsigned char *plaintext,
	unsigned char *key,
	unsigned char *iv,
	unsigned char *ciphertext) {

	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;
	int plaintext_len = strlen((char*)plaintext);

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	* this stage.
	*/
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
		ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int aes_decrypt(unsigned char *ciphertext,
	int ciphertext_len,
	unsigned char *key,
	unsigned char *iv,
	unsigned char *plaintext) {

	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	* EVP_DecryptUpdate can be called multiple times if necessary
	*/
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	* this stage.
	*/
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
		plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}