#include <stdio.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define ECB_MODE 1
#define CBC_MODE 2
#define PLAIN_TEXT_MAX_SIZE 1000
#define CRYPTO_TEXT_MAX_SIZE 1000
#define KEY_LENGTH 16
#define BYTES_THAT_CAN_BE_ENCRYPTED 8

char *plainTextFileName = "plaintext.txt";
char *cryptoTextFileName = "cryptotext.txt";

int cryptoMode = CBC_MODE;
char *initVector = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

char *encryptionKey = "\x6D\x65\x64\x69\x61\x6E\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20";
// char *encryptionKey = "meat            ";

char *plainText;
char *cryptoText;
char *decryptedText;


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
void handleErrors(void);


void main(int argc, char **args) {
	if (cryptoMode == ECB_MODE) {
		printf("Starting to encrypt with key <%s> in ECB_MODE.\n", encryptionKey);
	} else {
		if (cryptoMode == CBC_MODE) {
			printf("Starting to encrypt with key <%s> in CBC_MODE.\n", encryptionKey);
		} else {
			printf("%s\n", "I don't know this kind of encryption mode.");
		}
	}

	FILE *plainTextFile = fopen(plainTextFileName, "r");
	FILE *cryptoTextFile = fopen(cryptoTextFileName, "w");

	plainText = malloc(PLAIN_TEXT_MAX_SIZE * sizeof(char));
	cryptoText = malloc(CRYPTO_TEXT_MAX_SIZE * sizeof(char));

	fread(plainText, 1, PLAIN_TEXT_MAX_SIZE, plainTextFile);

	printf("%s\n", plainText);

	encrypt(plainText, strlen(plainText), encryptionKey, initVector, cryptoText);

	printf("%s\n", cryptoText);

	fprintf(cryptoTextFile, "%s", cryptoText);
}

void handleErrors(void) {
	ERR_print_errors_fp(stderr);
	abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext) {
	EVP_CIPHER_CTX *ctx;

	int len;
	int ciphertext_len;

	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	if (cryptoMode == ECB_MODE) {
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
 			handleErrors();
	}
	if (cryptoMode == CBC_MODE) {
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		handleErrors();
	}	  


	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
	ciphertext_len = len;

	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext) {
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	if (cryptoMode == ECB_MODE) {
		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
			handleErrors();
	}
	if (cryptoMode == CBC_MODE) {
		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		handleErrors();
	}

	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
		plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}