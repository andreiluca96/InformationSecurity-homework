#include <stdio.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <ctype.h>

#define ECB_MODE 1
#define CBC_MODE 2
#define PLAIN_TEXT_MAX_SIZE 1000
#define CRYPTO_TEXT_MAX_SIZE 1000
#define KEY_LENGTH 16
#define BYTES_THAT_CAN_BE_ENCRYPTED 8

char *plainTextFileName = "plaintext.txt";
char *cryptoTextFileName = "cryptotext.txt";
char *dictionaryFileName = "dictionary.txt";

int cryptoMode = ECB_MODE;
char *initVector = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

// char *encryptionKey = "\x6D\x65\x64\x69\x61\x6E\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20";
char *encryptionKey = "meat            ";

char *plainText;
char *cryptoText;
char *decryptedText;

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
	FILE *encryptedFile = fopen(cryptoTextFileName, "r");
	FILE *dictionaryFile = fopen(dictionaryFileName, "r");

	plainText = malloc(PLAIN_TEXT_MAX_SIZE * sizeof(char));
	decryptedText = malloc(PLAIN_TEXT_MAX_SIZE * sizeof(char));
	cryptoText = malloc(CRYPTO_TEXT_MAX_SIZE * sizeof(char));


	fread(plainText, 1, PLAIN_TEXT_MAX_SIZE, plainTextFile);
	printf("Plain text: <%s>\n", plainText);
	fread(cryptoText, 1, CRYPTO_TEXT_MAX_SIZE, encryptedFile);

	size_t len1 = 0;
	size_t read;
	char *word = malloc(KEY_LENGTH * sizeof(char));
	while ((read = getline(&word, &len1, dictionaryFile)) != -1) {
        for (int i = 0; i < strlen(word); i++) {
        	word[i] = tolower(word[i]);
        }
        word[strlen(word) - 1] = '\0';

        char *key = malloc(KEY_LENGTH * sizeof(char));
        sprintf(key, "%-16s", word);
        key[16] = '\0';

        printf("<%s>%d\n", key, (int)strlen(key));

        int len = decrypt(cryptoText, strlen(cryptoText), key, initVector, decryptedText);
		decryptedText[len] = '\0';
		if (strcmp(plainText, decryptedText) == 0) {
			printf("The encryption key is: <%s>\n", word);
			break;
		}
    }
}

void handleErrors(void) {
	// ERR_print_errors_fp(stderr);
	// abort();
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