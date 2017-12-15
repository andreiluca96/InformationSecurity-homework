#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


char *INPUT_FILE_NAME1 = "file1.txt";
char *INPUT_FILE_NAME2 = "file2.txt";

char *SHA256_OUTPUT_FILE1 = "h1_sh256";
char *SHA256_OUTPUT_FILE2 = "h2_sh256";

char *MD5_OUTPUT_FILE1 = "h1_md5";
char *MD5_OUTPUT_FILE2 = "h2_md5";


int INPUT_SIZE = 1000;
int SHA256_SIZE = 257;
int MD5_SIZE = 129;

char *applySHA256(char *content);
char *applyMD5(char *content);
int getNumberOfCharacterDifferences(char *input1, char *input2, int inputSize);

void digest_message_SHA256(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len);
void digest_message_MD5(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len);
void handleErrors(void);

void main(int argc, char **argv) {
	FILE *file1 = fopen(INPUT_FILE_NAME1, "r");
	FILE *file2 = fopen(INPUT_FILE_NAME2, "r");
	FILE *file1SHA256 = fopen(SHA256_OUTPUT_FILE1, "w");
	FILE *file2SHA256 = fopen(SHA256_OUTPUT_FILE2, "w");
	FILE *file1MD5 = fopen(MD5_OUTPUT_FILE1, "w");
	FILE *file2MD5 = fopen(MD5_OUTPUT_FILE2, "w");

	char *fileContent1 = malloc(INPUT_SIZE * sizeof(char));
	char *fileContent2 = malloc(INPUT_SIZE * sizeof(char));

	fread(fileContent1, 1, INPUT_SIZE, file1);
	fread(fileContent2, 1, INPUT_SIZE, file2);
	
	printf("%s\n\n", "Inputs:");
	printf("InputFile1: %s", fileContent1);
	printf("InputFile2: %s\n", fileContent2);

	char *sha256Result1 = applySHA256(fileContent1);
	char *sha256Result2 = applySHA256(fileContent2);

	int differences = getNumberOfCharacterDifferences(sha256Result1, sha256Result2, SHA256_SIZE);

	printf("SHA256 for InputFile1:%s\n", sha256Result1);
	printf("SHA256 for InputFile2:%s\n", sha256Result2);
	printf("SHA256 diffrences: %d\n\n", differences);

	fprintf(file1SHA256, "%s %d\n", sha256Result1, differences);
	fprintf(file2SHA256, "%s %d\n", sha256Result2, differences);

	char *md5Result1 = applyMD5(fileContent1);
	char *md5Result2 = applyMD5(fileContent2);

	differences = getNumberOfCharacterDifferences(md5Result1, md5Result2, MD5_SIZE);

	printf("MD5 for InputFile1:%s\n", md5Result1);
	printf("MD5 for InputFile2:%s\n", md5Result2);
	printf("MD5 diffrences: %d\n", differences);

	fprintf(file1MD5, "%s %d\n", md5Result1, differences);
	fprintf(file2MD5, "%s %d\n", md5Result2, differences);
}

void handleErrors(void) {
	ERR_print_errors_fp(stderr);
	abort();
}

char *applySHA256(char *content) {
	char *result = malloc(SHA256_SIZE * sizeof(char));
	SHA256(content, strlen(content), result);

	return result;
}

char *applyMD5(char *content) {
	char *result = malloc(MD5_SIZE * sizeof(char));
	MD5(content, strlen(content), result);

	return result;
}

int getNumberOfCharacterDifferences(char *input1, char *input2, int inputSize) {
	int diffrences = 0;

	for (int i = 0; i < inputSize; i++) {
		if (input1[i] != input2[i]) {
			diffrences++;
		}
	}

	return diffrences;
}

// void digest_message_SHA256(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
// {
// 	EVP_MD_CTX *mdctx;

// 	if((mdctx = EVP_MD_CTX_create()) == NULL)
// 		handleErrors();

// 	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
// 		handleErrors();

// 	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
// 		handleErrors();

// 	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
// 		handleErrors();

// 	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
// 		handleErrors();

// 	EVP_MD_CTX_destroy(mdctx);
// }

// void digest_message_MD5(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
// {
// 	EVP_MD_CTX *mdctx;

// 	if((mdctx = EVP_MD_CTX_create()) == NULL)
// 		handleErrors();

// 	if(1 != EVP_DigestInit_ex(mdctx, EVP_md5(), NULL))
// 		handleErrors();

// 	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
// 		handleErrors();

// 	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_md5()))) == NULL)
// 		handleErrors();

// 	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
// 		handleErrors();

// 	EVP_MD_CTX_destroy(mdctx);
// }

