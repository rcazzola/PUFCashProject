
/*****************************************************************************************************
*  Author: Cyrus Minwalla
*  Date: Oct 27, 2021
*  Organization: Bank of Canada
*  Purpose: Provide a high-level interface to OpenSSL's AES 256-bit CBC mode cipher implementation
******************************************************************************************************/


#ifndef AES_256_CBC_OPENSSL_H
#define AES_256_CBC_OPENSSL_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

extern int encrypt_256(unsigned char *key,
            unsigned char *iv, 
            unsigned char *plaintext, 
            int plaintext_len, 
            unsigned char *ciphertext);
extern int decrypt_256(unsigned char *key,
            unsigned char *iv, 
            unsigned char *ciphertext, int ciphertext_len, 
            unsigned char *plaintext);
/************************************************************************************
 * BLOCK MODE
 ***********************************************************************************/
extern EVP_CIPHER_CTX * encrypt_init_AES256(unsigned char *key, unsigned char *iv);
extern EVP_CIPHER_CTX * decrypt_init_AES256(unsigned char *key, unsigned char *iv);
extern void encrypt_block_AES256(EVP_CIPHER_CTX *ctx, unsigned char *key,
            unsigned char *iv, 
            unsigned char *plaintext, int plaintext_len, 
            unsigned char *ciphertext, int *ciphertext_len);
extern void encrypt_final_AES256(EVP_CIPHER_CTX *ctx, 
            unsigned char *key,
            unsigned char *iv, 
            unsigned char *plaintext, int plaintext_len, 
            unsigned char *ciphertext, int *ciphertext_len);
extern void decrypt_block_AES256(EVP_CIPHER_CTX * ctx, unsigned char *key,
            unsigned char *iv, 
            unsigned char *ciphertext, int ciphertext_len, 
            unsigned char *plaintext, int *plaintext_len);
extern void decrypt_final_AES256(EVP_CIPHER_CTX * ctx, unsigned char *key,
            unsigned char *iv, 
            unsigned char *ciphertext, int ciphertext_len, 
            unsigned char *plaintext, int *plaintext_len);


#endif //AES_256_ECB_OPENSSL_H
