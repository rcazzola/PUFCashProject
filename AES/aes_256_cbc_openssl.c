/*****************************************************************************************************
*  Author: Cyrus Minwalla
*  Date: Oct 27, 2021
*  Organization: Bank of Canada
*  Purpose: Provide a high-level interface to OpenSSL's AES 256-bit CBC mode cipher implementation
*  Original: OpenSSL Wiki: https://wiki.openssl6.org/index.php/EVP_Symmetric_Encryption_and_Decryption

******************************************************************************************************/

#include "aes_256_cbc_openssl.h"

//CM - Note ciphertext length is at minimum input length + cipher_block_size - 1
int encrypt_256(unsigned char *key,
            unsigned char *iv, 
            unsigned char *plaintext, int plaintext_len, 
            unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len, ciphertext_len;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); 
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

#ifdef DEBUG
printf("encrypt_256(): First returned ciphertext len %d\n", ciphertext_len); fflush(stdout);
#endif

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

#ifdef DEBUG
printf("encrypt_256(): len of final %d\tFinal ciphertext len %d\n", len, ciphertext_len); fflush(stdout);
#endif

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt_256(unsigned char *key,
            unsigned char *iv, 
            unsigned char *ciphertext, int ciphertext_len, 
            unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len, plaintext_len;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    //Initialise the decryption operation. For 256 bit AES (i.e. a 256 bit key), the IV size is 64 bits    
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

#ifdef DEBUG
printf("decrypt_256(): First returned plaintext len %d\n", plaintext_len); fflush(stdout);
#endif

    //CM - This pads the final block if the input is not an exact multiple of 8 byte blocks 
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

#ifdef DEBUG
printf("decrypt_256(): Final plaintext len %d\n", plaintext_len); fflush(stdout);
#endif

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
/************************************************************************************
 * BLOCK MODE
 ***********************************************************************************/
//CM - Note ciphertext length is at minimum input length + cipher_block_size - 1
EVP_CIPHER_CTX * encrypt_init_AES256(unsigned char *key, unsigned char *iv){
   // Create and initialise the context 
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
   EVP_CIPHER_CTX_set_padding(ctx, 0);
   return ctx;

}

EVP_CIPHER_CTX * decrypt_init_AES256(unsigned char *key, unsigned char *iv){
   // Create and initialise the context 
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
   EVP_CIPHER_CTX_set_padding(ctx, 0);   
   return ctx;
}

void encrypt_block_AES256(EVP_CIPHER_CTX *ctx, unsigned char *key,
            unsigned char *iv, 
            unsigned char *plaintext, int plaintext_len, 
            unsigned char *ciphertext, int *ciphertext_len)
{
    EVP_EncryptUpdate(ctx, ciphertext, ciphertext_len, plaintext, plaintext_len);
    //return ciphertext_len;
}

void encrypt_final_AES256(EVP_CIPHER_CTX *ctx, 
            unsigned char *key,
            unsigned char *iv, 
            unsigned char *plaintext, int plaintext_len, 
            unsigned char *ciphertext, int *ciphertext_len){

    int len;

    EVP_EncryptFinal_ex(ctx, ciphertext, &len);
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

}

void decrypt_block_AES256(EVP_CIPHER_CTX * ctx, unsigned char *key,
            unsigned char *iv, 
            unsigned char *ciphertext, int ciphertext_len, 
            unsigned char *plaintext, int *plaintext_len)
{
   EVP_DecryptUpdate(ctx, plaintext, plaintext_len, ciphertext, ciphertext_len);

}

void decrypt_final_AES256(EVP_CIPHER_CTX * ctx, unsigned char *key,
            unsigned char *iv, 
            unsigned char *ciphertext, int ciphertext_len, 
            unsigned char *plaintext, int *plaintext_len)
{
    //CM - This pads the final block if the input is not an exact multiple of 8 byte blocks 
    int len;

    EVP_DecryptFinal_ex(ctx, plaintext, &len);
    *plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

