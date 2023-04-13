/*****************************************************************************************************
*  Author: Cyrus Minwalla
*  Date: May 6, 2020
*  Organization: Bank of Canada
*  Original: OpenSSL Wiki: https://wiki.openssl6.org/index.php/EVP_Symmetric_Encryption_and_Decryption
*  Purpose: Test openssl AES ECB encryption and decryption
******************************************************************************************************/

//#include "aes_128_ecb_openssl.h"
#include "aes_256_cbc_openssl.h"
int main (void)
{    
    unsigned char key[16] = "0123456789012345";

    unsigned char iv[8] = "01234567";

    unsigned char plaintext[64] = "The quick brown fox jumps over the lazy dog slowly and carefully";
                                                                                
    int plaintext_len = 64; //length in bytes
    unsigned char ciphertext[65];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[65];

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt(key, iv, plaintext, plaintext_len, ciphertext);
    ciphertext[ciphertext_len]='\0';
    //Print the cipher text
    fprintf(stderr, "Ciphertext is:\n");
    BIO_dump_fp(stderr, ciphertext, 64);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(key, iv, ciphertext, ciphertext_len, decryptedtext);
    decryptedtext[decryptedtext_len] = '\0'; //NULL terminator only needed for printing.

    /* Show the decrypted text */
    fprintf(stderr, "Decrypted text is:\n");
    fprintf(stderr, "%s\n", decryptedtext);


    //Test Block Mode Encryption

    unsigned char ciphertext_block[65];

    unsigned char decryptedtext_block[65];
    
    int total_len_enc=0, total_len_dec=0, 
        enc_length=0, dec_length=0;

    fprintf(stderr, "\nTesting Block Mode\n");
    fprintf(stderr, "==================\n");    
        
    EVP_CIPHER_CTX *ctx_enc = encrypt_init_AES256(key, iv);
    for(int i=0; i<4; i++){
        //fprintf(stderr, "Step %d: Total length = %d\n", i, total_len_enc);
        encrypt_block_AES256(ctx_enc, key, iv, &plaintext[i*16], 16, &ciphertext_block[i*16], &enc_length);
        total_len_enc+=enc_length;
    }
    ciphertext_block[total_len_enc]='\0';
    //Print the cipher text
    fprintf(stderr, "Ciphertext is:\n");
    BIO_dump_fp(stderr, ciphertext_block, 64);

    //Test Block Mode Decryption
    EVP_CIPHER_CTX *ctx_dec = decrypt_init_AES256(key, iv);
    for(int i=0; i<4; i++){
        //fprintf(stderr, "Step %d: Total length = %d\n", i, total_len_dec);
        decrypt_block_AES256(ctx_dec, key, iv, ciphertext_block+i*16, 16, decryptedtext_block+i*16, &dec_length);
        total_len_dec+=dec_length;
    }

    decryptedtext_block[total_len_dec] = '\0'; //NULL terminator only needed for printing.

    /* Show the decrypted text */
    fprintf(stderr, "Decrypted text is:\n");
    fprintf(stderr, "%s\n", decryptedtext_block);

    EVP_CIPHER_CTX_free(ctx_enc);

    return 0;
}
