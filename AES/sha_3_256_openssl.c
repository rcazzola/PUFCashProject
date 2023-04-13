// ========================================================================================================
// ========================================================================================================
// ****************************************** sha_3_256_openssl.c *****************************************
// ========================================================================================================
// ========================================================================================================

// ===========================================================================================================
// ===========================================================================================================
// Cyrus's SHA-3 OpenSSL hash wrapper. ASSUME hash input and output buffers are already allocated.

// ====================== SHA-3 =========================
#include <openssl/bn.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

void hash_256(int max_string_len, int hash_in_len_bytes, unsigned char *hash_input, int hash_out_len_bytes, 
   unsigned char *hash_output)
   {
//   int digest_length;
   unsigned int hash_out_byte_len;

//   if ( (digest_length = EVP_MD_size(EVP_sha3_256())) != hash_out_len_bytes )
//      { 
//      printf("hash_256(): SHA-3 digest length %d NOT equal to hash_out_len_bytes %d\n", digest_length, hash_out_len_bytes); 
//      exit(EXIT_FAILURE); 
//      }

   if ( hash_in_len_bytes != hash_out_len_bytes )
      { 
      printf("hash_256(): hash_in_len_bytes %d NOT equal to hash_out_len_bytes %d - FIX ME TO DO MULTIPLE ITERATIONS\n", 
         hash_in_len_bytes, hash_out_len_bytes); 
      exit(EXIT_FAILURE); 
      }

   EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
   if ( EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL) != 1 ) 
      { printf("hash_256(): Could not create SHA3 digest: EVP_DigestInit_ex() error"); exit(EXIT_FAILURE); }

// Digest update can be called multiple times on an input buffer.
    if ( EVP_DigestUpdate(mdctx, hash_input, hash_in_len_bytes) != 1 ) 
       { printf("hash_256(): EVP_DigestUpdate() error"); exit(EXIT_FAILURE); }

// Once hashing is complete, the digest can be read out.
   if ( EVP_DigestFinal_ex(mdctx, hash_output, &hash_out_byte_len) != 1 ) 
      { printf("hash_256(): EVP_DigestFinal_ex() error"); exit(EXIT_FAILURE); }
   EVP_MD_CTX_destroy(mdctx);

   return; 
   }
