// ========================================================================================================
// ========================================================================================================
// *************************************** commonDB_RT_PUFCash.h ******************************************
// ========================================================================================================
// ========================================================================================================
//
//--------------------------------------------------------------------------------
// Company: IC-Safety, LLC and University of New Mexico
// Engineer: Professor Jim Plusquellic
// Exclusive License: IC-Safety, LLC
// Copyright: Univ. of New Mexico
//--------------------------------------------------------------------------------

#include "verifier_common.h"
#include "device_common.h"
#include "commonDB.h"

extern const char *SQL_ListB_insert_into_cmd;
extern const char *SQL_ListB_read_n2_cmd; 
extern const char *SQL_ListB_get_index_cmd;

extern const char *SQL_PreAuthInfo_insert_into_cmd;
extern const char *SQL_PreAuthInfo_get_index_cmd;


// ZeroTrust PROTOCOL
void ZeroTrustAddCustomerATs(int max_string_len, sqlite3 *DB_Trust_AT, int chip_num, 
   int Chlng_num, int ZHK_A_num_bytes, unsigned char *ZHK_A_nonce, unsigned char *nonce, int status);

int ZeroTrustGetCustomerATs(int max_string_len, sqlite3 *DB_Trust_AT, int **chip_num_arr_ptr, 
   int **chlng_num_arr_ptr, int ZHK_A_num_bytes, unsigned char ***ZHK_A_nonce_arr_ptr, 
   unsigned char ***nonce_arr_ptr, int get_only_customer_AT, int customer_chip_num, 
   int return_customer_AT_info, int report_tot_num_ATs_only, int *num_one_customer_ATs_ptr);


// PUF-Cash V3.0
void PUFCashAdd_WRec_Data(int max_string_len, sqlite3 *DB_PUFCash_V3, int AnonChipNum, unsigned char *LLK,
   int LLK_num_bytes, unsigned char *eCt_buffer, unsigned char *heCt_buffer, int eCt_tot_bytes, int num_eCt);

int PUFCashGet_WRec_Data(int max_string_len, sqlite3 *DB_PUFCash_V3, int AnonChipNum, 
   int get_ids_or_eCt_blobs, int **WRec_ids_ptr, int WRec_id, unsigned char **eCt_buffer_ptr, 
   unsigned char **heCt_buffer_ptr, int *num_eCt_ptr);

int PUFCashUpdate_WRec_Data(int max_string_len, sqlite3 *DB_PUFCash_V3, int WRec_id, unsigned char *eCt_buffer,
   unsigned char *heCt_buffer, int eCt_tot_bytes, int num_eCt);

int PUFCashAddLLKChlngInfo(int max_string_len, sqlite3 *DB_PUFCash_V3, int chip_num, int anon_chip_num, 
   unsigned char *Chlng_blob, int Chlng_num_bytes, unsigned char mask[2], int LLK_type, int allow_only_one);

int PUFCashGetLLKChlngInfo(int max_string_len, sqlite3 *DB_PUFCash_V3, int *chip_num_ptr,
   int *anon_chip_num_ptr, unsigned char **Chlng_blob_ptr, int *Chlng_blob_num_bytes_ptr,
   int allow_multiple_LLK, int *Chlng_index_ptr, int status, int check_exists_only, unsigned char mask[2]);


// TTP
int PUFCashAddAcctRec(int max_string_len, sqlite3 *DB_PUFCash_V3, int Alice_chip_num, int TID, 
   int num_eCt, int min_withdraw_increment);

int PUFCashGetAcctRec(int max_string_len, sqlite3 *DB_PUFCash_V3, int Alice_chip_num, int *TID_ptr, 
   int *num_eCt_ptr, int do_update, int update_amt);

