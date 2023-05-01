// ========================================================================================================
// ========================================================================================================
// ************************************************* ttp.c ************************************************
// ========================================================================================================
// ========================================================================================================
//
//--------------------------------------------------------------------------------
// Company: IC-Safety, LLC and University of New Mexico
// Engineer: Professor Jim Plusquellic
// Exclusive License: IC-Safety, LLC
// Copyright: Univ. of New Mexico
//--------------------------------------------------------------------------------

#include "common.h"
#include "device_hardware.h"
#include "device_common.h"
#include "device_regen_funcs.h"
#include "commonDB_RT_PUFCash.h"

#include <signal.h>
#include <errno.h>

#include <pthread.h>

// ====================== DATABASE STUFF =========================
#include <sqlite3.h>
#include "commonDB.h"

#include "aes_128_ecb_openssl.h"
#include "aes_256_cbc_openssl.h"

// -----------------------------------------
// THREADS
typedef struct
   {
   int task_num;
   int iteration_cnt;
   char *history_file_name;
   SRFHardwareParamsStruct *SHP_ptr;
   int Bank_socket_desc; 
   int Device_socket_desc; 
   char customer_IP[16];
   unsigned char *TTP_session_key;
   int port_number;
   int in_use;
   int client_index;
   int *client_sockets; 
   int num_TTPs;
   int max_string_len; 
   int max_TTP_connect_attempts; 
   ClientInfoStruct *Client_CIArr;
   int my_IP_pos; 
   int exclude_self; 
   int RANDOM;
   int num_eCt_nonce_bytes;
   pthread_mutex_t Thread_mutex;
   pthread_cond_t Thread_cv;
   } ThreadDataType;


// ========================================================================================================
// ========================================================================================================
// CUSTOMER ACCOUNT CREATION: Create accounts for customers with a default amount. First get a list of chip_nums 
// (IDs) from the Bank and create an deposit record for each customer with transaction ID (TID) 0 with 
// deposit_amt (currently $100).

int GetCustomerChipNums(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, unsigned char *TTP_session_key, 
   int Bank_socket_desc, int TID, int deposit_amt)
   {
   char request_str[max_string_len];
   int num_chips, chip_num, Alice_chip_num;

#ifdef DEBUG
printf("\nGetCustomerChipNums(): BEGIN!\n"); fflush(stdout);
#endif

// Sanity check. Customers are forced to deposit multiples of some amount, currently $5.
   if ( (deposit_amt % MIN_WITHDRAW_INCREMENT) != 0 )
      { printf("ERROR: Default deposit Amt %d MUST be divisible by %d!\n", deposit_amt, MIN_WITHDRAW_INCREMENT); exit(EXIT_FAILURE); }

// Tell Bank we want a list of customer chip_nums
   if ( SockSendB((unsigned char *)"TTP-GET-DEVICE-IDS", strlen("TTP-GET-DEVICE-IDS") + 1, Bank_socket_desc) < 0 )
      { printf("ERROR: Failed to send 'TTP-GET-DEVICE-IDS' to Bank!\n"); exit(EXIT_FAILURE); }

// Get and decrypt the number of chip_nums first.
   unsigned char *eReq = Allocate1DUnsignedChar(AES_INPUT_NUM_BYTES);

   if ( SockGetB(eReq, AES_INPUT_NUM_BYTES, Bank_socket_desc) != AES_INPUT_NUM_BYTES  )
      { printf("ERROR: GetCustomerChipNums(): Failed to get 'number of chip_nums' from Bank!\n"); exit(EXIT_FAILURE); }

   decrypt_256(TTP_session_key, SHP_ptr->AES_IV, eReq, AES_INPUT_NUM_BYTES, (unsigned char *)request_str);
   sscanf(request_str, "%d", &num_chips);

// Sanity check
   if ( num_chips <= 0 )
      { printf("ERROR: Number of chips sent by Bank is <= 0: %d!\n", num_chips); return 0; }

// Encrypt and transmit the chip_nums to the TTP.
   for ( chip_num = 0; chip_num < num_chips; chip_num++ )
      {

// Get encrypted Alice_chip_num.
      if ( SockGetB(eReq, AES_INPUT_NUM_BYTES, Bank_socket_desc) != AES_INPUT_NUM_BYTES  )
         { printf("ERROR: GetCustomerChipNums(): Failed to get 'chip_num' from Bank!\n"); exit(EXIT_FAILURE); }

      decrypt_256(TTP_session_key, SHP_ptr->AES_IV, eReq, AES_INPUT_NUM_BYTES, (unsigned char *)request_str);
      sscanf(request_str, "%d", &Alice_chip_num);

#ifdef DEBUG
printf("GetCustomerChipNums(): Adding Alice_chip_num %d to Accounts Table with TID %d\tDeposit Amount %d\n",
   Alice_chip_num, TID, deposit_amt); fflush(stdout);
#endif

// Only allow one record to exist for each customer at this point.
      if ( PUFCashAddAcctRec(max_string_len, SHP_ptr->DB_PUFCash_V3, Alice_chip_num, TID, 
         deposit_amt, MIN_WITHDRAW_INCREMENT) == 0 )
         return 0;
      }

   if ( eReq != NULL )
      free(eReq); 

#ifdef DEBUG
printf("\nGetCustomerChipNums(): DONE!\n"); fflush(stdout);
#endif

   return 1;
   }


// ========================================================================================================
// ========================================================================================================
// The Bank and Alice need to generate a session key THROUGH THIS TTP. The TTP simply acts as a forwarding 
// agent between the Bank and Alice during KEK_SessionKey generation. I need to replicate the actions 
// taken when GenChlngDeliverSpreadFactorsToDevice() within verifier_regen_funcs.c is called, which 
// first calls CommonCore, etc.

void AliceTTPBankSessionKeyGen(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int Alice_socket_desc, 
   int Bank_socket_desc)
   {
   char request_str[max_string_len];
   int use_database_chlngs;
   int num_PIs, num_POs;

printf("AliceTTPBankSessionKeyGen(): CALLED!\n"); fflush(stdout);
#ifdef DEBUG
#endif

// -------------------------------------------
// First get use_database_chlngs, num_PIs and num_POs (control information) that the verifier is using.
   if ( SockGetB((unsigned char *)request_str, max_string_len, Bank_socket_desc) < 0 )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to get 'use_database_chlngs' from Bank!\n"); exit(EXIT_FAILURE); }
   if ( sscanf(request_str, "%d%d%d", &use_database_chlngs, &num_PIs, &num_POs) != 3 )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to extract 'use_database_chlngs, num_PIs and num_POs' from Bank!\n"); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("AliceTTPBankSessionKeyGen(): 'use_database_chlngs' %d\tnum_PIs %d\tnum_POs %d!\n", use_database_chlngs, num_PIs, num_POs); fflush(stdout);
#endif

// -------------------------------------------
// verifier_regeneration.c/GenChlngDeliverSpreadFactorsToDevice()/CommonCore(), Part 1 -> GoSendVectors()
   if ( SockGetB((unsigned char *)request_str, MAX_STRING_LEN, Alice_socket_desc) != 3 )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to get 'GO' from Alice!\n"); exit(EXIT_FAILURE); }
   if ( SockSendB((unsigned char *)request_str, strlen(request_str)+1, Bank_socket_desc) < 0 )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to send 'GO' to Bank!\n"); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("AliceTTPBankSessionKeyGen(): Got and Sent 'GO' '%s'!\n", request_str); fflush(stdout);
#endif

// -------------------------------------------
// verifier_regeneration.c/common.c/GoSendVectors()
// the LFSR seed used by the server.  Always send the seed independent of whether we are generating and sending 
// vectors from the server (here) or if the device will generate them using only the DB_ChallengeGen_seed.
   if ( SockGetB((unsigned char *)request_str, MAX_STRING_LEN, Bank_socket_desc) < 0 )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to get 'DB_ChallengeGen_seed_str' from Bank!\n"); exit(EXIT_FAILURE); }
   if ( SockSendB((unsigned char *)request_str, strlen(request_str)+1, Alice_socket_desc) < 0 )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to send 'DB_ChallengeGen_seed_str' to Alice!\n"); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("AliceTTPBankSessionKeyGen(): Got and Sent 'DB_ChallengeGen_seed_str' '%s'!\n", request_str); fflush(stdout);
#endif

// -------------------------------------------
// verifier_regeneration.c/common.c/SendVectorsAndMask()
// If the server (and Alice) are NOT using client-side database-generated challenges, then we must get the vectors and
// re-transmit them.
   unsigned char *vec = NULL;
   unsigned char *mask = NULL;
   if ( use_database_chlngs == 0 )
      {
      int num_vecs, num_rise_vecs, has_masks;
      int vec_num;

      vec = Allocate1DUnsignedChar(num_PIs/8);
      mask = Allocate1DUnsignedChar(num_POs/8);

// Get num_vecs 
      if ( SockGetB((unsigned char *)request_str, MAX_STRING_LEN, Bank_socket_desc) < 0 )
         { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to get 'vecs string' from Bank!\n"); exit(EXIT_FAILURE); }
      if ( SockSendB((unsigned char *)request_str, strlen(request_str)+1, Alice_socket_desc) < 0 )
         { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to send 'vecs string' to Alice!\n"); exit(EXIT_FAILURE); }

// Parse out the data.
      if ( sscanf(request_str, "%d%d%d", &num_vecs, &num_rise_vecs, &has_masks) != 3 )
         { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to extract 'num_vecs, num_rise_vecs and has_masks' from Bank!\n"); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("AliceTTPBankSessionKeyGen(): use_database_chlngs is 0 %d\tnum_vecs %d\tnum_rise_vecs %d\thas_masks %d!\n",
   use_database_chlngs, num_vecs, num_rise_vecs, has_masks); fflush(stdout);
#endif

// Send first_vecs and second_vecs to remote server.
      for ( vec_num = 0; vec_num < num_vecs; vec_num++ )
         {
         if ( SockGetB(vec, num_PIs/8, Bank_socket_desc) != num_PIs/8 )
            { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to get 'first_vec[%d]' from Bank!\n", vec_num); exit(EXIT_FAILURE); }
         if ( SockSendB(vec, num_PIs/8, Alice_socket_desc) < 0 )
            { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to send 'first_vec[%d]' to Alice!\n", vec_num); exit(EXIT_FAILURE); }

         if ( SockGetB(vec, num_PIs/8, Bank_socket_desc) != num_PIs/8 )
            { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to get 'second_vec[%d]' from Bank!\n", vec_num); exit(EXIT_FAILURE); }
         if ( SockSendB(vec, num_PIs/8, Alice_socket_desc) < 0 )
            { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to send 'second_vec[%d]' to Alice!\n", vec_num); exit(EXIT_FAILURE); }

         if ( has_masks == 1 && SockGetB(mask, num_POs/8, Bank_socket_desc) != num_POs/8 )
            { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to get 'mask[%d]' from Bank!\n", vec_num); exit(EXIT_FAILURE); }
         if ( has_masks == 1 && SockSendB(mask, num_POs/8, Alice_socket_desc) < 0 )
            { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to send 'mask[%d]' to Alice!\n", vec_num); exit(EXIT_FAILURE); }
         }

#ifdef DEBUG
printf("AliceTTPBankSessionKeyGen(): Got and Sent server-side vectors (use_database_chlngs is 0)!\n"); fflush(stdout);
#endif
      }

// -------------------------------------------
// verifier_regeneration.c/GenChlngDeliverSpreadFactorsToDevice()/CommonCore(), Part 1
// XOR_nonce exchange
   unsigned char *nonce = Allocate1DUnsignedChar(SHP_ptr->num_required_nonce_bytes);

#ifdef DEBUG
printf("AliceTTPBankSessionKeyGen(): Get/Send 'verifier_n2/XOR_nonce'!\n"); fflush(stdout);
#endif

   if ( SockGetB(nonce, SHP_ptr->num_required_nonce_bytes, Bank_socket_desc) != SHP_ptr->num_required_nonce_bytes )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to get 'verifier_n2' from Bank!\n"); exit(EXIT_FAILURE); }
   if ( SockSendB(nonce, SHP_ptr->num_required_nonce_bytes, Alice_socket_desc) < 0 )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to send 'verifier_n2' to Alice!\n"); exit(EXIT_FAILURE); }

   if ( SockGetB(nonce, SHP_ptr->num_required_nonce_bytes, Alice_socket_desc) != SHP_ptr->num_required_nonce_bytes )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to get 'XOR_nonce' from Alice!\n"); exit(EXIT_FAILURE); }
   if ( SockSendB(nonce, SHP_ptr->num_required_nonce_bytes, Bank_socket_desc) < 0 )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to send 'XOR_nonce' to Bank!\n"); exit(EXIT_FAILURE); }

// -------------------------------------------
// verifier_regeneration.c/GenChlngDeliverSpreadFactorsToDevice()/CommonCore(), Part 2
// SelectParams (nothing), ComputeSendSpreadFactors(), KEK_SessionKey ALWAYS sends SF (independent of mode).
   unsigned char *SF = Allocate1DUnsignedChar(SHP_ptr->num_SF_bytes);

   int target_attempts = 0;
   while (1)
      {

#ifdef DEBUG
printf("AliceTTPBankSessionKeyGen(): Get/Send 'SF'\tTarget attempts %d!\n", target_attempts); fflush(stdout);
#endif

      if ( SockGetB(SF, SHP_ptr->num_SF_bytes, Bank_socket_desc) != SHP_ptr->num_SF_bytes )
         { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to get 'SF' from Bank!\n"); exit(EXIT_FAILURE); }
      if ( SockSendB(SF, SHP_ptr->num_SF_bytes, Alice_socket_desc) < 0 )
         { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to send 'SF' to Alice!\n"); exit(EXIT_FAILURE); }

      if ( SockGetB((unsigned char *)request_str, max_string_len, Alice_socket_desc) < 0 )
         { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to get 'SPREAD_FACTORS DONE' string from Alice!\n"); exit(EXIT_FAILURE); }
      if ( SockSendB((unsigned char *)request_str, strlen(request_str)+1, Bank_socket_desc) < 0 )
         { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to send 'SPREAD_FACTORS DONE' string to Bank!\n"); exit(EXIT_FAILURE); }

      target_attempts++;
      if ( strcmp(request_str, "SPREAD_FACTORS DONE") == 0 )
         break;
      }

#ifdef DEBUG
printf("AliceTTPBankSessionKeyGen(): DONE 'SF'\tFINAL Target attempts %d!\n", target_attempts); fflush(stdout);
#endif

// -------------------------------------------
// verifier_regeneration.c/KEK_SessionKeyGen()
// Get/Send the XMR_SHD generated by Alice to the Bank.

#ifdef DEBUG
printf("AliceTTPBankSessionKeyGen(): Get/Send 'XHD'!\n"); fflush(stdout);
#endif

   int XMR_num_bytes = target_attempts * SHP_ptr->num_required_PNDiffs/8;
   unsigned char *XMR_SHD = Allocate1DUnsignedChar(XMR_num_bytes);

   if ( SockGetB(XMR_SHD, XMR_num_bytes, Alice_socket_desc) != XMR_num_bytes )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to get 'XMR_SHD' from Alice!\n"); exit(EXIT_FAILURE); }
   if ( SockSendB(XMR_SHD, XMR_num_bytes, Bank_socket_desc) < 0 )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to send 'XMR_SHD' to Bank!\n"); exit(EXIT_FAILURE); }

// -------------------------------------------
// verifier_regeneration.c/KEK_SessionKeyGen()
// Trial encryption
   unsigned char *trial_encryption = Allocate1DUnsignedChar(AES_INPUT_NUM_BITS/8);

#ifdef DEBUG
printf("AliceTTPBankSessionKeyGen(): Get/Send 'trial_encryption'!\n"); fflush(stdout);
#endif

   if ( SockGetB(trial_encryption, AES_INPUT_NUM_BITS/8, Bank_socket_desc) != AES_INPUT_NUM_BITS/8 )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to get 'trial_encryption' from Bank!\n"); exit(EXIT_FAILURE); }
   if ( SockSendB(trial_encryption, AES_INPUT_NUM_BITS/8, Alice_socket_desc) < 0 )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to send 'trial_encryption' to Alice!\n"); exit(EXIT_FAILURE); }

   if ( SockGetB((unsigned char *)request_str, max_string_len, Alice_socket_desc) != 5 )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to get 'PASS/FAIL' string from Alice!\n"); exit(EXIT_FAILURE); }
   if ( SockSendB((unsigned char *)request_str, strlen(request_str)+1, Bank_socket_desc) < 0 )
      { printf("ERROR: AliceTTPBankSessionKeyGen(): Failed to send 'PASS/FAIL' string to Bank!\n"); exit(EXIT_FAILURE); }

   if ( vec != NULL )
      free(vec); 
   if ( mask != NULL )
      free(mask); 
   if ( nonce != NULL )
      free(nonce); 
   if ( SF != NULL )
      free(SF); 
   if ( XMR_SHD != NULL )
      free(XMR_SHD); 
   if ( trial_encryption != NULL )
      free(trial_encryption); 

printf("AliceTTPBankSessionKeyGen(): DONE!\n"); fflush(stdout);
#ifdef DEBUG
#endif

   return;
   }

// Alice Withdrawal
// ========================================================================================================
// ========================================================================================================
// Alice withdrawal operation. Alice authenticates and generates session key with TTP using zero trust. 
// She sends her withdrawal amount. TTP maintains Bank account and checks her balance. If okay, TTP 
// forwards request to Bank.

void AliceWithdrawal(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int Alice_socket_desc,
   pthread_mutex_t *PUFCash_Account_DB_mutex_ptr, pthread_mutex_t *ZeroTrust_AuthenToken_DB_mutex_ptr, 
   unsigned char *SK_TF, int min_withdraw_increment, int Bank_socket_desc, int port_number, int num_CIArr, 
   ClientInfoStruct *Client_CIArr, int My_TTP_index)
   {
   char request_str[max_string_len];

// ===============================
// ===============================
// ZeroTrust Alice-TTP authentication encryption key generation: Start by getting Alice_chip_num so we can get a specific AT 
// from the Bank. Also needed to access her Account Table below.
   int chip_num;

   if ( SockGetB((unsigned char *)request_str, max_string_len, Alice_socket_desc) < 0 )
      { printf("ERROR: AliceWithdrawal(): Error receiving 'Alice_chip_num' from Alice!\n"); exit(EXIT_FAILURE); }
   sscanf(request_str, "%d", &chip_num);

// When Alice makes a withdrawal, her and the TTP carry out ZeroTrust authentication, which means the TTP must have AT
// for the customers. The TTP created AT at startup with the IA, so when customer's request AT, they get the TTP ATs.
// But the TTP has NOT yet fetched AT for the customers (it is NOT menu driver like Alice and Bob where Alice and Bob
// explicitly get AT using a menu option). Get an AT for Alice from the Bank.

// Add an AT for Alice.
    int is_TTP = 1;
    ZeroTrust_GetATs(MAX_STRING_LEN, SHP_ptr, Bank_socket_desc, is_TTP, SK_TF, ZeroTrust_AuthenToken_DB_mutex_ptr, chip_num);

// ZeroTrust: Authentication and session key generation. Alice and Bob determine if each has an AT for the other (set local_AT_status 
// and remote_AT_status) and then get each others chip IDs. 
   int local_AT_status, remote_AT_status, Alice_chip_num, I_am_Alice; 

   I_am_Alice = 0;
   Alice_chip_num = ExchangeIDsConfirmATExists(max_string_len, SHP_ptr, SHP_ptr->chip_num, port_number, I_am_Alice, Alice_socket_desc, 
      &local_AT_status, &remote_AT_status);

// Sanity check
   if ( chip_num != Alice_chip_num )
      { 
      printf("ERROR: AliceWithdrawal(): chip_num sent by Alice to get AT %d differs from chip_num returned by 'ExchangeIDs...' %d\n",
         chip_num, Alice_chip_num); exit(EXIT_FAILURE);
      }

// Return FAILURE if both Alice and Bob do NOT have ATs for each other.
   if ( remote_AT_status == -1 || local_AT_status == -1 )
      {
      printf("WARNING: AliceWithdrawal(): Alice does NOT have an AT for the TTP: remote_AT_status is 0 => %d!\n", remote_AT_status); fflush(stdout);
      return; 
      }

// Sanity checks.
   if ( num_CIArr != 1 || My_TTP_index != 0 )
      { printf("ERROR: AliceWithdrawal(): The number of CIArr is NOT 1 (%d) OR My_TTP_index is not 0 (%d)!\n", num_CIArr, My_TTP_index); exit(EXIT_FAILURE); }

// Now generate a shared key. Assume Alice and TTP have ATs on each other. Exchange the nonces in the ATs, hash them with 
// the ZeroTrust_LLKs to create two ZHK_A_nonces, XOR them for the shared key. The shared key is stored in the Client_CIArr 
// for the follow-up transaction.
   I_am_Alice = 0;
   if ( ZeroTrustGenSharedKey(max_string_len, SHP_ptr, Alice_chip_num, Alice_socket_desc, I_am_Alice, num_CIArr, Client_CIArr, My_TTP_index) == 1 )
      { printf("TTP SUCCEEDED in authenticating Alice and generating a shared key!\n"); fflush(stdout); }
   else
      { 
      printf("TTP FAILED in authenticating Alice and generating a shared key!\n"); fflush(stdout); 
      return;
      }

// Get Alice-TTP shared key for ZeroTrust.
   unsigned char *SK_FA = Client_CIArr[My_TTP_index].AliceBob_shared_key;
   Client_CIArr[My_TTP_index].AliceBob_shared_key = NULL;

// Sanity check.
   if ( SK_FA == NULL )
      { printf("ERROR: AliceWithdrawal(): SK_FA from ZeroTrust authen/key gen is NULL!\n"); exit(EXIT_FAILURE); }

// 1) Get Alice's chip_num and her encrypted withdrawal amount. 
   char *Alice_request_str[max_string_len];
   int Alice_chip_num_encrypted, num_eCt;
   unsigned char *eID_amt = Allocate1DUnsignedChar(AES_INPUT_NUM_BYTES);
// ****************************
// ADD CODE

////////////////AishaNEW////////////////////////////////////
   if ( SockGetB((unsigned char *)eID_amt, max_string_len, Alice_socket_desc) < 0 )
      { printf("ERROR: AliceWithdrawal(): Error receiving 'Alice_anon_chip_num num_eCt' from Alice!\n"); exit(EXIT_FAILURE); }
/////////////////////////////////////****************************

// 2) Decrypt them
// ****************************
// ADD CODE 
// ****************************

   //////////////Rachel//////////////////////
   sscanf(eID_amt, "%d %d", &Alice_chip_num_encrypted, &num_eCt);
   ////////////////////////////////////////

// ===============================
// 3) TTP checks Alice's Bank account and confirms she is allowed to withdraw this amount. NOTE: Use Alice's chip_num
// here (NOT her anonymous chip_num). The Bank gets the anonymous value if you decide to send it. Currently, only 
// one TID allowed at this point.
   int fail_or_pass; 
   int TID_DB, num_eCt_DB;
   int do_update = 0;
   int update_amt = 0;

   pthread_mutex_lock(PUFCash_Account_DB_mutex_ptr);
   PUFCashGetAcctRec(max_string_len, SHP_ptr->DB_PUFCash_V3, Alice_chip_num_encrypted, &TID_DB, &num_eCt_DB, do_update, update_amt); 
   pthread_mutex_unlock(PUFCash_Account_DB_mutex_ptr);

// 4) Check request against balance, send ISF or HSF to Alice.
// ****************************
// ADD CODE

//////////////////AishaNEW///////////////////////
printf("NUM_ECT_DB = %d\n", num_eCt_DB);
if(num_eCt > num_eCt_DB) {
   if ( SockSendB((unsigned char *)"ISF", strlen("ISF")+1, Alice_socket_desc) < 0 )
      { printf("ERROR: AliceWithdrawal(): Failed to send ISF to Alice!\n"); exit(EXIT_FAILURE); }
}
else {
   if ( SockSendB((unsigned char *)"HSF", strlen("HSF")+1, Alice_socket_desc) < 0 )
      { printf("ERROR: AliceWithdrawal(): Failed to send HSF to Alice!\n"); exit(EXIT_FAILURE); }

       do_update = 1;
       update_amt = num_eCt_DB - num_eCt;

      printf("UPDATING HERE\n");
      pthread_mutex_lock(PUFCash_Account_DB_mutex_ptr);
      PUFCashGetAcctRec(max_string_len, SHP_ptr->DB_PUFCash_V3, Alice_anon_chip_num, &TID_DB, &num_eCt_DB, do_update, update_amt); 
      pthread_mutex_unlock(PUFCash_Account_DB_mutex_ptr);
}
/////////////////////////// ****************************

// 5) Start Bank transaction by sending Alice's request amount and chip_num (or anonomous chip_num).
   if ( SockSendB((unsigned char *)"WITHDRAW", strlen("WITHDRAW") + 1, Bank_socket_desc) < 0 ) {
      printf("ERROR: AliceWithdrawal(): Failed to send 'WITHDRAW' to Bank!\n"); exit(EXIT_FAILURE);
   }

// 6) Encrypt eID_amt with SK_TF
// ****************************
// ADD CODE 
// ****************************

////////////////Rachel///////////////////////////
unsigned char *eID_amt_plaintext = Allocate1DUnsignedChar(AES_INPUT_NUM_BYTES);
unsigned char *eID_amt_encrypted = Allocate1DUnsignedChar(AES_INPUT_NUM_BYTES);

if ( SockSendB((unsigned char *)eID_amt, AES_INPUT_NUM_BYTES, Bank_socket_desc) < 0 )
   { printf("ERROR: AliceWithdrawal(): TTP failed to send encrypted eID_amt to BANK\n"); exit(EXIT_FAILURE); }

////////////////////////////////////////////////////

// 7) The Bank and Alice need to generate a session key. Normally Alice contacts the Bank to do this but we cannot
// break the chain of custody here between Alice->FI->TI, so the TTP will act as a forwarding agent between 
// the Bank and Alice during KEK_SessionKeyGen process.
   AliceTTPBankSessionKeyGen(max_string_len, SHP_ptr, Alice_socket_desc, Bank_socket_desc);

   ////////////////////////Rachel//////////////////////////////
   unsigned char *LLK = Allocate1DUnsignedChar(SHP_ptr->ZHK_A_num_bytes);


  if ( SockGetB((unsigned char *)LLK, SHP_ptr->ZHK_A_num_bytes, Alice_socket_desc) < 0 )
      { printf("ERROR: AliceWithdrawal(): Failed to get LLK from Alice!\n"); exit(EXIT_FAILURE); }
   
   printf("LLK on TTP side = %s\n", LLK);


    if ( SockSendB((unsigned char *)LLK, SHP_ptr->ZHK_A_num_bytes, Bank_socket_desc) < 0 )
      { printf("ERROR: AliceWithdrawal(): TTP failed to send ZeroTrust_LLK to Bank!\n"); exit(EXIT_FAILURE); }
   //////////////////////////////////////////////////////////////


// ===============================
// 8) Get ACK/NAK from Bank
   if ( SockGetB((unsigned char *)request_str, max_string_len, Bank_socket_desc) != 4 )
      { printf("ERROR: AliceWithdrawal(): Failed to get 'ACK/NAK' from Bank!\n"); exit(EXIT_FAILURE); }
   if ( strcmp(request_str, "NAK") == 0 )
      { 
      printf("WARNING: AliceWithdrawal(): Bank sent NAK -- cancelling transaction!\n"); 
      return; 
      }

// 9) Get eeCt and heeCt and forward to Alice.
// ****************************
// ADD CODE 
// ****************************

   ////////////////////////Rachel/////////////////////
   int eCt_tot_bytes = num_eCt * HASH_IN_LEN_BYTES;

   unsigned char *eeCt_buffer = Allocate1DUnsignedChar(eCt_tot_bytes);
   unsigned char *eheCt_buffer = Allocate1DUnsignedChar(eCt_tot_bytes);


   printf("num_eCt in TTP = %d\n", num_eCt);
   printf("SIZE OF eCt_tot_bytes = %d\n", eCt_tot_bytes);

   //get eeCt and eheCt from bank
   printf("--------WAITING FOR eeCt/eheCT--------\n");

   if ( SockGetB((unsigned char *)eeCt_buffer, eCt_tot_bytes, Bank_socket_desc) < 0 )
      { printf("ERROR: AliceWithdrawal(): Failed to get 'eeCt_buffer' from Bank!\n"); exit(EXIT_FAILURE); }

   if ( SockGetB((unsigned char *)eheCt_buffer, eCt_tot_bytes, Bank_socket_desc) < 0 )
      { printf("ERROR: AliceWithdrawal(): Failed to get 'eheCt_buffer' from Bank!\n"); exit(EXIT_FAILURE); }


   //send eeCt and eheCt to Alice
   if ( SockSendB((unsigned char *)eeCt_buffer, eCt_tot_bytes, Alice_socket_desc) < 0 )
      { printf("ERROR: AliceWithdrawal(): TTP failed to send encrypted eeCt_buffer to Alice\n"); exit(EXIT_FAILURE); }

   if ( SockSendB((unsigned char *)eheCt_buffer, eCt_tot_bytes, Alice_socket_desc) < 0 )
      { printf("ERROR: AliceWithdrawal(): TTP failed to send encrypted eheCt_buffer to Alice\n"); exit(EXIT_FAILURE); }
      printf("--------DONE WAITING FOR eeCt/eheCT--------\n");

  /////////////////////////////////////////////////////////
   return;
   }



// ********************
// ADD CODE 
// ********************

// Alice Account
// ========================================================================================================
// ========================================================================================================
// Alice account operation. Alice authenticates and generates session key with TTP using zero trust. 
// She sends her withdrawal amount. TTP maintains Bank account and checks her balance. If okay, TTP 
// forwards request to Bank.

/////////////////////Aisha/////////////////////////////
void AliceAccount(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int Alice_socket_desc,
   pthread_mutex_t *PUFCash_Account_DB_mutex_ptr, pthread_mutex_t *ZeroTrust_AuthenToken_DB_mutex_ptr, 
   unsigned char *SK_TF, int min_withdraw_increment, int Bank_socket_desc, int port_number, int num_CIArr, 
   ClientInfoStruct *Client_CIArr, int My_TTP_index)
   {
   char request_str[max_string_len];

printf("AliceAccount(): BEGIN!\n"); fflush(stdout);
#ifdef DEBUG
#endif

// ===============================
// ===============================
// ZeroTrust Alice-TTP authentication encryption key generation: Start by getting Alice_chip_num so we can get a specific AT 
// from the Bank. Also needed to access her Account Table below.
int chip_num;

printf("AliceAccount(): Getting chip_num from Alice so we can fetch an AT for Alice from the Bank!\n"); fflush(stdout); 
#ifdef DEBUG
#endif
   if ( SockGetB((unsigned char *)request_str, max_string_len, Alice_socket_desc) < 0 )
      { printf("ERROR: AliceAccount(): Error receiving 'Alice_chip_num' from Alice!\n"); exit(EXIT_FAILURE); }
   sscanf(request_str, "%d", &chip_num);

// When Alice makes a withdrawal, her and the TTP carry out ZeroTrust authentication, which means the TTP must have AT
// for the customers. The TTP created AT at startup with the IA, so when customer's request AT, they get the TTP ATs.
// But the TTP has NOT yet fetched AT for the customers (it is NOT menu driver like Alice and Bob where Alice and Bob
// explicitly get AT using a menu option). Get an AT for Alice from the Bank.

printf("AliceAccount(): TTP getting AT for Alice's chip_num %d!\n", chip_num); fflush(stdout); 
#ifdef DEBUG
#endif

// Add an AT for Alice.
    int is_TTP = 1;
    ZeroTrust_GetATs(MAX_STRING_LEN, SHP_ptr, Bank_socket_desc, is_TTP, SK_TF, ZeroTrust_AuthenToken_DB_mutex_ptr, chip_num);

// ZeroTrust: Authentication and session key generation. Alice and Bob determine if each has an AT for the other (set local_AT_status 
// and remote_AT_status) and then get each others chip IDs. 
   int local_AT_status, remote_AT_status, Alice_chip_num, I_am_Alice; 

printf("AliceAccount(): TTP carrying out ZeroTrust protocol with Alice (chip_num %d)!\n", chip_num); fflush(stdout); 
#ifdef DEBUG
#endif
   
   I_am_Alice = 0;
   Alice_chip_num = ExchangeIDsConfirmATExists(max_string_len, SHP_ptr, SHP_ptr->chip_num, port_number, I_am_Alice, Alice_socket_desc, 
      &local_AT_status, &remote_AT_status);

// Sanity check
   if ( chip_num != Alice_chip_num )
      { 
      printf("ERROR: AliceAccount(): chip_num sent by Alice to get AT %d differs from chip_num returned by 'ExchangeIDs...' %d\n",
         chip_num, Alice_chip_num); exit(EXIT_FAILURE);
      }

// Return FAILURE if both Alice and Bob do NOT have ATs for each other.
   if ( remote_AT_status == -1 || local_AT_status == -1 )
      {
      printf("WARNING: AliceAccount(): Alice does NOT have an AT for the TTP: remote_AT_status is 0 => %d!\n", remote_AT_status); fflush(stdout);
      return; 
      }

printf("AliceAccount(): Exchange ID's completed successfully with Alice's chip_num %d!\n", Alice_chip_num); fflush(stdout);
#ifdef DEBUG
#endif

// Sanity checks.
   if ( num_CIArr != 1 || My_TTP_index != 0 )
      { printf("ERROR: AliceAccount(): The number of CIArr is NOT 1 (%d) OR My_TTP_index is not 0 (%d)!\n", num_CIArr, My_TTP_index); exit(EXIT_FAILURE); }

// Now generate a shared key. Assume Alice and TTP have ATs on each other. Exchange the nonces in the ATs, hash them with 
// the ZeroTrust_LLKs to create two ZHK_A_nonces, XOR them for the shared key. The shared key is stored in the Client_CIArr 
// for the follow-up transaction.
   I_am_Alice = 0;
   if ( ZeroTrustGenSharedKey(max_string_len, SHP_ptr, Alice_chip_num, Alice_socket_desc, I_am_Alice, num_CIArr, Client_CIArr, My_TTP_index) == 1 )
      { printf("TTP SUCCEEDED in authenticating Alice and generating a shared key!\n"); fflush(stdout); }
   else
      { 
      printf("TTP FAILED in authenticating Alice and generating a shared key!\n"); fflush(stdout); 
      return;
      }

// Get Alice-TTP shared key for ZeroTrust.
   unsigned char *SK_FA = Client_CIArr[My_TTP_index].AliceBob_shared_key;
   Client_CIArr[My_TTP_index].AliceBob_shared_key = NULL;

// Sanity check.
   if ( SK_FA == NULL )
      { printf("ERROR: AliceAccount(): SK_FA from ZeroTrust authen/key gen is NULL!\n"); exit(EXIT_FAILURE); }

int TID = 0;
int num_eCt = 0;

// Only allow one record to exist for each customer at this point.
      if ( PUFCashGetAcctRec(max_string_len, SHP_ptr->DB_PUFCash_V3, Alice_chip_num, &TID, 
         &num_eCt, 0, 0) == 0 ) {

         return;
      }


printf("Account Data Retrieved with TID = %d and Amount = %d\n", TID, num_eCt); fflush(stdout);

char num_eCt_str[max_string_len];
sprintf(num_eCt_str, "%d", num_eCt);

if ( SockSendB((unsigned char *)num_eCt_str, strlen(num_eCt_str)+1, Alice_socket_desc) < 0 )
      { printf("ERROR: Failed to send data from FI to Alice\n"); }
else { 
   printf("SUCCESS: Sent data from FI to Alice\n");
   int amount;
   sscanf(num_eCt_str, "%d", &amount);
   int cents = amount % 100;
   int dollars = amount / 100;
   printf("Account Balance: $%d.%02d\n", dollars, cents);
   // printf("Account Balance: %s\n", num_eCt_str);
}

printf("AliceAccount(): DONE!\n"); fflush(stdout);
#ifdef DEBUG
#endif

   return;
   }


////////////////////////////////////////////////////////////
// ========================================================================================================
// ========================================================================================================
// TTP thread.

void TTPThread(ThreadDataType *ThreadDataPtr)
   {
   SRFHardwareParamsStruct *SHP_ptr;
   int Device_socket_desc;
   unsigned char *SK_TF;
   int Bank_socket_desc;
   int client_index;
   int *client_sockets;
   int max_string_len;

   char command_str[MAX_STRING_LEN];

   static pthread_mutex_t PUFCash_Account_DB_mutex = PTHREAD_MUTEX_INITIALIZER;
   static pthread_mutex_t ZeroTrust_AuthenToken_DB_mutex = PTHREAD_MUTEX_INITIALIZER;

printf("TTPThread: CREATED!\t(Task %d\tIterationCnt %d)\n", ThreadDataPtr->task_num, ThreadDataPtr->iteration_cnt); fflush(stdout);
#ifdef DEBUG
#endif

   while (1)
      {

// Sleep waiting for the main program to receive connect request from Alice or a TTP, and assign a Device_socket_desc
// No CPU cycles are wasted here in a busy wait, which is important when we query TTPs for performance information.
      pthread_mutex_lock(&(ThreadDataPtr->Thread_mutex));
      while ( ThreadDataPtr->in_use == 0 )
         pthread_cond_wait(&(ThreadDataPtr->Thread_cv), &(ThreadDataPtr->Thread_mutex));
      pthread_mutex_unlock(&(ThreadDataPtr->Thread_mutex));

struct timeval t1, t2;
long elapsed; 
gettimeofday(&t2, 0);
#ifdef DEBUG
#endif

//      task_num = ThreadDataPtr->task_num;
//      iteration_cnt = ThreadDataPtr->iteration_cnt;

// Get local copies/pointers from the data structure.
      SHP_ptr = ThreadDataPtr->SHP_ptr;
      Device_socket_desc = ThreadDataPtr->Device_socket_desc;
      SK_TF = ThreadDataPtr->TTP_session_key;
      Bank_socket_desc = ThreadDataPtr->Bank_socket_desc;
      client_index = ThreadDataPtr->client_index;
      client_sockets = ThreadDataPtr->client_sockets;
      max_string_len = ThreadDataPtr->max_string_len;

printf("\nTASK BEGIN: ID %d\tClient index %d\tDevice socket descriptor %d\tIterationCnt %d\n", ThreadDataPtr->task_num, 
   client_index, Device_socket_desc, ThreadDataPtr->iteration_cnt); fflush(stdout);
#ifdef DEBUG
#endif

// ====================================================================================================
// ====================================================================================================
// Originally did this but eliminated Bank requests in V3.0. These should never happen.
      if ( client_index == 0 )
         {
         printf("Bank request!\n"); fflush(stdout); 
         exit(EXIT_FAILURE); 
         }

// All socket activity is from Alice or TTP (none ever from the Bank). Get the COMMAND string. 
#ifdef DEBUG
printf("Alice request!\n"); fflush(stdout); 
#endif
      if ( SockGetB((unsigned char *)command_str, max_string_len, Device_socket_desc) < 0 )
         { printf("ERROR: TTPThread(): Error receiving 'command_str' from Alice!\n"); exit(EXIT_FAILURE); }

printf("\tProcessing command '%s'\tID %d\tITERATION %d\n", command_str, ThreadDataPtr->task_num, ThreadDataPtr->iteration_cnt); fflush(stdout);
#ifdef DEBUG
#endif

// =========================
// =========================
// PUF-Cash 3.0: Alice withdrawal. 
      if ( strcmp(command_str, "ALICE-WITHDRAWAL") == 0 )
         AliceWithdrawal(max_string_len, SHP_ptr, Device_socket_desc, &PUFCash_Account_DB_mutex, &ZeroTrust_AuthenToken_DB_mutex, SK_TF, 
            MIN_WITHDRAW_INCREMENT, Bank_socket_desc, ThreadDataPtr->port_number, ThreadDataPtr->num_TTPs, ThreadDataPtr->Client_CIArr, 
            ThreadDataPtr->my_IP_pos);
// Aisha
// PUF-Cash 3.0: Alice account. 
      else if ( strcmp(command_str, "ALICE-ACCOUNT") == 0 ) {
         // printf("Here in condition 2"); fflush(stdout);
         AliceAccount(max_string_len, SHP_ptr, Device_socket_desc, &PUFCash_Account_DB_mutex, &ZeroTrust_AuthenToken_DB_mutex, SK_TF, 
            MIN_WITHDRAW_INCREMENT, Bank_socket_desc, ThreadDataPtr->port_number, ThreadDataPtr->num_TTPs, ThreadDataPtr->Client_CIArr, 
            ThreadDataPtr->my_IP_pos);
      }

// =========================
// =========================
// Unknown message type
      else
         { printf("Unknown message '%s'\n", command_str); exit(EXIT_FAILURE); }


// ====================================================================================================
// Close the socket descriptor from another TTP or from Alice, BUT DO NOT CLOSE THE Bank socket descriptor at index 0.
      if ( client_index != 0 )
         {

printf("Closing Device socket %d\n", Device_socket_desc); fflush(stdout);
#ifdef DEBUG
#endif

         close(Device_socket_desc);

// Restore activity on this client_socket_descriptor. Note this is a shared array among the threads but no semaphore needed here because 
// each thread updates a unique element given by client_index.
         client_sockets[client_index] = 0;
         }

// Else restore the Bank socket descriptor on client socket 0. We assigned -1 to it when the thread was created to prevent main() 
// OpenMultipleSocketServer() from processing activity while we service the request.
      else
         client_sockets[client_index] = Bank_socket_desc;

gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t2.tv_sec)*1000000 + t1.tv_usec-t2.tv_usec; printf("\tElapsed: Command '%s'\tID %d\tITERATION %d\t%ld us\n\n", 
   command_str, ThreadDataPtr->task_num, ThreadDataPtr->iteration_cnt, (long)elapsed); fflush(stdout);
#ifdef DEBUG
#endif

// Indicate to the parent that this thread is available for reassignment.
      pthread_mutex_lock(&(ThreadDataPtr->Thread_mutex));
      ThreadDataPtr->in_use = 0;
      pthread_mutex_unlock(&(ThreadDataPtr->Thread_mutex));
      }

// Nope -- this generates some type of library required message -- an error. I'm not destroying threads any longer -- they get created and run forever.
//   pthread_exit(NULL);

// We never return;
   return;
   }


// ========================================================================================================
// ========================================================================================================
// ========================================================================================================
// MEM LEAK
//#include <mcheck.h>

#define MAX_THREADS 20
SRFHardwareParamsStruct SHP[1];

ThreadDataType ThreadDataArr[MAX_THREADS] = {
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   {0, 0, NULL, NULL, 0, 0, "", NULL, 0, 0, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER},
   };

int main(int argc, char *argv[]) 
   {
   volatile unsigned int *CtrlRegA;
   volatile unsigned int *DataRegA;
   unsigned int ctrl_mask;

   SRFHardwareParamsStruct *SHP_ptr;

   char *history_file_name;
   char *Bank_IP;
   char *client_IP;
   int *client_sockets;

   int TTP_socket_desc = 0;
   int Device_socket_desc = 0;
   char *TTP_IP;

   ClientInfoStruct *Client_CIArr; 
   int num_TTPs = 0;

   int Bank_socket_desc;

   int client_index;
   int SD;

   int RANDOM;

   int nonce_base_address;
   int num_eCt_nonce_bytes;
   int num_KEK_authen_nonce_bytes; 

   int port_number; 

   int gen_session_key;

   unsigned char *TTP_session_key; 
   int my_IP_pos;

   int thread_num;
   int exclude_self;

   int fix_params; 
   int num_sams;

   int num_PIs;
   int num_POs;

   int DUMP_BITSTRINGS;
   int DEBUG_FLAG;

   int PCR_or_PBD_or_PO; 

// The PL-side TRNG_LFSR is 64 bits. Note that we currently only suport loading the low-order 8-bits of the seed register below.
   unsigned char TRNG_LFSR_seed;

// ====================== DATABASE STUFF =========================
   sqlite3 *DB_Challenges;
   int rc;
   char *DB_name_Challenges;
   Allocate1DString(&DB_name_Challenges, MAX_STRING_LEN);
   int use_database_chlngs; 

   char *Netlist_name;
   char *Synthesis_name;
   char *ChallengeSetName; 

   int design_index;
   int num_PIs_DB, num_POs_DB;

   int ChallengeGen_seed; 

// Trust protocol
   sqlite3 *DB_Trust_AT;
   char *DB_name_Trust_AT;
   Allocate1DString(&DB_name_Trust_AT, MAX_STRING_LEN);

// PUF-Cash V3.0 protocol 
   sqlite3 *DB_PUFCash_V3;
   char *DB_name_PUFCash_V3;
   Allocate1DString(&DB_name_PUFCash_V3, MAX_STRING_LEN);

   float command_line_SC;

   Allocate1DString(&TTP_IP, IP_LENGTH);
   Allocate1DString(&Bank_IP, MAX_STRING_LEN);
   Allocate1DString(&history_file_name, MAX_STRING_LEN);


// ======================================================================================================================
// COMMAND LINE
// ======================================================================================================================
   if ( argc != 3 )
      {
      printf("ERROR: Parameters: Device IP (192.168.1.9) -- Bank IP (192.168.1.20)\n");
      exit(EXIT_FAILURE);
      }

   strcpy(TTP_IP, argv[1]);
   strcpy(Bank_IP, argv[2]);

   fix_params = 0;
   num_sams = 4;
   PCR_or_PBD_or_PO = 0;
   command_line_SC = 1.0;

// Sanity checks
   if ( fix_params != 0 && fix_params != 1 )
      { printf("ERROR: 'fix_params' MUST be 0 or 1!\n"); exit(EXIT_FAILURE); }

   if ( num_sams != 1 && num_sams != 4 && num_sams != 8 && num_sams != 16 )
      { printf("ERROR: 'num_sams' MUST be 1, 4, 8 or 16!\n"); exit(EXIT_FAILURE); }

   if ( PCR_or_PBD_or_PO != 0 && PCR_or_PBD_or_PO != 1 && PCR_or_PBD_or_PO != 2 )
      { printf("ERROR: 'PCR_or_PBD_or_PO' MUST be 0, 1 or 2!\n"); exit(EXIT_FAILURE); }

// Upper limit is arbitrary -- they never get this big -- 3.2 looks to be the max.
   if ( command_line_SC <= 0.0 || command_line_SC > (float)MAX_SCALING_VALUE )
      { printf("ERROR: 'command_line_SC' MUST be >= 0.0 and <= %f -- FIX ME!\n", (float)MAX_SCALING_VALUE); exit(EXIT_FAILURE); }

// This doesn't work yet -- still using command line value.
//   GetMyIPAddr(MAX_STRING_LEN, "eth0", &TTP_IP);

   Allocate1DString(&client_IP, MAX_STRING_LEN);
   client_sockets = Allocate1DIntArray(MAX_CLIENTS);

   Allocate1DString((char **)(&Netlist_name), MAX_STRING_LEN);
   Allocate1DString((char **)(&Synthesis_name), MAX_STRING_LEN);
   Allocate1DString((char **)(&ChallengeSetName), MAX_STRING_LEN);

// ====================================================== PARAMETERS ====================================================
   strcpy(DB_name_Challenges, "Challenges.db");
   strcpy(Netlist_name, "SR_RFM_V4_TDC");
   strcpy(Synthesis_name, "SRFSyn1");
   strcpy(ChallengeSetName, "Master1_OptKEK_TVN_0.00_WID_1.75");

   strcpy(DB_name_Trust_AT, "AuthenticationToken.db");

   strcpy(DB_name_PUFCash_V3, "PUFCash_V3.db");

// Must be set to 0 until I fully integrate this into all of the primitives.
   use_database_chlngs = 0;
   ChallengeGen_seed = 1;

   char AES_IV[AES_IV_NUM_BYTES] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

// For Customer Acct Creation: Default transaction ID. We allow only one record for now.
   int TID = 0;

// Default deposit amount for each customer ($100). Must be divisible by MIN_WITHDRAW_INCREMENT (500 or $5).
   int default_deposit_amt = 10000;

// The PL-side TRNG_LFSR is 64 bits. 
   TRNG_LFSR_seed = 1;

   strcpy(history_file_name, "TTP0_history.txt");

// Used only in the multiple TTP model.
   exclude_self = 0;

// NOTE: ASSUMPTION:
//    NUM_XOR_NONCE_BYTES   <=  num_eCt_nonce_bytes   ==   SE_TARGET_NUM_KEY_BITS/8   <=   NUM_REQUIRED_PNDIFFS/8
//           8                         16                            32                              256
// We always use 8 bytes for the XOR_nonce (NUM_XOR_NONCE_BYTES) to SelectParams. My plan is to use 16 byte nonces
// (num_eCt_nonce_bytes), 32 bytes AES session keys (256 bits for SE_TARGET_NUM_KEY_BITS) and NUM_REQUIRED_PNDIFFS are always 
// 2048/16 = 256. 
   num_eCt_nonce_bytes = ECT_NUM_BYTES;
   num_KEK_authen_nonce_bytes = KEK_AUTHEN_NUM_NONCE_BITS/8; 

// Base address, can be eliminated -- always 0. 
   nonce_base_address = 0;

   port_number = 8888;

// These depend on the function unit. For SR_RFM, it's 784 and 64
   num_PIs = NUM_PIS;
   num_POs = NUM_POS;

// MEM LEAK -- also run 'export MALLOC_TRACE=./memtrace.txt' at the command line.
//   mtrace();

// Enable/disable debug information.
   DUMP_BITSTRINGS = 0;
   DEBUG_FLAG = 0;
// ====================================================== PARAMETERS ====================================================
// Sanity check. With SF stored in (signed char) now, we can NOT allow TrimCodeConstant to be any larger than 64. See
// log notes on 1_1_2022.
   if ( TRIMCODE_CONSTANT > 64 )
      { printf("ERROR: main(): TRIMCODE_CONSTANT %d MUST be <= 64\n", TRIMCODE_CONSTANT); exit(EXIT_FAILURE); }

// We also assume that the SHA-3 hash input and output are the same size as the AK_A/HK_As, which must be the same size as 
// the KEK key (since we use KEK_Regen() below to regenerate it). 
   if ( HASH_IN_LEN_BITS != KEK_TARGET_NUM_KEY_BITS || HASH_OUT_LEN_BITS != KEK_TARGET_NUM_KEY_BITS )
      { 
      printf("ERROR: main(): HASH_IN_LEN_BITS %d MUST be equal to HASH_OUT_LEN_BIT %d MUST be equal to KEK_TARGET_NUM_KEY_BITS %d\n", 
         HASH_IN_LEN_BITS, HASH_OUT_LEN_BITS, KEK_TARGET_NUM_KEY_BITS); exit(EXIT_FAILURE); 
      }

// Sanity check, constraint must be honored because of space allocations.
//    NUM_XOR_NONCE_BYTES   <=  num_eCt_nonce_bytes   <=   SE_TARGET_NUM_KEY_BITS/8   <=   NUM_REQUIRED_PNDIFFS/8
//           8                         16                            32                              256
   if ( !(NUM_XOR_NONCE_BYTES <= num_eCt_nonce_bytes && num_eCt_nonce_bytes <= SE_TARGET_NUM_KEY_BITS/8 && 
      SE_TARGET_NUM_KEY_BITS/8 <= NUM_REQUIRED_PNDIFFS/8) )
      { 
      printf("ERROR: Constraint violated: NUM_XOR_NONCE_BYTES %d <= num_eCt_nonce_bytes %d && \n\
         num_eCt_nonce_bytes %d == SE_TARGET_NUM_KEY_BITS/8 %d <= NUM_REQUIRED_PNDIFFS/8 %d\n",
         NUM_XOR_NONCE_BYTES, num_eCt_nonce_bytes, num_eCt_nonce_bytes, SE_TARGET_NUM_KEY_BITS/8, NUM_REQUIRED_PNDIFFS/8);
      exit(EXIT_FAILURE);
      }

   printf("Parameters: This Device IP %s\tBank IP %s\tFIX PARAMS %d\tNum Sams %d\tPCR/PBD/PO %d\n", TTP_IP, Bank_IP, fix_params, 
      num_sams, PCR_or_PBD_or_PO); fflush(stdout);

// The number of samples is set BELOW after CtrlRegA is given an address.
   ctrl_mask = 0;

// For handling Ctrl-C. We MUST exit gracefully to keep the hardware from quitting at a point where the
// fine phase of the MMCM is has not be set back to 0. If it isn't, then re-running this program will
// likely fail because my local fine phase register (which is zero initially after a RESET) is out-of-sync 
// with the MMCM phase (which is NOT zero).
   signal(SIGINT, intHandler);

// When we save output file, this tells us what we used.
   printf("PARAMETERS: SE Target Num Bits %d\n\n", SE_TARGET_NUM_KEY_BITS);

// Open up the memory mapped device so we can access the GPIO registers.
   int fd = open("/dev/mem", O_RDWR|O_SYNC);

   if (fd < 0) 
      { printf("ERROR: /dev/mem could NOT be opened!\n"); exit(EXIT_FAILURE); }

// Add 2 for the DataReg (for an SpreadFactor of 8 bytes for 32-bit integer variables)
   DataRegA = mmap(0, getpagesize(), PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPIO_0_BASE_ADDR);
   CtrlRegA = DataRegA + 2;

// ********************************************************************************************************** 
// !!!!!!!!!! FOR TDC, THE LOW ORDER 4 BITS at RESET are dedicated to the TimingDivisor and MUST BE 0.
// Do a hardware reset. NOTE: We also load the initial seed for the TRNG here. Only the low-order 8 bits. 
//
// 1_23_2022: Inspected /borg_data/FPGAs/ZYBO/SR_RFM/Verilog/COMMON/Top_TDC.v (and Top_MMCM.v) -- looks
// like I load TRNG_CP_LFSR_seed[7:0] with GPIO bits [15:8] at RESET in TRNG.v,
//    assign TRNG_CP_LFSR_seed[7:0] = GPIO_Ins_tri_i[`WORD_SIZE_NB-1:8];
//
//   *CtrlRegA = ctrl_mask | (1 << OUT_CP_RESET) | (unsigned int)(TRNG_LFSR_seed < 8);
   *CtrlRegA = ctrl_mask | (1 << OUT_CP_RESET);
   *CtrlRegA = ctrl_mask;
   usleep(10000);

// Set the number of samples
   if ( num_sams == 1 )
      ctrl_mask = (0 << OUT_CP_NUM_SAM1) | (0 << OUT_CP_NUM_SAM0);
   else if ( num_sams == 4 )
      ctrl_mask = (0 << OUT_CP_NUM_SAM1) | (1 << OUT_CP_NUM_SAM0);
   else if ( num_sams == 8 )
      ctrl_mask = (1 << OUT_CP_NUM_SAM1) | (0 << OUT_CP_NUM_SAM0);
   else if ( num_sams == 16 )
      ctrl_mask = (1 << OUT_CP_NUM_SAM1) | (1 << OUT_CP_NUM_SAM0);
   else
      { printf("ERROR: Number of samples MUST be 1, 4, 8 or 16!\n"); exit(EXIT_FAILURE); }

   *CtrlRegA = ctrl_mask;

// ====================== DATABASE STUFF =========================
   rc = sqlite3_open(":memory:", &DB_Challenges);
   if ( rc != 0 )
      { printf("Failed to open Challenge Database: %s\n", sqlite3_errmsg(DB_Challenges)); sqlite3_close(DB_Challenges); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("Reading filesystem database '%s' into memory!\n", DB_name_Challenges); fflush(stdout);
#endif

   if ( LoadOrSaveDb(DB_Challenges, DB_name_Challenges, 0) != 0 )
      { printf("Failed to open and copy into memory '%s': ERR: %s\n", DB_name_Challenges, sqlite3_errmsg(DB_Challenges)); sqlite3_close(DB_Challenges); exit(EXIT_FAILURE); }

// Get the PUFDesign parameters from the database. 
   if ( GetPUFDesignParams(MAX_STRING_LEN, DB_Challenges, Netlist_name, Synthesis_name, &design_index, &num_PIs_DB, &num_POs_DB) != 0 )
      { printf("ERROR: PUFDesign index NOT found for '%s', '%s'!\n", Netlist_name, Synthesis_name); exit(EXIT_FAILURE); }

// Sanity check
   if ( num_PIs_DB != num_PIs || num_POs_DB != num_POs )
      { 
      printf("ERROR: Number of PIs %d or POs %d in database do NOT match those in common.h %d and %d!\n", num_PIs_DB, num_POs_DB, num_PIs, num_POs); 
      exit(EXIT_FAILURE); 
      }

// Trust protocol 
   rc = sqlite3_open(":memory:", &DB_Trust_AT);
   if ( rc != 0 )
      { printf("Failed to open Trust_AT Database: %s\n", sqlite3_errmsg(DB_Trust_AT)); sqlite3_close(DB_Trust_AT); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("Reading filesystem database '%s' into memory!\n", DB_name_Trust_AT); fflush(stdout);
#endif

   if ( LoadOrSaveDb(DB_Trust_AT, DB_name_Trust_AT, 0) != 0 )
      { printf("Failed to open and copy into memory '%s': ERR: %s\n", DB_name_Trust_AT, sqlite3_errmsg(DB_Trust_AT)); sqlite3_close(DB_Trust_AT); exit(EXIT_FAILURE); }

// PUF-Cash V3.0
   rc = sqlite3_open(":memory:", &DB_PUFCash_V3);
   if ( rc != 0 )
      { printf("Failed to open PUFCash_V3 Database: %s\n", sqlite3_errmsg(DB_PUFCash_V3)); sqlite3_close(DB_PUFCash_V3); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("Reading filesystem database '%s' into memory!\n", DB_name_PUFCash_V3); fflush(stdout);
#endif

   if ( LoadOrSaveDb(DB_PUFCash_V3, DB_name_PUFCash_V3, 0) != 0 )
      { printf("Failed to open and copy into memory '%s': ERR: %s\n", DB_name_PUFCash_V3, sqlite3_errmsg(DB_PUFCash_V3)); sqlite3_close(DB_PUFCash_V3); exit(EXIT_FAILURE); }

// ================================================================================================================================
// ================================================================================================================================
   SHP_ptr = &(SHP[0]);

// NOTE: WE MUST DO THIS IN THE PARENT because we use it below.
   static pthread_mutex_t GenChallenge_mutex = PTHREAD_MUTEX_INITIALIZER;

// If we set 'use_database_chlngs' to 1, then we can NOT allow more than one thread to run GenChallengeDB() at the same time because we
// call rand(). If the device or TTP is going to get the same set of random numbers as this verifier is than after srand() is seeded with 
// 'DB_ChallengeGen_seed', we must block other threads until the vector sequence is completely generated, i.e., rand() is NOT re-entrant!
// We can do this in main() or here once we've initialized the GenChallenge_mutex mutex above (it is static and therefore global to all threads).
   SHP_ptr->GenChallenge_mutex_ptr = &GenChallenge_mutex;


// =========================
// Set some of the params in the data structure. NOTE: This structure is not really used AFTER the authentication and session key generation
// with the Bank below. We need to be careful if we start using the PUF within the processing loop below. We must create an array of these SHP 
// structures for each thread (using only one for now), and then protect calls to the PUF using semaphores.
   SHP_ptr->CtrlRegA = CtrlRegA;
   SHP_ptr->DataRegA = DataRegA;
   SHP_ptr->ctrl_mask = ctrl_mask;

// After device authenticates successfully, verifier sends its ID from the Enrollment database to the device. The device will use this as it's ID.
   SHP_ptr->chip_num = -1;

// NOT relevant here in the TTP. 
   SHP_ptr->anon_chip_num = -1;

   SHP_ptr->DB_Challenges = DB_Challenges;
   SHP_ptr->DB_name_Challenges = DB_name_Challenges;

   SHP_ptr->use_database_chlngs = use_database_chlngs;
   SHP_ptr->DB_design_index = design_index;
   SHP_ptr->DB_ChallengeSetName = ChallengeSetName;
   SHP_ptr->DB_ChallengeGen_seed = ChallengeGen_seed; 

   SHP_ptr->DB_Trust_AT = DB_Trust_AT;
   SHP_ptr->DB_name_Trust_AT = DB_name_Trust_AT;

   SHP_ptr->DB_PUFCash_V3 = DB_PUFCash_V3;
   SHP_ptr->DB_name_PUFCash_V3 = DB_name_PUFCash_V3;
   SHP_ptr->eCt_num_bytes = ECT_NUM_BYTES;

// NOT used in the TTP.
   SHP_ptr->Alice_EWA = NULL;
   SHP_ptr->Alice_K_AT = NULL;

// Other protocol. This must also match the length of KEK_TARGET_NUM_KEY_BITS/8. Might make more sense to just set it to that even 
// though we use KEK session key generation to generate the MAT_LLK.
//   SHP.MAT_LLK_num_bytes = SE_TARGET_NUM_KEY_BITS/8;

// Other protocol. This must also match the length of KEK_TARGET_NUM_KEY_BITS/8. Might make more sense to just set it to that even 
// though we use KEK session key generation to generate the PHK_A_nonce.
//   SHP.PHK_A_num_bytes = SE_TARGET_NUM_KEY_BITS/8;

// ZeroTrust protocol. 
   SHP_ptr->ZHK_A_num_bytes = KEK_TARGET_NUM_KEY_BITS/8;

// Added this when updating GenLLK function. 
   SHP_ptr->KEK_LLK_num_bytes = KEK_TARGET_NUM_KEY_BITS/8;

// These we will eventually come from the verifier via a message.
   SHP_ptr->num_PIs = num_PIs;
   SHP_ptr->num_POs = num_POs;

   SHP_ptr->fix_params = fix_params;

   SHP_ptr->num_required_PNDiffs = NUM_REQUIRED_PNDIFFS;

   SHP_ptr->num_SF_bytes = NUM_REQUIRED_PNDIFFS * SF_WORDS_TO_BYTES_MULT;
   SHP_ptr->num_SF_words = NUM_REQUIRED_PNDIFFS; 

// 1_1_2022: If TRIMCODE_CONSTANT is <= 32, then we can preserve on precision bit in the iSpreadFactors for the device, else we cannot preserve any.
   if ( TRIMCODE_CONSTANT <= 32 )
      SHP_ptr->iSpreadFactorScaler = 2;
   else
      SHP_ptr->iSpreadFactorScaler = 1;

   if ( (SHP_ptr->iSpreadFactors = (signed char *)calloc(SHP_ptr->num_SF_words, sizeof(signed char))) == NULL )
      { printf("ERROR: Failed to allocate storage for iSpreadFactors!\n"); exit(EXIT_FAILURE); }

   if ( (SHP_ptr->verifier_SHD = (unsigned char *)calloc(SHP_ptr->num_required_PNDiffs/8, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for verifier_SHD!\n"); exit(EXIT_FAILURE); }
   if ( (SHP_ptr->verifier_SBS = (unsigned char *)calloc(SHP_ptr->num_required_PNDiffs/8, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for verifier_SBS!\n"); exit(EXIT_FAILURE); }
   if ( (SHP_ptr->device_SHD = (unsigned char *)calloc(SHP_ptr->num_required_PNDiffs/8, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for device_SHD!\n"); exit(EXIT_FAILURE); }
   if ( (SHP_ptr->device_SBS = (unsigned char *)calloc(SHP_ptr->num_required_PNDiffs/8, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for device_SBS!\n"); exit(EXIT_FAILURE); }
   SHP_ptr->verifier_SHD_num_bytes = 0;
   SHP_ptr->verifier_SBS_num_bytes = 0;
   SHP_ptr->device_SHD_num_bytes = 0;
   SHP_ptr->device_SBS_num_bits = 0; 

// Note: MAX_GENERATED_NONCE_BYTES MUST BE LARGER THAN NUM_XOR_NONCE_BYTES.
   SHP_ptr->nonce_base_address = nonce_base_address;
   SHP_ptr->max_generated_nonce_bytes = MAX_GENERATED_NONCE_BYTES; 
   SHP_ptr->num_required_nonce_bytes = NUM_XOR_NONCE_BYTES; 

// This is filled in by CollectPNs as the hardware reads nonce bytes.
   SHP_ptr->num_device_n1_nonces = 0;
   if ( (SHP_ptr->device_n1 = (unsigned char *)calloc(SHP_ptr->max_generated_nonce_bytes, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for verifier_n2!\n"); exit(EXIT_FAILURE); }
   if ( (SHP_ptr->verifier_n2 = (unsigned char *)calloc(SHP_ptr->num_required_nonce_bytes, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for verifier_n2!\n"); exit(EXIT_FAILURE); }
   if ( (SHP_ptr->XOR_nonce = (unsigned char *)calloc(SHP_ptr->num_required_nonce_bytes, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for XOR_nonce!\n"); exit(EXIT_FAILURE); }

   SHP_ptr->vec_chunk_size = CHLNG_CHUNK_SIZE; 
   SHP_ptr->XMR_val = XMR_VAL;

   memcpy((char *)SHP_ptr->AES_IV, (char *)AES_IV, AES_IV_NUM_BYTES);

   SHP_ptr->SE_target_num_key_bits = SE_TARGET_NUM_KEY_BITS; 
   SHP_ptr->SE_final_key = NULL;
   SHP_ptr->authen_min_bitstring_size = AUTHEN_MIN_BITSTRING_SIZE;

// KEK information presumably stored in NVM for regeneration, preserved here in separate fields.
   SHP_ptr->KEK_target_num_key_bits = KEK_TARGET_NUM_KEY_BITS;
   SHP_ptr->KEK_final_enroll_key = NULL;
   SHP_ptr->KEK_final_regen_key = NULL;
   SHP_ptr->KEK_final_XMR_SHD = NULL;

// 5_11_2021: For tracking the number of minority bit flips with KEK FSB mode (NOT NE mode).
   SHP_ptr->KEK_BS_regen_arr = NULL;

   SHP_ptr->KEK_final_SpreadFactors_enroll = NULL;

   SHP_ptr->KEK_num_vecs = 0;
   SHP_ptr->KEK_num_rise_vecs = 0;;
   SHP_ptr->KEK_has_masks = 1;
   SHP_ptr->KEK_first_vecs_b = NULL;
   SHP_ptr->KEK_second_vecs_b = NULL;
   SHP_ptr->KEK_masks_b = NULL;
   if ( (SHP_ptr->KEK_XOR_nonce = (unsigned char *)calloc(SHP_ptr->num_required_nonce_bytes, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for XOR_nonce!\n"); exit(EXIT_FAILURE); }
   SHP_ptr->num_direction_chlng_bits = NUM_DIRECTION_CHLNG_BITS;

// For Special KEK mode data from hardware. Will eventually be eliminated once I change the VHDL to do this in hardware.
   SHP_ptr->KEK_num_iterations = 0;

// Allocate space for the authentication nonce received from server during device authentication or generated locally
// for transmission to server for server authentication.
   if ( (SHP_ptr->KEK_authentication_nonce = (unsigned char *)calloc(num_KEK_authen_nonce_bytes, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for KEK_authentication_nonce!\n"); exit(EXIT_FAILURE); }
   SHP_ptr->num_KEK_authen_nonce_bits = num_KEK_authen_nonce_bytes*8;
   SHP_ptr->num_KEK_authen_nonce_bits_remaining = SHP_ptr->num_KEK_authen_nonce_bits;
   SHP_ptr->DA_cobra_key = NULL;

// XMR_SHD that is generated during KEK_DeviceAuthentication during each iteration (to be concatenated to a larger blob and 
// sent to server).
   if ( (SHP_ptr->KEK_authen_XMR_SHD_chunk = (unsigned char *)calloc(SHP_ptr->num_required_PNDiffs/8, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for KEK_authen_XMR_SHD_chunk!\n"); exit(EXIT_FAILURE); }

   SHP_ptr->num_vecs = 0;
   SHP_ptr->num_rise_vecs = 0;;
   SHP_ptr->has_masks = 1;
   SHP_ptr->first_vecs_b = NULL;
   SHP_ptr->second_vecs_b = NULL;
   SHP_ptr->masks_b = NULL;

//   SHP_ptr->PeerTrust_LLK = NULL;
   SHP_ptr->ZeroTrust_LLK = NULL;

   SHP_ptr->param_LFSR_seed_low = 0;
   SHP_ptr->param_LFSR_seed_high = 0;
   SHP_ptr->param_RangeConstant = RANGE_CONSTANT;
   SHP_ptr->param_SpreadConstant = SPREAD_CONSTANT;
   SHP_ptr->param_Threshold = THRESHOLD_CONSTANT;
   SHP_ptr->param_TrimCodeConstant = TRIMCODE_CONSTANT;
   SHP_ptr->param_PCR_or_PBD_or_PO = PCR_or_PBD_or_PO;

// 10_28_2022: Get the personalized ScalingConstant from the command line. NOTE: This is passed into the state machine as a FIXED POINT value
// with SCALING_PRECISION_NB bits of precision (currently 11 bits), xxxxx.xxxxxxxxxxx. Convert from floating point to scaled integer. So a 
// scaling value of 1.0 will be equal to 1 << SCALING_PRECISION_NB, which is 2^11 = 2048 (0000100000000000). NOTE: MyScalingConstant VALUE MUST BE POSITIVE and 
// between 1.0 and x.0 (current 5.0) above. So values here are between 4096 and 20480.
// 11_12_2022: Adding this 'do_scaling' flag, and initializing it to 0. COBRA and possibly SKE (PARCE) are the only functions that set it to 1.
   SHP_ptr->do_scaling = 0;
   SHP_ptr->MyScalingConstant = (int)(command_line_SC * pow(2.0, (float)SCALING_PRECISION_NB));

// Sanity check
   if ( SHP_ptr->MyScalingConstant < 0 || SHP_ptr->MyScalingConstant > (MAX_SCALING_VALUE << SCALING_PRECISION_NB) )
      { printf("ERROR: MyScalingConstant MUST be >= 0 and <= %d\n", MAX_SCALING_VALUE << SCALING_PRECISION_NB); exit(EXIT_FAILURE); }

#ifdef DEBUG
if ( SHP_ptr->MyScalingConstant == (1 << SCALING_PRECISION_NB) )
   { printf("NO SCALING WILL OCCUR: ScalingConstant IS 1.0\n"); fflush(stdout); }
else
   { printf("ScalingConstant: %f\tScaled FixedPoint %d\n", command_line_SC, SHP_ptr->MyScalingConstant); fflush(stdout); }
#endif

// The PL-side TRNG_LFSR is 64 bits. Note that we currently only suport loading the low-order 16-bits of the seed register. 
   SHP_ptr->TRNG_LFSR_seed = TRNG_LFSR_seed;

// For frequency statistics of the TRNG. Need to declare these here for the TTP -- can NOT make them static in multi-threaded apps.
   SHP_ptr->num_ones = 0; 
   SHP_ptr->total_bits = 0; 
   SHP_ptr->iteration = 0;

   SHP_ptr->do_COBRA = DO_COBRA;

   SHP_ptr->DUMP_BITSTRINGS = DUMP_BITSTRINGS;
   SHP_ptr->DEBUG_FLAG = DEBUG_FLAG;

// ================================
// Open up the random source for device to generate nonce bytes that will be used to SelectParams for authentication.
   if ( (RANDOM = open("/dev/urandom", O_RDONLY)) == -1 )
      { printf("ERROR: Could not open /dev/urandom\n"); exit(EXIT_FAILURE); }
   printf("\tSuccessfully open '/dev/urandom'\n");

// ========================================================
// Open up a socket connection to the Bank and keep it open forever. OpenSocketClient returns -1 on failure.
   int attempts = 0;
   while ( OpenSocketClient(MAX_STRING_LEN, Bank_IP, port_number, &Bank_socket_desc) < 0 && attempts < 50 )
      {
      printf("INFO: Waiting to connect to Bank '%s'!\n", Bank_IP); fflush(stdout); 
      usleep(200000);
      attempts++;
      }
   if ( attempts == 50 )
      { printf("ERROR: Open socket call to Bank failed!\n"); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("Bank_socket_descriptor %d\n", Bank_socket_desc); fflush(stdout);
#endif

// ========================================================
// Initialize all client_sockets to 0. We do NOT DO THIS any longer in the call to OpenMultipleSocketServer below.
   int client_num;
   for ( client_num = 0; client_num < MAX_CLIENTS; client_num++) 
      { client_sockets[client_num] = 0; }

// Add the TTP socket to the client_sockets list so we can monitor activity on it. 
   client_sockets[0] = Bank_socket_desc;


// ================================================================================================
// Generate the KEK long-lived KEK, either by running KEK_Enroll but communicating with the Bank to get 
// challenges (if no Chlng info exists in the AuthenticationToken.db), or by reading out the LLK Chlng information 
// and running KEK_Regen. Called by both the device and TTP.

// Setting this to 1 allows MORE THAN one LLK_type = 2 Chlngs to exist. There should be only one. This data is now
// stored in the PUFCash_V3 DB, in the PUFCash_LLK table. The LLK key is stored in the ZeroTrust_LLK field when 
// LLK_type is 2.
   int allow_multiple_LLK = 0;
   int open_socket = 0;
   int LLK_type = 2;
   int zero_trust_LLK_index;
   zero_trust_LLK_index = GenLLK(MAX_STRING_LEN, SHP_ptr, open_socket, Bank_IP, port_number, Bank_socket_desc, allow_multiple_LLK, 
      LLK_type, SHP_ptr->KEK_LLK_num_bytes);


// ========================================================
// I do mutual authenication and session key gen above in GenLLK operation but ONLY conditionally. Note that we MUST do session key 
// generation with THIS call to TTP-AUTHENTICATION (Alice and Bob depend on it) because we ONLY do the KEK LLK operation ONCE after 
// provisioning in GenLLK and then just read the KEK vectors from the database to regenerate the KEK key (we do NOT do MA and SKG). 
// We must have a session key generated. We will do authentication twice ONLY one time when the AuthenticationToken.db is overwritten.

// Mutually authenticate and generate TTP_session_key with the Bank. NOTE: KEK_DeviceAuthentication() return chip_num = -1 IF IT FAILS. 
   if ( SockSendB((unsigned char *)"TTP-AUTHENTICATION", strlen("TTP-AUTHENTICATION") + 1, Bank_socket_desc) < 0 )
      { printf("ERROR: main(): Failed to send 'TTP-AUTHENTICATION' to Bank!\n"); exit(EXIT_FAILURE); }
   gen_session_key = 1;
   if ( KEK_ClientServerAuthenKeyGen(MAX_STRING_LEN, SHP_ptr, Bank_socket_desc, gen_session_key) == 0 )
      exit(EXIT_FAILURE);
   TTP_session_key = SHP_ptr->SE_final_key;
   SHP_ptr->SE_final_key = NULL;


// ========================================================
// 7_5_2022: Adding this to allow Alice/Bob to authenticate with their TTP (commercial bank) using the ZeroTrust protocol.
// ZeroTrust_Enroll carries out the customer portion of the ZeroTrust Enrollment process, where TTP generates Authentication 
// Tokens that consist of a keyed-hash of its LLK + nonce (ZHK_A_nonce). This information is transmitted to IA (the Bank or server 
// or verifier). The Bank validates it and then stores it in its ZerTrust database table. IA encrypts this and distributes
// these to other customers upon request. 

// Sanity check
   if ( SHP_ptr->ZeroTrust_LLK == NULL )
      { printf("GenLLK() call FAILED to generate a ZeroTrust_LLK!\n"); exit(EXIT_FAILURE); }

// If NO AT elements exist in Alice's ZeroTrust table, then carry out enrollment. This is NOT necessary when we NEED to do 
// enrollment. Only doing this to prevent ZeroTrust_Enroll from being called over and over again during testing.

// Check if ATs exist. This flag dominates. Only the number of NOT USED ATs are returned if set
   int report_tot_num_ATs_only = 1;

// These flags irrelevant here.
   int get_only_customer_AT = 0;
   int return_customer_AT_info = 0;

   int customer_chip_num = -1;

// NOTE: We skip the authentication here for the TTP since it was done above. No semiphore needed here because this is 
// done at startup (before threads are created).
   int *chip_num_arr = NULL;
   int *chlng_num_arr = NULL;
   unsigned char **ZHK_A_nonce_arr = NULL;
   unsigned char **nonce_arr = NULL;
   int unused;
   int is_TTP = 1;
   if ( ZeroTrustGetCustomerATs(MAX_STRING_LEN, SHP_ptr->DB_Trust_AT, &chip_num_arr, &chlng_num_arr, SHP_ptr->ZHK_A_num_bytes, 
      &ZHK_A_nonce_arr, &nonce_arr, get_only_customer_AT, customer_chip_num, return_customer_AT_info, report_tot_num_ATs_only, &unused) == 0 )
      {
printf("No customer ATs found! Enrolling\n"); fflush(stdout);
#ifdef DEBUG
#endif

      ZeroTrust_Enroll(MAX_STRING_LEN, SHP_ptr, Bank_IP, port_number, zero_trust_LLK_index, is_TTP, Bank_socket_desc, TTP_session_key); 
      }

// ========================================================
// Get list of (TTP) IPs from Bank. This just checks that the Bank TTP IP matches the one used by this device (which runs as a TTP).

// Tell Bank we want the TTP IP information that it stores on the TTPs.
   if ( SockSendB((unsigned char *)"TTP-MASTER-GET-TTP-IP-INFO", strlen("TTP-MASTER-GET-TTP-IP-INFO") + 1, Bank_socket_desc) < 0 )
      { printf("ERROR: Failed to send 'TTP-MASTER-GET-TTP-IP-INFO' to Bank!\n"); exit(EXIT_FAILURE); }

// This call checks to determine that the Bank has the correct TTP IP (the one used here must match the one sent by the Bank).
// MAKE SURE Client_CIArr is NULL since we use realloc. NOTE: We use my_IP_pos here in ttp.c but NOT in device_regeneration.c
   Client_CIArr = NULL;
   int start_index = 0;
   is_TTP = 1;
   num_TTPs = GetClient_IPs(MAX_STRING_LEN, SHP_ptr, TTP_session_key, Bank_socket_desc, &Client_CIArr, MAX_CONNECT_ATTEMPTS, 
      IP_LENGTH, TTP_IP, &my_IP_pos, &exclude_self, start_index, is_TTP);

// Only support one TTP (thus far) in PUF-Cash V3.0.
   if ( num_TTPs != 1 )
      { printf("ERROR: num_TTPs MUST be 1 (%d)\tNot yet supporting multiple TTP!\n", num_TTPs); exit(EXIT_FAILURE); }

printf("main(): Bank returned num_TTPs %d!\n", num_TTPs); fflush(stdout);
#ifdef DEBUG
#endif

// ========================================================
// CUSTOMER ACCOUNT CREATION: Create accounts for customers with a default amount. First get a list of chip_nums from the Bank.
   if ( GetCustomerChipNums(MAX_STRING_LEN, SHP_ptr, TTP_session_key, Bank_socket_desc, TID, default_deposit_amt) == 0 )
      exit(EXIT_FAILURE);
   
// ========================================================
// THREADS:
// Load up data structure for the thread. Do this here so the threads can share the Bank socket descriptor. 
   for ( thread_num = 0; thread_num < MAX_THREADS; thread_num++ )
      {
      ThreadDataArr[thread_num].history_file_name = history_file_name;
      ThreadDataArr[thread_num].task_num = thread_num;

// I can get away with pointing all threads to the same SHP data structure, which stores PUF data, because we authenticate and generate
// a session key with the Bank EXACTLY ONCE, which was already done above. Otherwise we would need a mutex for this too.
      ThreadDataArr[thread_num].SHP_ptr = &(SHP[0]);


      ThreadDataArr[thread_num].Bank_socket_desc = Bank_socket_desc;
      ThreadDataArr[thread_num].Device_socket_desc = -1;
      ThreadDataArr[thread_num].TTP_session_key = TTP_session_key;
      ThreadDataArr[thread_num].port_number = port_number;
      ThreadDataArr[thread_num].in_use = 0;
      ThreadDataArr[thread_num].client_index = -1;
      ThreadDataArr[thread_num].client_sockets = client_sockets;
      ThreadDataArr[thread_num].num_TTPs = num_TTPs;
      ThreadDataArr[thread_num].max_string_len = MAX_STRING_LEN;
      ThreadDataArr[thread_num].max_TTP_connect_attempts = MAX_CONNECT_ATTEMPTS;

      ThreadDataArr[thread_num].Client_CIArr = (ClientInfoStruct *)calloc(num_TTPs, sizeof(ClientInfoStruct));
      for ( int i = 0; i < num_TTPs; i++ )
         ThreadDataArr[thread_num].Client_CIArr[i] = Client_CIArr[i];

      ThreadDataArr[thread_num].my_IP_pos = my_IP_pos;
      ThreadDataArr[thread_num].exclude_self = exclude_self;
      ThreadDataArr[thread_num].RANDOM = RANDOM;
      ThreadDataArr[thread_num].num_eCt_nonce_bytes = num_eCt_nonce_bytes;

// ******************************************************
// Create a set of static threads -- thread memory management on the Cora/Zybo seems to have problems. Pass to each a copy
// of DeviceDataArr structure. The loop below will update Device_socket_desc, client_index and in_use. The Thread will use
// the Device_socket_desc as the new communication channel. The client_index refers to the element in the client_sockets
// array that is in use during the message processing -- the processing thread will set this back to client_sockets[client_index]
// back to 0 before finishing. The Threads are in an infinit loop testing the in_use field. The parent here sets this to 1
// when a new message is to be processed.
//
// We need to call pthread_cancel() to have the pthread free resources (I think pthread_detach also frees resources). If I
// try to use pthread_cancel, I get a library complaint that some part of the thread library is missing -- need a newer version,
// or whatever. Since I create all these threads statically I don't need to create and destroy them so no need for these functions
// anyway.

// Allocate all threads. 
      int err;
      pthread_t thread_id;
      if ( (err = pthread_create((pthread_t *)&thread_id, NULL, (void *)TTPThread, (void *)&(ThreadDataArr[thread_num]))) != 0 )
         { printf("Failed to create thread: %d\n", err); fflush(stdout); }

// Detach thread since we don't need to synchronize with it (no 'join' required). Also allows resources to be freed when thread 
// terminates.
//      pthread_detach(thread_id);

#ifdef DEBUG
printf("Thread ID %lu\n", (unsigned long int)thread_id); fflush(stdout);
#endif

printf("Number of threads created: %d\n", thread_num + 1); fflush(stdout);
#ifdef DEBUG
#endif
      }

// Now that we've made copies of Client_CIArr, we can NULL out the original array. Memory leak on session_keys, etc.
// but not important since we do this exactly once at startup.
   if ( Client_CIArr != NULL )
      free(Client_CIArr);
   Client_CIArr = NULL;


// ===========================================================================================================================
// ===========================================================================================================================
   int num_iterations;
   int iteration;
   int first_time = 1;

   num_iterations = -1;
   for ( iteration = 0; (iteration < num_iterations || num_iterations == -1) && keepRunning == 1; iteration++ )
      {

// Note: If NOT a new connection, 'client_IP' is NOT filled in by OpenMultipleSocketServer(). 'client_IP' is NOT filled in
// for repeated communications from the Bank since we do NOT close this socket. NOTE: On FIRST call, client_sockets array is
// NO LONGER initialized to ALL zeros so we preserve assignment above.
      strcpy(client_IP, "");
      client_index = -1;
      Device_socket_desc = 0;
      SD = OpenMultipleSocketServer(MAX_STRING_LEN, &TTP_socket_desc, TTP_IP, port_number, client_IP, MAX_CLIENTS, client_sockets, 
         &client_index, first_time);
      first_time = 0;

// Interesting but I hadn't realized that my OpenMultipleSocketServer() routine will return every time something happens on an
// open socket, with SD = 0 and client_IP = 0.0.0.0, and with 'client_index' and 'client_sockets[client_index]' set to the open socket.
// And not just on socket connection requests! I hadn't seen this before because I would not call OpenMultipleSocketServer() again until 
// after all packets were processed by the code that used to run sequentially below but is now in a thread. With this spun off into a 
// thread, OpenMultipleSocketServer() gets called immediately after the thread is created (the whole point of using threads is to allow 
// parallelism). For sockets that are open already and have threads serving them, SD is 0. Let's ignore these. The Bank also sends
// messages here since it stays permanently connected. 
//      if ( SD == 0 )
//         continue;
// 5/6/2020: FIXED THIS when I created verifier_regeneration_pT.c. Changed ../PROTOCOL/common.c OpenMultipleSocketServer. BUT STILL
// NEED this to filter spurious Bank events. 
      if ( client_index == 0 )
         { 
//         printf("WARNING: SKIPPING 'spurious' Bank descriptor activity!\n"); fflush(stdout);
         continue;
         }

#ifdef DEBUG
struct timeval t1, t2;
long elapsed; 
gettimeofday(&t2, 0);
#endif

// Sanity check
      if ( client_index == -1 )
         { printf("ERROR: Failed to find an empty slot in client_sockets -- increase MAX_CLIENTS!\n"); exit(EXIT_FAILURE); }

printf("SD and Client_IP returned by OpenMultipleSocketServer %d and %s, stored at client_index %d in client_sockets %d!\n", SD, client_IP, 
   client_index, client_sockets[client_index]); fflush(stdout);
printf("\tBank SD and Bank_IP %d and %s, stored at client_index 0 in client_sockets[0] => %d!\n", Bank_socket_desc, Bank_IP, client_sockets[0]); fflush(stdout);
#ifdef DEBUG
#endif

// Client socket number is returned
      if ( SD >= 0 )
         Device_socket_desc = SD;
      else
         { printf("ERROR: Socket descriptor returned %d is negative!\n", SD); exit(EXIT_FAILURE); }

printf("\nITERATION %d\n", iteration);
#ifdef DEBUG
#endif

// Search for a thread that is available. Note that I reserve the last thread as a periodic history printing thread so
// it is never available. Note that there is a loop above that also eliminates this tread so if you add it back, change 
// it above too.
      int found_one = 0;
      while ( found_one == 0 )
         {
         for ( thread_num = 0; thread_num < MAX_THREADS - 1; thread_num++ )
            {
            pthread_mutex_lock(&(ThreadDataArr[thread_num].Thread_mutex));
            if ( ThreadDataArr[thread_num].in_use == 0 )
               {
               ThreadDataArr[thread_num].Device_socket_desc = Device_socket_desc;
               strcpy(ThreadDataArr[thread_num].customer_IP, client_IP);
               ThreadDataArr[thread_num].client_index = client_index;
               ThreadDataArr[thread_num].iteration_cnt = iteration;
               ThreadDataArr[thread_num].in_use = 1;
               found_one = 1;

// Make further activity on this socket descriptors ignored by OpenMultipleSocketServer() until the thread restores the 
// client_socket value when it completes communication with a TTP.
               client_sockets[client_index] = -1;

               pthread_cond_signal(&(ThreadDataArr[thread_num].Thread_cv));
               }
            pthread_mutex_unlock(&(ThreadDataArr[thread_num].Thread_mutex));
            if ( found_one == 1 )
               break;
            }
         }
       
printf("\tTasking Thread %d\n", thread_num); fflush(stdout);
#ifdef DEBUG
#endif

// Used this to find the bug with thread memory management. I used to create and destroy threads here dynamically. Instead creating them statically
// above and putting them in a forever loop.
//      TTPThread(&(ThreadDataArr[thread_num]));

#ifdef DEBUG
printf("\tWaiting for incoming connections from clients ....\n"); fflush(stdout);
#endif

#ifdef DEBUG
gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t2.tv_sec)*1000000 + t1.tv_usec-t2.tv_usec; printf("\tTOTAL EXEC TIME %ld us\n\n", (long)elapsed);
#endif
      }

// I do saves periodically in the threads without closing it. This is likely never called b/c we hit Ctrl-C. 
   printf("Saving 'in memory' '%s' to filesystem!\n", SHP_ptr->DB_name_Trust_AT); fflush(stdout);
   if ( LoadOrSaveDb(SHP_ptr->DB_Trust_AT, SHP_ptr->DB_name_Trust_AT, 1) != 0 )
      { printf("Failed to store 'in memory' database to %s: %s\n", SHP_ptr->DB_name_Trust_AT, sqlite3_errmsg(SHP_ptr->DB_Trust_AT)); sqlite3_close(SHP_ptr->DB_Trust_AT); exit(EXIT_FAILURE); }
   sqlite3_close(SHP_ptr->DB_Trust_AT);

   printf("Saving 'in memory' '%s' to filesystem!\n", SHP_ptr->DB_name_PUFCash_V3); fflush(stdout);
   if ( LoadOrSaveDb(SHP_ptr->DB_PUFCash_V3, SHP_ptr->DB_name_PUFCash_V3, 1) != 0 )
      { printf("Failed to store 'in memory' database to %s: %s\n", SHP_ptr->DB_name_PUFCash_V3, sqlite3_errmsg(SHP_ptr->DB_PUFCash_V3)); sqlite3_close(SHP_ptr->DB_PUFCash_V3); exit(EXIT_FAILURE); }
   sqlite3_close(SHP_ptr->DB_PUFCash_V3);

   free(TTP_session_key);

   close(Bank_socket_desc);
   return 0;
   }


