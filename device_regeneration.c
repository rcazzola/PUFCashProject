// ========================================================================================================
// ========================================================================================================
// **************************************** device_regeneration.c *****************************************
// ========================================================================================================
// ========================================================================================================
//
//--------------------------------------------------------------------------------
// Company: IC-Safety, LLC and University of New Mexico
// Engineer: Professor Jim Plusquellic
// Exclusive License: IC-Safety, LLC
// Copyright: Univ. of New Mexico
//--------------------------------------------------------------------------------


#include <signal.h>
#include "common.h"
#include "device_hardware.h"
#include "device_common.h"
#include "device_regen_funcs.h"
#include "commonDB_RT_PUFCash.h"
#include "interface.h"

// ====================== DATABASE STUFF =========================
#include <sqlite3.h>
#include "commonDB.h"

extern int usleep (__useconds_t __useconds);
extern int getpagesize (void)  __THROW __attribute__ ((__const__));

// Forward declarations
int AliceDoZeroTrust(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, ClientInfoStruct *Client_CIArr, 
   int num_CIArr, int other_party_index, int port_number, int other_party_socket_desc, int My_index);


// ========================================================================================================
// ========================================================================================================
// Alice authenticates with the TTP and then carries out the withdrawal. 

int AliceWithdrawal(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int TTP_index, 
   int My_index, ClientInfoStruct *Client_CIArr, int port_number, int num_CIArr, 
   int num_eCt_nonce_bytes, int num_eCt)
   {
   int TTP_socket_desc;

printf("\nAliceWithdrawal(): BEGIN\n\n"); fflush(stdout);
#ifdef DEBUG
#endif

// Sanity check
   if ( num_eCt == 0 )
      { printf("ERROR: AliceWithdrawal(): num_eCt withdrawal request is 0!\n"); return 0; }

// AliceWithdrawal authenticates with the TTP using ZeroTrust for a withdrawal. Open socket to TTP. Keep trying 
// until TTP gets to a point where he is listening. With polling, this should happen right away.
   int num_retries = 0;
   while ( OpenSocketClient(max_string_len, Client_CIArr[TTP_index].IP, port_number, &TTP_socket_desc) < 0 )
      { 
      printf("INFO: AliceWithdrawal(): Alice trying to connect to Bob to exchange IDs!\n"); fflush(stdout); 
      usleep(500000); 
      num_retries++;
      if ( num_retries > 500 )
         return 0;
      }

// ==============================
// Tell TTP we want to make a withdrawal. This will start the authentication process before the withdrawal.
   if ( SockSendB((unsigned char *)"ALICE-WITHDRAWAL", strlen("ALICE-WITHDRAWAL") + 1, TTP_socket_desc) < 0 )
      { printf("ERROR: AliceWithdrawal(): Failed to send 'WITHDRAW' to TTP!\n"); exit(EXIT_FAILURE); }

// ==============================
// Alice sends TTP her chip number. TTP uses this to fetch an AT from the Bank for Alice's transaction. 
// NOTE: Unlike Alice and Bob, the TTP does NOT fetch AT in advance (Alice and Bob do it with a menu option).

printf("\tAliceWithdrawal(): Alice sending TTP 'chip_num' so TTP can decide if it has an AT for Alice!\n"); fflush(stdout);
#ifdef DEBUG
#endif

   char Alice_chip_num_str[max_string_len];
   sprintf(Alice_chip_num_str, "%d", SHP_ptr->chip_num);
   if ( SockSendB((unsigned char *)Alice_chip_num_str, strlen(Alice_chip_num_str)+1, TTP_socket_desc) < 0 )
      { printf("ERROR: AliceWithdrawal(): Failed to send 'Alice_chip_num' to TTP!\n"); exit(EXIT_FAILURE); }

// ==============================
// Do ZeroTrust authentication and key generation between Alice and the TTP.
   if ( AliceDoZeroTrust(max_string_len, SHP_ptr, Client_CIArr, num_CIArr, TTP_index, port_number, TTP_socket_desc, My_index) == 0 )
      return 0;


// 1) Send encrypted Alice chip_num (or anon_chip_num), e.g., SHP_ptr->anon_chip_num and amount of the withdrawal to the TTP. 
// NOTE: Alice gets this anon_chip_num from the Bank (TI) at startup via an anonymous authentication operation. 
// ****************************
// ADD CODE 
// ****************************

// 2) Get response from TTP on whether Alice has enough funds. If insufficient funds ("ISF"), return 0, else continue.
// ****************************
// ADD CODE 
// ****************************

// 3) Generate a shared key between the Bank and Alice THROUGH the FI. The Bank can use timing data from the NAT (or AT if 
// anonymous) DB to construct the key. To generate a shared secret with the Bank, we just run KEK_SessionKey here, 
// which causes the device to run KEK. Here, the Bank generates challenge and receives the XHD from Alice. Note we do 
// NOT need to store this challenge in our PUFCash_LKK DB since it is a session key. 
   int session_or_DA_cobra = 0;
   if ( KEK_SessionKeyGen(max_string_len, SHP_ptr, TTP_socket_desc, session_or_DA_cobra) == 0 )
      {
      printf("ERROR: AliceWithdrawal(): Failed to generate a Session key with Bank THROUGH THE TTP!\n"); fflush(stdout); 
      return 0;
      }

   int SK_TA_num_bytes = SHP_ptr->SE_target_num_key_bits/8;
   unsigned char *SK_TA = SHP_ptr->SE_final_key; 
   SHP_ptr->SE_final_key = NULL;

// 4) Get the eeCt and eheCt
   int eCt_tot_bytes = num_eCt * SHP_ptr->eCt_num_bytes;
   int eCt_tot_bytes_adj = eCt_tot_bytes + AES_INPUT_NUM_BYTES - (eCt_tot_bytes % AES_INPUT_NUM_BYTES);
   unsigned char *eeCt_buffer = Allocate1DUnsignedChar(eCt_tot_bytes_adj);
   unsigned char *eheCt_buffer = Allocate1DUnsignedChar(eCt_tot_bytes_adj);
// ****************************
// ADD CODE 
// ****************************

// 5) Decrypt the eCt and heCt with SK_TA.
   unsigned char *eCt_buffer = Allocate1DUnsignedChar(eCt_tot_bytes);
   unsigned char *heCt_buffer = Allocate1DUnsignedChar(eCt_tot_bytes_adj);
// ****************************
// ADD CODE 
// ****************************

// ==============================
// 6) Add Alice eCt and heCt blobs to DB, along with her LLK. NOTE: Multiple outstanding withdrawals is NOT supported 
// right now because the LLK is used as a unique identifier in the PUFCash_WRec table of the PUFCash database (database
// scheme sets this is 'unique' which prevents duplicates. And Alice uses the same LLK for each successive withdrawal.
   PUFCashAdd_WRec_Data(max_string_len, SHP_ptr->DB_PUFCash_V3, SHP_ptr->chip_num, SHP_ptr->ZeroTrust_LLK, 
      SHP_ptr->KEK_LLK_num_bytes, eCt_buffer, heCt_buffer, eCt_tot_bytes, num_eCt);


   close(TTP_socket_desc);

printf("\nAliceWithdrawal(): DONE\n\n"); fflush(stdout);
#ifdef DEBUG
#endif

   return 1;
   }


// ========================================================================================================
// ========================================================================================================
// Alice calls this at startup to get the list of IPs for TTPs and Customers. It gets the current list from 
// the Bank, and then queries each client for it's capability.

void AliceGetClient_IPs(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, char *Bank_IP, int port_number, 
   ClientInfoStruct **Client_CIArr_ptr, int max_connect_attempts, int ip_length, char *My_IP, 
   int *num_TTPs_ptr, int *num_customers_ptr)
   {
   int my_IP_pos, num_clients, exclude_self, set_num;
   unsigned char *Alice_session_key;
   int Bank_socket_desc;
   int gen_session_key; 

   int start_index, is_TTP;
   char *check_IP;

#ifdef DEBUG
printf("AliceGetClient_IPs(): START!\n"); fflush(stdout);
#endif

// Once for TTPs and once for customers. ONLY SUPPORTED FOR TWO iterations. If more, YOU MUST set start_index
// below.
   start_index = 0;
   for ( set_num = 0; set_num < 2; set_num++ )
      {
      while ( OpenSocketClient(max_string_len, Bank_IP, port_number, &Bank_socket_desc) < 0 )
         {
         printf("INFO: Alice waiting to connect to Bank for TTP information!\n"); fflush(stdout); 
         usleep(200000);
         }

// Tell Bank we want the TTP or customer device information that it knows about. 
      if ( set_num == 0 && SockSendB((unsigned char *)"ALICE-GET-TTP-IPS", strlen("ALICE-GET-TTP-IPS") + 1, Bank_socket_desc) < 0 )
         { printf("ERROR: AliceGetClient_IPs(): Failed to send 'ALICE-GET-TTP-IPS' to Bank!\n"); exit(EXIT_FAILURE); }
      if ( set_num == 1 && SockSendB((unsigned char *)"ALICE-GET-CUSTOMER-IPS", strlen("ALICE-GET-CUSTOMER-IPS") + 1, Bank_socket_desc) < 0 )
         { printf("ERROR: AliceGetClient_IPs(): Failed to send 'ALICE-GET-CUSTOMER-IPS' to Bank!\n"); exit(EXIT_FAILURE); }

// Generate session key with Bank. 
      gen_session_key = 1;
      if ( KEK_ClientServerAuthenKeyGen(max_string_len, SHP_ptr, Bank_socket_desc, gen_session_key) == 0 )
         exit(EXIT_FAILURE);

      Alice_session_key = SHP_ptr->SE_final_key; 
      SHP_ptr->SE_final_key = NULL;

// When called to get TTP IP info, set chip_IP to NULL so an error check is NOT performed in the GetClient_IPs routine.
      if ( set_num == 0 )
         {
         check_IP = NULL;
         is_TTP = 1;
         }
      else
         {
         check_IP = My_IP;
         is_TTP = 0;
         }

      exclude_self = 0;
      num_clients = GetClient_IPs(max_string_len, SHP_ptr, Alice_session_key, Bank_socket_desc, Client_CIArr_ptr, 
         max_connect_attempts, ip_length, check_IP, &my_IP_pos, &exclude_self, start_index, is_TTP);

      if ( set_num == 0 )
         {
         *num_TTPs_ptr = num_clients;

// We must set the start_index to a point AFTER in TTP elements.
         start_index = *num_TTPs_ptr;

#ifdef DEBUG
printf("AliceGetClient_IPs(): Bank returned %d TTP IPs!\n", *num_TTPs_ptr); fflush(stdout);
#endif
         }
      else
         {
         *num_customers_ptr = num_clients;

// WARNING: We do NOT set start_index here because we are done after two iterations.

#ifdef DEBUG
printf("AliceGetClient_IPs(): Bank returned %d Customer IPs!\n", *num_customers_ptr); fflush(stdout);
#endif
         }

      if ( Alice_session_key != NULL )
         free(Alice_session_key);
      close(Bank_socket_desc);
      }

#ifdef DEBUG
printf("AliceGetClient_IPs(): DONE!\n"); fflush(stdout);
#endif

   return; 
   }


// ========================================================================================================
// ========================================================================================================
// ZeroTrust: This routine is responsible for authenticating Alice and Bob or Alice and TTP.
// Alice contacts Bob, sends her ID, Bob looks up her ID in his AT DB and returns his ID and whether he has 
// at AT for her. Alice looks up Bob's ID in her DB and sends him a yes or no on whether she has an AT for 
// him. This routine fails if either of the parties does not have an AT for the other party. 

int AliceDoZeroTrust(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, ClientInfoStruct *Client_CIArr, 
   int num_CIArr, int other_party_index, int port_number, int other_party_socket_desc, int My_index)
   {
   int local_AT_status, remote_AT_status, Bob_chip_num, I_am_Alice; 
   int fail_or_succeed = 0;

printf("\nAliceDoZeroTrust(): CALLED\n"); fflush(stdout);
#ifdef DEBUG
#endif

// Sanity check. Alice's (self) IP IS included the Client_CIArr and has 'self' field marked with 1.
   if ( other_party_index == -1 )
      { printf("'Other Party' index INVALID %d!\n", other_party_index); exit(EXIT_FAILURE); }

printf("AliceDoZeroTrust(): Doing ZeroTrust Part I: Get other_party chip_num using IP '%s'\n", 
   Client_CIArr[other_party_index].IP); fflush(stdout);
#ifdef DEBUG
#endif

// ----------------------------------
// Alice and Bob determine if each has an AT for the other (set local_AT_status and remote_AT_status) and then get each others chip IDs. 
// other_party_index (set above) is set to who Alice want's to pay. NOTE: ALL customer's IP are stored in the Client_CIArr, including
// Alice's. For testing, other_party_index is set to the first non-self entry in the caller.
   I_am_Alice = 1;
   Bob_chip_num = ExchangeIDsConfirmATExists(max_string_len, SHP_ptr, SHP_ptr->chip_num, port_number, I_am_Alice, other_party_socket_desc, 
      &local_AT_status, &remote_AT_status);

printf("AliceDoZeroTrust(): PART I: PeerTrust: Alice got Bob's ID %d!\n", Bob_chip_num); fflush(stdout);
#ifdef DEBUG
#endif

// ==================================
// ZeroTrust: If Alice and Bob do NOT each have ATs for each other, then fail. If they do, then at this point, we have only confirmed
// that they do and have NOT officially authenticated. However, Alice now attempts to generate a shared key with Bob below. If that
// fails, then authentication fails.

printf("AliceDoZeroTrust(): ZeroTrust: remote_AT_status %d\tlocal_AT_status %d\n", remote_AT_status, local_AT_status); fflush(stdout);
#ifdef DEBUG
#endif

// Return FAILURE if both Alice and Bob do NOT have ATs for each other.
   if ( remote_AT_status == -1 || local_AT_status == -1 )
      return 0;

// Authenticate and generate a shared key. We just checked that Alice and Bob (Alice and TTP) have ATs on each other. 
   I_am_Alice = 1;
   if ( (fail_or_succeed = ZeroTrustGenSharedKey(max_string_len, SHP_ptr, Bob_chip_num, other_party_socket_desc, I_am_Alice, num_CIArr, 
     Client_CIArr, My_index)) == 1 )
     { printf("Alice SUCCEEDED in authenticating Bob or TTP and generating a shared key!\n"); fflush(stdout); }
   else
     { printf("Alice FAILED in authenticating Bob or TTP and generating a shared key!\n"); fflush(stdout); }

   return fail_or_succeed;
   }


// ========================================================================================================
// ========================================================================================================
// This routine handles all incoming requests from other clients. The caller has received a connection 
// request and we opened the socket.

void ProcessInComingRequest(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int client_socket_desc, 
   int port_number, struct sockaddr_in *AliceBob_addr_ptr, ClientInfoStruct *Client_CIArr, int num_CIArr, 
   int My_index, int *keep_socket_open_ptr)
   {
   char request_str[max_string_len];
   int Alice_CIA_index; 
   char *Alice_IP;

// By default, close the incoming socket after this transaction is completed.
   *keep_socket_open_ptr = 0;

printf("ProcessInComingRequest: START\n"); fflush(stdout);
#ifdef DEBUG
#endif

// Get the transaction request from another client.
   if ( SockGetB((unsigned char *)request_str, max_string_len, client_socket_desc) < 0 )
      { printf("ERROR: Failed to get transaction request from Client!\n"); exit(EXIT_FAILURE); }

printf("ProcessInComingRequest(): TRANSACTION REQUEST: '%s'\n", request_str); fflush(stdout);
#ifdef DEBUG
#endif

// =========================
// =========================
// When Alice contacts Bob (Bob is listener), we execute this call. This happens when Alice's starts a transaction 
// where she needs to authenticate Bob, i.e., to pay Bob. 
   if ( strcmp(request_str, "ALICE-BOB-AUTHENTICATE") == 0 )
      {

// Fills in a static buffer with the IP (that is overwritten on the next call to this function). Do NOT allocate and free.
// NOTE: THIS IS NOT RE-ENTRANT. No problem here since we are NOT multi-threading on the device.
      Alice_IP = inet_ntoa(AliceBob_addr_ptr->sin_addr);

// *** NOTE: THIS MAY NOT BE NECESSARY
// Find Alice's index into Bob's Client_CIArr by searching for her IP. Send that in as the Alice_CIA_index parameter. Don't confuse 
// Alice's index into the Client_CIArr with her chip_num (ID)! 
      for ( Alice_CIA_index = 0; Alice_CIA_index < num_CIArr; Alice_CIA_index++ )
         if ( strcmp(Client_CIArr[Alice_CIA_index].IP, Alice_IP) == 0 )
            break;

printf("ProcessInComingRequest(): Found Alice's IP '%s' at index %d in Client_CIArr\n", Alice_IP, Alice_CIA_index); fflush(stdout);
#ifdef DEBUG
#endif

// Sanity check. 
      if ( Alice_CIA_index == num_CIArr )
         { printf("ERROR: ProcessInComingRequest(): Bob failed to find Alice's IP '%s' in his Client_CIArr!\n", Alice_IP); exit(EXIT_FAILURE); }

// 1) Alice starts the value transfer operation above with Alice sending Bob 'ALICE-BOB-AUTHENTICATE'.
// 2) Bob responds with Yes/No regarding whether he has an AT for Alice (sets local_AT_status), and then sends his chip_num. 
// 3) Once Alice has Bob's unique chip_num, she checks her DB to see if she has an AT for Bob.
// 4) Alice responds with Yes/No regarding whether she has an AT for Bob and Bob sets remote_AT_status.
      int Alice_chip_num, local_AT_status, remote_AT_status;

// ----------------------------------
      int I_am_Alice = 0;
      Alice_chip_num = ExchangeIDsConfirmATExists(max_string_len, SHP_ptr, SHP_ptr->chip_num, port_number, I_am_Alice, 
         client_socket_desc, &local_AT_status, &remote_AT_status);

// Sanity check
      if ( Alice_chip_num == -1 )
         {
         printf("ProcessInComingRequest(): Bob's call to ExchangeIDsConfirmATExists to find Alice's ID FAILED!\n"); fflush(stdout);
         return;
         }

// ----------------------------------
// ----------------------------------
// If Alice and Bob do NOT each have ATs for each other, then fail. If they do, then at this point, we have only confirmed
// that they do and have NOT officially authenticated. However, Alice now attempts to generate a shared key with Bob below. If that
// fails, then authentication fails.

// Return FAILURE if both Alice and Bob do NOT have ATs for each other.
      if ( remote_AT_status == -1 || local_AT_status == -1 )
         return; 

// Now generate a shared key. Assume Alice and Bob (Alice and TTP) have ATs on each other. Exchange the nonces in the ATs, hash them with 
// the PeerTrust_LLKs to create two PHK_A_nonces, XOR them for the shared key. The shared key is stored i the Client_CIArr for the follow-up
// transaction.
      I_am_Alice = 0;
      if ( ZeroTrustGenSharedKey(max_string_len, SHP_ptr, Alice_chip_num, client_socket_desc, I_am_Alice, num_CIArr, Client_CIArr, My_index) == 1 )
         { printf("Bob SUCCEEDED in authenticating Alice and generating a shared key!\n"); fflush(stdout); }
      else
         { printf("Bob FAILED in authenticating Alice and generating a shared key!\n"); fflush(stdout); }

// Keep the socket open. Needed to do this for AliceTransferDriver because after we authenticate and generate a session key, we follow
// this up with another transaction to Bob here.
      *keep_socket_open_ptr = 0;
      return;
      }


   return;
   }


// ========================================================================================================
// ========================================================================================================
// Driver for AliceTransfer where we authenticate and then carry out the transfer to Bob. 
// NOTE: I needed to remove the socket opening and message string sending from AliceDoZeroTrust because
// we use AliceDoZeroTrust to do authentication between Alice and Bob AND between Alice and the TTP 
// (during withdrawals). Created this 'Driver' to modularize the removal of these elements.

int AliceTransferDriver(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int My_index, int Bob_index, 
   ClientInfoStruct *Client_CIArr, int port_number, int num_CIArr)
// int num_eCt_nonce_bytes, int num_eCt) 
   {
   int Bob_socket_desc = -1;

printf("AliceTransferDriver(): BEGIN!\n"); fflush(stdout);
#ifdef DEBUG
#endif
 
// Sanity checks. Don't allow Alice to specify herself for the transfer operations
   if ( Bob_index == My_index )
      { 
      printf("ERROR: AliceTransferDriver(): Can NOT specify yourself for the value transfer operation!\n"); 
      return 0; 
      }
   if ( Bob_index < 0 || Bob_index >= num_CIArr )
      { 
      printf("ERROR: AliceTransferDriver(): Bob's ID must be between 0 and %d\tExcluding myself %d!\n", num_CIArr - 1, My_index); 
      return 0; 
      }

// Sanity check
   if ( Bob_index == -1 )
      { printf("ERROR: AliceTransferDriver(): 'Bob' index INVALID %d!\n", Bob_index); exit(EXIT_FAILURE); }

// Open socket to Bob. Keep trying until Bob gets to a point where he is listening. With polling, this should happen right away.
   int num_retries = 0;
   while ( OpenSocketClient(max_string_len, Client_CIArr[Bob_index].IP, port_number, &Bob_socket_desc) < 0 )
      { 
      printf("INFO: AliceTransferDriver(): Alice trying to connect to Bob to exchange IDs!\n"); fflush(stdout); 
      usleep(500000); 
      num_retries++;
      if ( num_retries > 500 )
         exit(EXIT_FAILURE);
      }

// Send the initial transaction request which starts the PeerTrust authentication process.
   if ( SockSendB((unsigned char *)"ALICE-BOB-AUTHENTICATE", strlen("ALICE-BOB-AUTHENTICATE") + 1, Bob_socket_desc) < 0 )
      { printf("ERROR: AliceTransferDriver(): Failed to send 'ALICE-BOB-AUTHENTICATE' to Bob!\n"); exit(EXIT_FAILURE); }

// Alice and Bob must have ATs for each other. If they don't, this fails and nothing more is done. This routine sends an 
// ALICE-BOB-AUTHENTICATE message and calls ExchangeIDsConfirmATExists. 
// TO_DO: KEEP THE SOCKET OPEN -- tried this but didn't work.
   if ( AliceDoZeroTrust(max_string_len, SHP_ptr, Client_CIArr, num_CIArr, Bob_index, port_number, Bob_socket_desc, 
      My_index) == 0 )
      {
      printf("ERROR: AliceTransferDriver(): Alice FAILED with Peer/Zero Trust to authenticate Bob -- Aborting transaction!\n"); 
      close(Bob_socket_desc);
      return 0;
      }

   close(Bob_socket_desc);


//   while ( OpenSocketClient(max_string_len, Client_CIArr[Bob_index].IP, port_number, &Bob_socket_desc) < 0 )
//      { 
//      printf("INFO: AliceTransferDriver(): Alice trying to connect to Bob to exchange IDs!\n"); fflush(stdout); 
//      usleep(500000); 
//      num_retries++;
//      if ( num_retries > 500 )
//         exit(EXIT_FAILURE);
//      }

// If Alice doesn't have enough eCash to support her request to pay Bob, return immediately and fail. Also, if Bob's IP doesn't
// exist, fail. This routine sends a ALICE-PAY-BOB message to Bob AND ASSUMES Bob_socket connection is STILL OPEN from the call
// to AliceDoZeroTrust (FullTrust) operation above.
//   int status;
//   status = AliceTransfer(max_string_len, SHP_ptr, Bob_index, num_eCt_nonce_bytes, num_eCt, Client_CIArr, My_index, 
//      Bob_socket_desc);

// Close Bob's socket descriptor.
//   close(Bob_socket_desc);


printf("AliceTransferDriver(): DONE!\n"); fflush(stdout);
#ifdef DEBUG
#endif

   return 1;
   }


// ========================================================================================================
// ========================================================================================================
// ========================================================================================================
SRFHardwareParamsStruct SHP;

int main(int argc, char *argv[])
   {
   volatile unsigned int *CtrlRegA;
   volatile unsigned int *DataRegA;
   unsigned int ctrl_mask;

   char *MyName;
   char *Bank_IP;
   char *My_IP;
   char *IP_list_filename;
   char *temp_str;

   int Bank_socket_desc = 0;
   ClientInfoStruct *Client_CIArr = NULL;
   int num_customers = 0;
   int num_TTPs = 0, num_CIArr = 0;

   int My_socket_desc;
   int AliceBob_socket_desc;
   struct sockaddr_in AliceBob_addr;
 
   int port_number;

   int nonce_base_address;
   int num_eCt_nonce_bytes;
   int num_KEK_authen_nonce_bytes; 

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
   int RandomCustomer_index; 

// Trust protocol
   sqlite3 *DB_Trust_AT;
   char *DB_name_Trust_AT;
   Allocate1DString(&DB_name_Trust_AT, MAX_STRING_LEN);

// PUF-Cash V3.0 protocol 
   sqlite3 *DB_PUFCash_V3;
   char *DB_name_PUFCash_V3;
   Allocate1DString(&DB_name_PUFCash_V3, MAX_STRING_LEN);

   float command_line_SC;

   Allocate1DString(&MyName, MAX_STRING_LEN);
   Allocate1DString(&My_IP, MAX_STRING_LEN);
   Allocate1DString(&Bank_IP, MAX_STRING_LEN);

// ======================================================================================================================
// COMMAND LINE
// ======================================================================================================================
   if ( argc != 4 )
      {
      printf("Parameters: MyName (Alice/Bob/Jim/Cyrus/George) -- Device IP (192.168.1.10) -- Bank IP (192.168.1.20)\n");
      exit(EXIT_FAILURE);
      }

   strcpy(MyName, argv[1]);
   strcpy(My_IP, argv[2]);
   strcpy(Bank_IP, argv[3]);

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

   Allocate1DString(&IP_list_filename, MAX_STRING_LEN);
   Allocate1DString(&temp_str, MAX_STRING_LEN);

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

// SET TO WHATEVER bitstream you program with.
//   int my_bitstream;
//   my_bitstream = 0;

   char AES_IV[AES_IV_NUM_BYTES] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

// The PL-side TRNG_LFSR is 64 bits. 
   TRNG_LFSR_seed = 1;

// NOTE: ASSUMPTION:
//    NUM_XOR_NONCE_BYTES   <=  num_eCt_nonce_bytes   <=   SE_TARGET_NUM_KEY_BITS/8   <=   NUM_REQUIRED_PNDIFFS/8
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

// Enable/disable debug information.
   DUMP_BITSTRINGS = 0;
   DEBUG_FLAG = 0;
// ====================================================== PARAMETERS ====================================================
// Sanity check Trust protocols. We also assume that the SHA-3 hash input and output are the same size as the AK_A/MHK_As, 
// which must be the same size as the KEK key (since we use KEK_Regen() below to regenerate it). 
   if ( HASH_IN_LEN_BITS != KEK_TARGET_NUM_KEY_BITS || HASH_OUT_LEN_BITS != KEK_TARGET_NUM_KEY_BITS )
      { 
      printf("ERROR: HASH_IN_LEN_BITS %d MUST be equal to HASH_OUT_LEN_BIT %d MUST be equal to KEK_TARGET_NUM_KEY_BITS %d\n", 
         HASH_IN_LEN_BITS, HASH_OUT_LEN_BITS, KEK_TARGET_NUM_KEY_BITS); exit(EXIT_FAILURE); 
      }

// Sanity check, constraint must be honored because of space allocations.
//    NUM_XOR_NONCE_BYTES   <=  num_eCt_nonce_bytes   <=   SE_TARGET_NUM_KEY_BITS/8   <=   NUM_REQUIRED_PNDIFFS/8
//           8                         16                            32                              256
   if ( !(NUM_XOR_NONCE_BYTES <= num_eCt_nonce_bytes && num_eCt_nonce_bytes <= SE_TARGET_NUM_KEY_BITS/8 && 
      SE_TARGET_NUM_KEY_BITS/8 <= NUM_REQUIRED_PNDIFFS/8) )
      { 
      printf("ERROR: Constraint violated: NUM_XOR_NONCE_BYTES %d <= num_eCt_nonce_bytes %d && \n\
         num_eCt_nonce_bytes %d <= SE_TARGET_NUM_KEY_BITS/8 %d <= NUM_REQUIRED_PNDIFFS/8 %d\n",
         NUM_XOR_NONCE_BYTES, num_eCt_nonce_bytes, num_eCt_nonce_bytes, SE_TARGET_NUM_KEY_BITS/8, NUM_REQUIRED_PNDIFFS/8);
      exit(EXIT_FAILURE);
      }

   printf("Parameters: This Device IP %s\tBank IP %s\tFIX PARAMS %d\tNum Sams %d\tPCR/PBD/PO %d\n", My_IP, Bank_IP, fix_params, num_sams, PCR_or_PBD_or_PO); fflush(stdout);

// The number of samples is set BELOW after CtrlRegA is given an address.
   ctrl_mask = 0;

// For handling Ctrl-C. We MUST exit gracefully to keep the hardware from quitting at a point where the
// fine phase of the MMCM is has not be set back to 0. If it isn't, then re-running this program will
// likely fail because my local fine phase register (which is zero initially after a RESET) is out-of-sync 
// with the MMCM phase (which is NOT zero).
   signal(SIGINT, intHandler);

// When we save output file, this tells us what we used.
   printf("PARAMETERS: PCR/PBD %d\tSE Target Num Bits %d\n\n", PCR_or_PBD_or_PO, SE_TARGET_NUM_KEY_BITS); fflush(stdout);

// Open up the memory mapped device so we can access the GPIO registers.
   int fd = open("/dev/mem", O_RDWR|O_SYNC);
   if (fd < 0) 
      { printf("ERROR: /dev/mem could NOT be opened!\n"); exit(EXIT_FAILURE); }

// Add 2 for the DataReg (for an SpreadFactor of 8 bytes for 32-bit integer variables)
   DataRegA = (volatile unsigned int *)mmap(0, getpagesize(), PROT_READ|PROT_WRITE, MAP_SHARED, fd, GPIO_0_BASE_ADDR);
   CtrlRegA = DataRegA + 2;

// ********************************************************************************************************** 
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

// PUF-Cash V3.0 protocol 
   rc = sqlite3_open(":memory:", &DB_PUFCash_V3);
   if ( rc != 0 )
      { printf("Failed to open PUFCash_V3 Database: %s\n", sqlite3_errmsg(DB_PUFCash_V3)); sqlite3_close(DB_PUFCash_V3); exit(EXIT_FAILURE); }

#ifdef DEBUG
   printf("Reading filesystem database '%s' into memory!\n", DB_name_PUFCash_V3); fflush(stdout);
#endif

   if ( LoadOrSaveDb(DB_PUFCash_V3, DB_name_PUFCash_V3, 0) != 0 )
      { printf("Failed to open and copy into memory '%s': ERR: %s\n", DB_name_PUFCash_V3, sqlite3_errmsg(DB_PUFCash_V3)); sqlite3_close(DB_PUFCash_V3); exit(EXIT_FAILURE); }

// =========================
// Set some of the params in the data structure.
   SHP.CtrlRegA = CtrlRegA;
   SHP.DataRegA = DataRegA;
   SHP.ctrl_mask = ctrl_mask;

// 10_11_2022: For testing COBRA and RangeConstant -- added this field. Can be used in other places for PUF-Cash too.
   StringCreateAndCopy(&(SHP.My_IP), My_IP);

// After device authenticates successfully with IA, IA sends its ID from the NAT database to the device. The device will use this as it's ID.
   SHP.chip_num = -1;

// This is also filled in by GenLLK(). THIS CAN BE DONE during device provisioning where the challenge are drawn from the ANONYMOUS DB, 
// or by doing an anonymous authentication at any time with the server.
   SHP.anon_chip_num = -1;

   SHP.DB_Challenges = DB_Challenges;
   SHP.DB_name_Challenges = DB_name_Challenges;

   SHP.use_database_chlngs = use_database_chlngs;
   SHP.DB_design_index = design_index;
   SHP.DB_ChallengeSetName = ChallengeSetName;
   SHP.DB_ChallengeGen_seed = ChallengeGen_seed; 

   SHP.DB_Trust_AT = DB_Trust_AT;
   SHP.DB_name_Trust_AT = DB_name_Trust_AT;

   SHP.DB_PUFCash_V3 = DB_PUFCash_V3;
   SHP.DB_name_PUFCash_V3 = DB_name_PUFCash_V3;
   SHP.eCt_num_bytes = ECT_NUM_BYTES;

// Alice's withdrawal amount
   SHP.Alice_EWA = NULL;
   SHP.Alice_K_AT = NULL;

// Other protocol. This must also match the length of KEK_TARGET_NUM_KEY_BITS/8. Might make more sense to just set it to that even 
// though we use KEK session key generation to generate the MAT_LLK.
//   SHP.MAT_LLK_num_bytes = SE_TARGET_NUM_KEY_BITS/8;

// Other protocol. This must also match the length of KEK_TARGET_NUM_KEY_BITS/8. Might make more sense to just set it to that even 
// though we use KEK session key generation to generate the PHK_A_nonce.
//   SHP.PHK_A_num_bytes = SE_TARGET_NUM_KEY_BITS/8;

// ZeroTrust protocol. See GenLLK -- NOT SE_TARGET_NUM_BYTES.
   SHP.ZHK_A_num_bytes = KEK_TARGET_NUM_KEY_BITS/8;

// Added this when updating GenLLK function. 
   SHP.KEK_LLK_num_bytes = KEK_TARGET_NUM_KEY_BITS/8;

// For POP
   SHP.POP_LLK_num_bytes = KEK_TARGET_NUM_KEY_BITS/8;

// These we will eventually come from the verifier via a message. 
   SHP.num_PIs = num_PIs;
   SHP.num_POs = num_POs;

   SHP.fix_params = fix_params;

   SHP.num_required_PNDiffs = NUM_REQUIRED_PNDIFFS;

   SHP.num_SF_bytes = NUM_REQUIRED_PNDIFFS * SF_WORDS_TO_BYTES_MULT;
   SHP.num_SF_words = NUM_REQUIRED_PNDIFFS; 

// 1_1_2022: If TRIMCODE_CONSTANT is <= 32, then we can preserve on precision bit in the iSpreadFactors for the device, else we cannot preserve any.
   if ( TRIMCODE_CONSTANT <= 32 )
      SHP.iSpreadFactorScaler = 2;
   else
      SHP.iSpreadFactorScaler = 1;

   if ( (SHP.iSpreadFactors = (signed char *)calloc(SHP.num_SF_words, sizeof(signed char))) == NULL )
      { printf("ERROR: Failed to allocate storage for iSpreadFactors!\n"); exit(EXIT_FAILURE); }

   if ( (SHP.verifier_SHD = (unsigned char *)calloc(SHP.num_required_PNDiffs/8, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for verifier_SHD!\n"); exit(EXIT_FAILURE); }
   if ( (SHP.verifier_SBS = (unsigned char *)calloc(SHP.num_required_PNDiffs/8, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for verifier_SBS!\n"); exit(EXIT_FAILURE); }
   if ( (SHP.device_SHD = (unsigned char *)calloc(SHP.num_required_PNDiffs/8, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for device_SHD!\n"); exit(EXIT_FAILURE); }
   if ( (SHP.device_SBS = (unsigned char *)calloc(SHP.num_required_PNDiffs/8, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for device_SBS!\n"); exit(EXIT_FAILURE); }
   SHP.verifier_SHD_num_bytes = 0;
   SHP.verifier_SBS_num_bytes = 0;
   SHP.device_SHD_num_bytes = 0;
   SHP.device_SBS_num_bits = 0; 

// Note: MAX_GENERATED_NONCE_BYTES MUST BE LARGER THAN NUM_XOR_NONCE_BYTES.
   SHP.nonce_base_address = nonce_base_address;
   SHP.max_generated_nonce_bytes = MAX_GENERATED_NONCE_BYTES; 
   SHP.num_required_nonce_bytes = NUM_XOR_NONCE_BYTES; 

// This is filled in by CollectPNs as the hardware reads nonce bytes.
   SHP.num_device_n1_nonces = 0;
   if ( (SHP.device_n1 = (unsigned char *)calloc(SHP.max_generated_nonce_bytes, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for verifier_n2!\n"); exit(EXIT_FAILURE); }
   if ( (SHP.verifier_n2 = (unsigned char *)calloc(SHP.num_required_nonce_bytes, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for verifier_n2!\n"); exit(EXIT_FAILURE); }
   if ( (SHP.XOR_nonce = (unsigned char *)calloc(SHP.num_required_nonce_bytes, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for XOR_nonce!\n"); exit(EXIT_FAILURE); }

   SHP.vec_chunk_size = CHLNG_CHUNK_SIZE; 
   SHP.XMR_val = XMR_VAL;

   memcpy((char *)SHP.AES_IV, (char *)AES_IV, AES_IV_NUM_BYTES);

   SHP.SE_target_num_key_bits = SE_TARGET_NUM_KEY_BITS; 
   SHP.SE_final_key = NULL;
   SHP.authen_min_bitstring_size = AUTHEN_MIN_BITSTRING_SIZE;

// KEK information presumably stored in NVM for regeneration, preserved here in separate fields.
   SHP.KEK_target_num_key_bits = KEK_TARGET_NUM_KEY_BITS;
   SHP.KEK_final_enroll_key = NULL;
   SHP.KEK_final_regen_key = NULL;
   SHP.KEK_final_XMR_SHD = NULL;

// 5_11_2021: For tracking the number of minority bit flips with KEK FSB mode (NOT NE mode).
   SHP.KEK_BS_regen_arr = NULL;

   SHP.KEK_final_SpreadFactors_enroll = NULL;

   SHP.KEK_num_vecs = 0;
   SHP.KEK_num_rise_vecs = 0;;
   SHP.KEK_has_masks = 1;
   SHP.KEK_first_vecs_b = NULL;
   SHP.KEK_second_vecs_b = NULL;
   SHP.KEK_masks_b = NULL;
   if ( (SHP.KEK_XOR_nonce = (unsigned char *)calloc(SHP.num_required_nonce_bytes, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for XOR_nonce!\n"); exit(EXIT_FAILURE); }
   SHP.num_direction_chlng_bits = NUM_DIRECTION_CHLNG_BITS;

// For Special KEK mode data from hardware. Will eventually be eliminated once I change the VHDL to do this in hardware.
   SHP.KEK_num_iterations = 0;

// Allocate space for the authentication nonce received from server during device authentication or generated locally
// for transmission to server for server authentication.
   if ( (SHP.KEK_authentication_nonce = (unsigned char *)calloc(num_KEK_authen_nonce_bytes, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for KEK_authentication_nonce!\n"); exit(EXIT_FAILURE); }
   SHP.num_KEK_authen_nonce_bits = num_KEK_authen_nonce_bytes*8;
   SHP.num_KEK_authen_nonce_bits_remaining = SHP.num_KEK_authen_nonce_bits;
   SHP.DA_cobra_key = NULL;

// XMR_SHD that is generated during KEK_DeviceAuthentication during each iteration (to be concatenated to a larger blob and 
// sent to server).
   if ( (SHP.KEK_authen_XMR_SHD_chunk = (unsigned char *)calloc(SHP.num_required_PNDiffs/8, sizeof(unsigned char))) == NULL )
      { printf("ERROR: Failed to allocate storage for KEK_authen_XMR_SHD_chunk!\n"); exit(EXIT_FAILURE); }

   SHP.num_vecs = 0;
   SHP.num_rise_vecs = 0;;
   SHP.has_masks = 1;
   SHP.first_vecs_b = NULL;
   SHP.second_vecs_b = NULL;
   SHP.masks_b = NULL;

//   SHP.PeerTrust_LLK = NULL;
   SHP.ZeroTrust_LLK = NULL;

   SHP.param_LFSR_seed_low = 0;
   SHP.param_LFSR_seed_high = 0;
   SHP.param_RangeConstant = RANGE_CONSTANT;
   SHP.param_SpreadConstant = SPREAD_CONSTANT;
   SHP.param_Threshold = THRESHOLD_CONSTANT;
   SHP.param_TrimCodeConstant = TRIMCODE_CONSTANT;
   SHP.param_PCR_or_PBD_or_PO = PCR_or_PBD_or_PO;

// 10_28_2022: Get the personalized ScalingConstant from the command line. NOTE: This is passed into the state machine as a FIXED POINT value
// with SCALING_PRECISION_NB bits of precision (currently 11 bits), xxxxx.xxxxxxxxxxx. Convert from floating point to scaled integer. So a 
// scaling value of 1.0 will be equal to 1 << SCALING_PRECISION_NB, which is 2^11 = 2048 (0000100000000000). NOTE: MyScalingConstant VALUE MUST BE POSITIVE and 
// between 1.0 and x.0 (current 5.0) above. So values here are between 4096 and 20480.
// 11_12_2022: Adding this 'do_scaling' flag, and initializing it to 0. COBRA and possibly SKE (PARCE) are the only functions that set it to 1.
   SHP.do_scaling = 0;
   SHP.MyScalingConstant = (int)(command_line_SC * pow(2.0, (float)SCALING_PRECISION_NB));

// Sanity check
   if ( SHP.MyScalingConstant < 0 || SHP.MyScalingConstant > (MAX_SCALING_VALUE << SCALING_PRECISION_NB) )
      { printf("ERROR: MyScalingConstant MUST be >= 0 and <= %d\n", MAX_SCALING_VALUE << SCALING_PRECISION_NB); exit(EXIT_FAILURE); }

#ifdef DEBUG
if ( SHP.MyScalingConstant == (1 << SCALING_PRECISION_NB) )
   { printf("NO SCALING WILL OCCUR: ScalingConstant IS 1.0\n"); fflush(stdout); }
else
   { printf("ScalingConstant: %f\tScaled FixedPoint %d\n", command_line_SC, SHP.MyScalingConstant); fflush(stdout); }
#endif

// The PL-side TRNG_LFSR is 64 bits. Note that we currently only suport loading the low-order 16-bits of the seed register. 
   SHP.TRNG_LFSR_seed = TRNG_LFSR_seed;

// For frequency statistics of the TRNG. Need to declare these here for the TTP -- can NOT make them static in multi-threaded apps.
   SHP.num_ones = 0; 
   SHP.total_bits = 0; 
   SHP.iteration = 0;

// 10_31_2021: We are now using a seed to specify the vector sequence on the device, TTP and verifier. When challenges are selected, we depend
// on the sequence returned by rand() to be the same no matter where this routine runs, device, TT or verifier. The verifier and TTP are multi-threaded
// and therefore it is possible that multiple threads call this routine simultaneously, interrupting the sequence generated by rand() (rand is NOT re-entrant).
// If this occurs, then the vector challenges used by the, e.g., verifier and device will be different and the security function will fail. When the device
// calls this function, the mutex is NULL. 
   SHP.GenChallenge_mutex_ptr = NULL;

   SHP.do_COBRA = DO_COBRA;

   SHP.DUMP_BITSTRINGS = DUMP_BITSTRINGS;
   SHP.DEBUG_FLAG = DEBUG_FLAG;


// ================================================================================================
// Generate an LLK with the Bank for PeerTrust. This is the LLK that we will use as input to the 
// SHA-3 hash (plus a nonce) to generate ZHK_A_nonce (keyed-hash of KK_A -- which is the KEK key 
// generated in FSB mode). Also need a 'HOSE' LLK (hardware-oriented secure enclave) for Propagation
// of Providence and PUF-Cash.

// Generate the KEK long-lived KEK, either by running KEK_Enroll by communicating with IA to get challenges 
// (if no Chlng info exists in the AuthenticationToken.db), or by reading out the LLK Chlng information 
// and running KEK_Regen. Called by both the device and TTP.

// Setting allow_multiple_LLK to 1 allows MORE THAN one LLK_type = 2 Chlngs to exist. There should be 
// only one although I have integrated a method to associate a Chlng number with the PeerTrust_LLKs,
// so in the future, we can allow more than one.
//
// NOTE: GenLLK generates the PeerTrust_LLK and where we obtain Alice's unique id (chip_num) from the 
// NON-anonymous DB. I added an ID transfer from IA in DA_Report, which is called as part of device 
// authentication, i.e., KEK_DeviceAuthentication_SKE. The SHP.chip_num (SHP_ptr->chip_num) field is filled in. 
// The LLK_type param here indicates whether we are saving the PeerTrust LLK (2) 
   int allow_multiple_LLK = 0;
   int open_socket = 1;
   int LLK_type = 2;
   int zero_trust_LLK_index;
   zero_trust_LLK_index = GenLLK(MAX_STRING_LEN, &SHP, open_socket, Bank_IP, port_number, Bank_socket_desc, 
      allow_multiple_LLK, LLK_type, SHP.KEK_LLK_num_bytes);

// Save the new chip num to the anon_chip_num field and restore the non-anonymous to the chip_num field.
   SHP.anon_chip_num = SHP.chip_num;

printf("\nMyChip NON-ANONYMOUS server ID %d\n", SHP.chip_num); fflush(stdout);
#ifdef DEBUG
#endif

// If NO AT elements exist in Alice's ZeroTrust table, then carry out enrollment. This is NOT necessary when we NEED to do 
// enrollment. Only doing this to prevent ZeroTrust_Enroll from being called over and over again during testing.

// Check if ATs exist. This flag dominates. Only the number of NOT USED ATs are returned if set
   int report_tot_num_ATs_only = 1;

// These flags irrelevant here.
   int get_only_customer_AT = 0;
   int return_customer_AT_info = 0;

   int customer_chip_num = -1;

// NOTE: We MUST DO the authentication here for a customer.
   int *chip_num_arr = NULL;
   int *chlng_num_arr = NULL;
   unsigned char **ZHK_A_nonce_arr = NULL;
   unsigned char **nonce_arr = NULL;
   int unused;
   int is_TTP = 0;
   Bank_socket_desc = 0;
   unsigned char *session_key = NULL;
   if ( ZeroTrustGetCustomerATs(MAX_STRING_LEN, SHP.DB_Trust_AT, &chip_num_arr, &chlng_num_arr, SHP.ZHK_A_num_bytes, 
      &ZHK_A_nonce_arr, &nonce_arr, get_only_customer_AT, customer_chip_num, return_customer_AT_info, report_tot_num_ATs_only, &unused) == 0 )
      {
printf("No customer ATs found! Enrolling\n"); fflush(stdout);
#ifdef DEBUG
#endif

      ZeroTrust_Enroll(MAX_STRING_LEN, &SHP, Bank_IP, port_number, zero_trust_LLK_index, is_TTP, Bank_socket_desc, session_key);
      }


printf("GenLLK(): MyChip ANONYMOUS server ID %d\n", SHP.anon_chip_num); fflush(stdout);
#ifdef DEBUG
#endif

// Do ZeroTrust authentication between Alice and Bob. First get device IPs from the server.
   int CIA_index, TTP_index; 

// This routine fetches a list of TTP and CUSTOMER IPs from the Bank and allocates space for the CIArr. It sends ALICE-GET-TTP-IPS first
// and then 'ALICE-GET-CUSTOMER-IPS' to the Bank, authenticates and generates a session key (IPs are encrypted). The Client_CIArr is 
// filled in with IP information. A field called 'self' is set to 1 if a customer element refers to THIS device. TTP(s) occupy the
// first element(s) in the array. NOTE: Client_CIArr MUST be set to NULL here since we use re-allocate in this routine.
   Client_CIArr = NULL;
   AliceGetClient_IPs(MAX_STRING_LEN, &SHP, Bank_IP, port_number, &Client_CIArr, MAX_CONNECT_ATTEMPTS, 
      IP_LENGTH, My_IP, &num_TTPs, &num_customers);

// PUF-Cash V3.0 require at least one TTP.
   if ( num_TTPs != 1 )
      { printf("ERROR: PUF-Cash V3.0 supports only 1 TTP!\tBank returned %d TTPs!\n", num_TTPs); exit(EXIT_FAILURE); }

// ASSUMES THERE IS ONLY 1 TTP, at index 0 in the Client_CIArr.
   TTP_index = 0;

// Sanity check. 
   if ( Client_CIArr[TTP_index].IP == NULL )
      { printf("ERROR: IP for TTP_index %d is NULL!\n", TTP_index); exit(EXIT_FAILURE); }

// PUF-Cash V3.0 requires at least two customers.
   if ( num_customers < 2 )
      { printf("ERROR: PUF-Cash V3.0 requires at least two customers!\tBank returned %d customers!\n", num_customers); exit(EXIT_FAILURE); }

   num_CIArr = num_TTPs + num_customers;

#ifdef DEBUG
printf("Alice fetched %d TTP IPs (MUST BE 1)\tAnd %d Customers\tAnd %d total CIArr elements!\n", 
   num_TTPs, num_customers, num_CIArr); fflush(stdout);
#endif

// ********* TESTING ONLY. For PeerTrust, find first element that is NOT myself so we can automate process below. This is used by Alice to 
// select a Bob to do a payment transaction with. 
   RandomCustomer_index = -1;
   int My_index = -1;
   for ( CIA_index = 0; CIA_index < num_CIArr; CIA_index++ )
      {

// Alice keeps searching until we find a valid Bob -- using first non-TTP and non-self for now. 
      if ( Client_CIArr[CIA_index].is_TTP == 0 && RandomCustomer_index == -1 && Client_CIArr[CIA_index].self == 0 )
         RandomCustomer_index = CIA_index;

// Find the index of Alice (self). Used below for various reasons.
      if ( Client_CIArr[CIA_index].self == 1 )
         {
         if ( My_index == -1 )
            My_index = CIA_index;
         else
            { printf("ERROR: Have TWO self indexes!\n"); exit(EXIT_FAILURE); }
         }

// Sanity check. Everyone must have an IP
      if ( Client_CIArr[CIA_index].IP == NULL )
         { printf("ERROR: IP for CIA_index %d is NULL!\n", CIA_index); exit(EXIT_FAILURE); }

// Sanity check. A customer can NOT be a TTP.
      if ( Client_CIArr[CIA_index].is_TTP == 0 && strcmp(Client_CIArr[TTP_index].IP, Client_CIArr[CIA_index].IP) == 0 )
         { printf("ERROR: TTP with IP %s cannot ALSO be a customer!\n", Client_CIArr[TTP_index].IP); exit(EXIT_FAILURE); }
      }

#ifdef DEBUG
printf("Alice fetched %d Customer IPs\tFound SELF at index %d\tFound a unique 'RandomCustomer' at index %d!\n", 
   num_customers, My_index, RandomCustomer_index); fflush(stdout);
#endif

   if ( My_index == -1 )
      { printf("ERROR: FAILED to find a valid 'SELF' %d!\n", My_index); exit(EXIT_FAILURE); }
   if ( RandomCustomer_index == -1 )
      { printf("ERROR: FAILED to find a valid 'Bob' %d!\n", RandomCustomer_index); exit(EXIT_FAILURE); }


printf("\n");
printf("Bank returned %d TTP IPs!\n", num_TTPs); fflush(stdout);
printf("Bank returned %d Customer IPs!\n", num_customers); fflush(stdout);

// List indexes that Alice/Bob can choose in menu below.
printf("Indexes that exist for menu selection options:\n");
for ( CIA_index = 0; CIA_index < num_CIArr; CIA_index++ )
   {
   if ( Client_CIArr[CIA_index].is_TTP == 1 )
      printf("TTP: Index %d\t(DO NOT CHOOSE)\n", CIA_index);
   else if ( Client_CIArr[CIA_index].self == 1 )
      printf("Self: Index %d\t(DO NOT CHOOSE)\n", CIA_index);
   else 
      printf("AVAILABLE for menu selection: Index %d\n", CIA_index);
   }
printf("\n");
fflush(stdout);
#ifdef DEBUG
#endif


// ================================================
// LOOP
// ================================================
   int iteration;
   int client_wants_to_connect;
   int first_time_stream = 1;
   int num_iterations;
   int option;
   int main_menu_blocks;
   struct transfer trn;

   int num_eCt;

   main_menu_blocks = 0;

// Set to -1 for infinite number of iterations.
   num_iterations = -1;

   for ( iteration = 0; (iteration < num_iterations || num_iterations == -1) && keepRunning == 1; iteration++ )
      {

#ifdef DEBUG
printf("ITERATION %d\n", iteration); fflush(stdout);
#endif

#ifdef DEBUG
printf("Checking for incoming connections from any device ....\n\n"); fflush(stdout);
#endif

// Serve-up a socket connection to wait for connection requests from any device. This is a non-blocking call if last parameter
// is set to 1. If a connection requests exists, we connect and this routine returns 1, otherwise it returns 0.
      client_wants_to_connect = OpenSocketServer(MAX_STRING_LEN, &My_socket_desc, My_IP, port_number, &AliceBob_socket_desc, 
         &AliceBob_addr, !first_time_stream, 1);
      first_time_stream = 0;

// As bob, process incoming transaction requests from Alice.
      if ( client_wants_to_connect == 1 )
         {

printf("Connect client IP %s\n", inet_ntoa(AliceBob_addr.sin_addr)); fflush(stdout);
#ifdef DEBUG
#endif

         int keep_socket_open = 0;
         ProcessInComingRequest(MAX_STRING_LEN, &SHP, AliceBob_socket_desc, port_number, &AliceBob_addr, Client_CIArr, 
            num_CIArr, My_index, &keep_socket_open);

// Close socket descriptor.
         if ( keep_socket_open == 0 )
            close(AliceBob_socket_desc);
         continue;
         }

// Check that SRF is ready. 
      if ( DEBUG_FLAG == 1 )
         {
         if ( (*DataRegA & (1 << IN_SM_READY)) == 0 )
            { printf("\t\tERROR: PUF Engine is NOT ready!\n"); exit(EXIT_FAILURE); }
         else
            { printf("\t\tHARDWARE IS READY!\n\n"); fflush(stdout); }
         }

// Do a sync after each transaction to make sure the SD card is not getting corrupt with partial writes.
      system("sync");

// This is a non-blocking poll for input (with main_menu_blocks is set to 0).
      option = main_menu(main_menu_blocks, iteration);

// This just slows down the loop. 
      if ( option != MENU_NOOP )
         usleep(500000);


// ====================================================================
// ====================================================================
      switch (option)
         {

// ======================================
// ======================================
// Alice/Bob Withdrawal money from FI (TTP_DB.elf)
         case MENU_WITHDRAW:

            num_eCt = get_withdraw();

#ifdef DEBUG
printf("\tWITHDRAWAL AMOUNT %d\n", num_eCt); fflush(stdout); 
#endif

// This is for a 'cancel' request from the GUI function get_withdraw().
            if ( num_eCt == -1 )
               continue;

// Do NOT allow Alice to withdraw in any increment other than this min amount, e.g., $5
            if ( (num_eCt % MIN_WITHDRAW_INCREMENT) != 0 )
               {
               printf("ERROR: Requested withdrawal %d\tYou MUST withdraw in increments of %d!\n", 
                  num_eCt, MIN_WITHDRAW_INCREMENT); fflush(stdout); 
               withdraw_fail();
               continue;
               }

// Alice authenticates with the TTP and then carries out the withdrawal. 
            if ( AliceWithdrawal(MAX_STRING_LEN, &SHP, TTP_index, My_index, Client_CIArr, port_number, num_CIArr, 
               num_eCt_nonce_bytes, num_eCt) == 0 )
               { printf("ERROR: Alice FAILED to withdraw %d eCt\n", num_eCt); fflush(stdout); }
            else
               { printf("ERROR: Alice SUCCEEDED in withdrawing %d eCt\n", num_eCt); fflush(stdout); }
            break;


// ======================================
// ======================================
// Alice pays Bob. 
         case MENU_TRANSFER:

            trn = get_transfer();

// If invalid amount, continue.
            if ( trn.amount == -1 )
               { continue; }

            int Bob_index = trn.id_to;
//            num_eCt = trn.amount;

// Driver for AliceTransfer where we authenticate and then carry out the transfer to Bob. 
//            if ( AliceTransferDriver(MAX_STRING_LEN, &SHP, My_index, RandomCustomer_index, Client_CIArr, port_number, num_CIArr) == 1 )
            if ( AliceTransferDriver(MAX_STRING_LEN, &SHP, My_index, Bob_index, Client_CIArr, port_number, num_CIArr) == 1 )
               transfer_success(trn);
            else
               transfer_fail();
            break;

// ======================================
// ======================================
// Contact IA (the Bank) to get a list of ATs that it stores, one unique AT that corresponds to each customer.
         case MENU_GET_AT:

// Open up a socket connection to the Bank. OpenSocketClient returns -1 on failure.
            while ( OpenSocketClient(MAX_STRING_LEN, Bank_IP, port_number, &Bank_socket_desc) < 0 )
               {
               printf("INFO: Alice waiting to connect to Bank to get PeerTrust Authentication Tokens!\n"); fflush(stdout); 
               usleep(200000);
               }

            unsigned char *session_key = NULL;
            int is_TTP = 0;
            ZeroTrust_GetATs(MAX_STRING_LEN, &SHP, Bank_socket_desc, is_TTP, session_key, NULL, -1); 
            break;

// ======================================
// ======================================
// NoOp: Used when main_menu() using poll (non-blocking) mode.
         case MENU_NOOP:
            break;

         default:
            printf("Not implemented\n\n");
         }

      }


// The Challenges DB is read-only.
   sqlite3_close(DB_Challenges);

   printf("Saving 'in memory' '%s' to filesystem!\n", SHP.DB_name_Trust_AT); fflush(stdout);
   if ( LoadOrSaveDb(SHP.DB_Trust_AT, SHP.DB_name_Trust_AT, 1) != 0 )
      { printf("Failed to store 'in memory' database to %s: %s\n", SHP.DB_name_Trust_AT, sqlite3_errmsg(SHP.DB_Trust_AT)); sqlite3_close(SHP.DB_Trust_AT); exit(EXIT_FAILURE); }
   sqlite3_close(SHP.DB_Trust_AT);

   printf("Saving 'in memory' '%s' to filesystem!\n", SHP.DB_name_PUFCash_V3); fflush(stdout);
   if ( LoadOrSaveDb(SHP.DB_PUFCash_V3, SHP.DB_name_PUFCash_V3, 1) != 0 )
      { printf("Failed to store 'in memory' database to %s: %s\n", SHP.DB_name_PUFCash_V3, sqlite3_errmsg(SHP.DB_PUFCash_V3)); sqlite3_close(SHP.DB_PUFCash_V3); exit(EXIT_FAILURE); }
   sqlite3_close(SHP.DB_PUFCash_V3);

   fflush(stdout);
   system("sync");

   return 0;
   }
