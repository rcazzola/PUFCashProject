// ========================================================================================================
// ========================================================================================================
// ******************************************* device_common.c ********************************************
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

#include <aes_128_ecb_openssl.h>
#include "aes_256_cbc_openssl.h"


// ========================================================================================================
// ========================================================================================================
// Get encrypted versions of the TTP or Ted IPs from the Bank.

int ReceiveIPInfo(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int Bank_socket_desc, 
   int *num_clients_ptr, char ***IPs_ptr, int ip_length, unsigned char *Session_key, char *my_IP,
   int *exclude_self_ptr)
   {
   char num_clients_str[max_string_len];
   unsigned char *eIPs, *fIPs;
   int IP_length_bytes;
   int i, j;

   int my_IP_pos, ip_cnter;

// Device has already authenticated to Bank in an earlier transaction so no need for that here.
#ifdef DEBUG
printf("ReceiveIPInfo: START!\n"); fflush(stdout);
#endif

#ifdef DEBUG
struct timeval t1, t2;
long elapsed; 
gettimeofday(&t2, 0);
#endif

// Sanity check. We expect IPs_ptr to be NULL.
   if ( *IPs_ptr != NULL )
      { printf("ERROR: ReceiveIPInfo(): Expected *IPs_ptr to be NULL!\n"); exit(EXIT_FAILURE); }

// Get the number of devices as a string first.
   if ( SockGetB((unsigned char *)num_clients_str, max_string_len, Bank_socket_desc) < 0 )
      { printf("ERROR: ReceiveIPInfo(): Failed to get 'num_clients_str' from Bank!\n"); exit(EXIT_FAILURE); }
   if ( sscanf(num_clients_str, "%d", num_clients_ptr) != 1 )
      { printf("ERROR: ReceiveIPInfo(): Failed to convert 'num_clients_str' to an integer!\n"); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("ReceiveIPInfo: num_clients from Bank: %d!\n", *num_clients_ptr); fflush(stdout);
#endif

// Sanity check. 
   if ( *num_clients_ptr == 0 )
      { printf("ERROR: ReceiveIPInfo(): Bank sent 0 device IPs!\n"); exit(EXIT_FAILURE); }

// PUF-Cash V2.0 stuff.
// 6_17_2020: Recent addition to allow only ONE TTP. If Bank provides ONLY 1 TTP IP, then force Master to be used 
// (disable exclude_self).
   if ( *num_clients_ptr == 1 )
      *exclude_self_ptr = 0;

// Each IP, e.g., 192.168.xxx.xxx, is at most 15 bytes long + NULL termination makes it 16. If, e.g., num_clients is
// 4 and ip_length is 16, then we need to allocate 4*16 = 64 bytes here.
   IP_length_bytes = (*num_clients_ptr * ip_length);
   IP_length_bytes += AES_INPUT_NUM_BYTES - (IP_length_bytes % AES_INPUT_NUM_BYTES);

   fIPs = Allocate1DUnsignedChar(IP_length_bytes);
   eIPs = Allocate1DUnsignedChar(IP_length_bytes);

// Get the flattened, encrypted packet of IPs.
   if ( SockGetB(eIPs, IP_length_bytes, Bank_socket_desc) != IP_length_bytes )
      { printf("ERROR: ReceiveIPInfo(): Get eIPs from Bank failed\n"); exit(EXIT_FAILURE); }

   decrypt_256(Session_key, SHP_ptr->AES_IV, eIPs, IP_length_bytes, fIPs);

#ifdef DEBUG
printf("IPs\n\t"); fflush(stdout);
for ( i = 0; i < (*num_clients_ptr) * ip_length; i++ )
   printf("%c ", fIPs[i]);
fflush(stdout);
#endif

// Copy the IPs into a flat array. We initialize to all zero above (calloc) so the strings will be NULL terminated. 
// Filter out any match that is found to match my_IP -- we don't want or need the IP of the device itself (when a 
// TTP calls this function) in this list, UNLESS exclude_self is 0, in which case, include it -- see note
// above. We also need to remove the session key so remember the position in the list where my_IP was found.
   my_IP_pos = -1;
   ip_cnter = 0;
   *IPs_ptr = NULL;
   for ( i = 0; i < *num_clients_ptr; i++ )
      {

// Check for match to my_IP. Note that my_IP is NULL when device_regeneration calls this routine. 
      if ( my_IP != NULL )
         {
         for ( j = 0; j < ip_length && (unsigned int)j < strlen(my_IP); j++ )
            if ( fIPs[i*ip_length + j] != my_IP[j] )
               break;
         if ( (unsigned int)j == strlen(my_IP) )
            {
            my_IP_pos = i;

// 6_17_2020: Keep this self IP when we WANT the Master TTP because 1) its the only TTP or 2) we choose to use it in
// n2 generation.
            if ( *exclude_self_ptr == 1 )
               continue;
            }
         }

// Allocate/reallocate storage for next element
      if ( (*IPs_ptr = (char **)realloc(*IPs_ptr, (ip_cnter + 1) * sizeof(char *))) == NULL )
         { printf("ERROR: ReceiveIPInfo(): realloc failed to allocate storage for IPs_ptr\n"); exit(EXIT_FAILURE); }
      if ( ((*IPs_ptr)[ip_cnter] = (char *)calloc(ip_length, sizeof(char))) == NULL )
         { printf("ERROR: ReceiveIPInfo(): calloc failed to allocate storage for IPs_ptr[i]\n"); exit(EXIT_FAILURE); }

      for ( j = 0; j < ip_length; j++ )
         (*IPs_ptr)[ip_cnter][j] = fIPs[i*ip_length + j];

// The storage is calloc'ed so they are be NULL-terminated strings.
#ifdef DEBUG
printf("ReceiveIPInfo(): %d) IP received from Bank: '%s'!\n", ip_cnter, (*IPs_ptr)[ip_cnter]); fflush(stdout);
#endif
      ip_cnter++; 
      }

// Sanity check. We MUST find our IP in the list sent from the Bank.
   if ( my_IP != NULL && my_IP_pos == -1 )
      { printf("ERROR: ReceiveIPInfo(): my_IP is NON-NULL %s but was NOT found in Bank's transmitted list!\n", my_IP); exit(EXIT_FAILURE); }

// Note 'my_IP' if given (when called from ttp_DB.c) is NOT counted above.
   *num_clients_ptr = ip_cnter;

   if ( eIPs != NULL )
      free(eIPs);
   if ( fIPs != NULL )
      free(fIPs);

// Send ACK to the Bank to allow it to continue
   if ( SockSendB((unsigned char *)"ACK", strlen("ACK") + 1, Bank_socket_desc) < 0  )
      { printf("ERROR: ReceiveIPInfo(): Failed to send 'ACK' to Bank!\n"); exit(EXIT_FAILURE); }

// Get ACK from Bank
   char ack_str[max_string_len];
   if ( SockGetB((unsigned char *)ack_str, max_string_len, Bank_socket_desc) < 0  )
      { printf("ERROR: ReceiveIPInfo(): Failed to get 'ACK' from Bank!\n"); exit(EXIT_FAILURE); }
   if ( strcmp(ack_str, "ACK") != 0 )
      { printf("ERROR: ReceiveIPInfo(): Failed to match 'ACK' string from Bank!\n"); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("ReceiveIPInfo: DONE!\n"); fflush(stdout);
#endif

#ifdef DEBUG
gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t2.tv_sec)*1000000 + t1.tv_usec-t2.tv_usec; printf("\tElapsed: ReceiveIPInfo() %ld us\n\n", (long)elapsed);
#endif

   return my_IP_pos; 
   }


// ========================================================================================================
// ========================================================================================================
// Allocate and initialize storage for a new ClientInfoStruct.

void AllocateAndInitialize_CIArr(ClientInfoStruct **Client_CIArr_ptr, int cur_num_CIAs)
   {
   if ( (*Client_CIArr_ptr = (ClientInfoStruct *)realloc(*Client_CIArr_ptr, (cur_num_CIAs + 1)*sizeof(ClientInfoStruct))) == NULL )
      { printf("ERROR: AllocateAndInitialize_CIArr(): Failed to allocate storage for Client_CIArr\n"); exit(EXIT_FAILURE); }

   (*Client_CIArr_ptr)[cur_num_CIAs].index = cur_num_CIAs;
   (*Client_CIArr_ptr)[cur_num_CIAs].chip_num = -1;
   (*Client_CIArr_ptr)[cur_num_CIAs].self = 0;
   (*Client_CIArr_ptr)[cur_num_CIAs].is_TTP = 0;

   (*Client_CIArr_ptr)[cur_num_CIAs].IP = NULL;

   (*Client_CIArr_ptr)[cur_num_CIAs].AliceBob_shared_key = NULL;

   return;
   }


// ========================================================================================================
// ========================================================================================================
// Alice and TTPs calls this at startup to get IPs for TTPs and Customers from the Bank. This routine also 
// allocates/reallocates the ClientInfoArr. 

int GetClient_IPs(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, unsigned char *session_key, 
   int Bank_socket_desc, ClientInfoStruct **CIArr_ptr, int max_connect_attempts, 
   int ip_length, char *my_IP, int *my_IP_pos_ptr, int *exclude_self_ptr, int start_index, int is_TTP)
   {
   char **Client_IPs = NULL;
   int client_index, num_clients;

#ifdef DEBUG
printf("GetClient_IPs: CALLED!\n"); fflush(stdout);
#endif

// Get and decrypt the list IPs sent by the Bank. Do NOT include the IP of this client in the list if exclude_self_ptr
// is set to 1. If set to 0 and Bank sends ONLY ONE IP, exclude_self_ptr is forced to 0. Store the position of 'my_IP' 
// in the return value so we can skip the session key fetching (only used if a TTP calls this routine). 
   *my_IP_pos_ptr = ReceiveIPInfo(max_string_len, SHP_ptr, Bank_socket_desc, &num_clients, &Client_IPs, ip_length, 
      session_key, my_IP, exclude_self_ptr);

// Sanity check. We MUST find one at least one client in the list sent from the Bank.
   if ( num_clients == 0 )
      { printf("ERROR: GetClient_IPs(): Number of Client IPs is 0!\n"); exit(EXIT_FAILURE); }

// Sanity check. We MUST always find 'my_IP' in the IPs sent by the Bank. 
   if ( my_IP != NULL && *my_IP_pos_ptr == -1 )
      { printf("ERROR: GetClient_IPs(): Failed to find Client IP in the list of IPs sent by Bank!\n"); exit(EXIT_FAILURE); }
   
// Check for at least the correct number of characters.
   int i;
   for ( i = 0; i < num_clients; i++ )
      if ( strlen(Client_IPs[i]) < 7 || strlen(Client_IPs[i]) > 15 )
         { 
         printf("ERROR: GetClient_IPs(): IP received from Bank MUST be between 7 characters and 15 characters => '%s'!\n", 
            Client_IPs[i]); 
         exit(EXIT_FAILURE); 
         }

// ======================================================
// Allocate storage for each TTP or customer and assign IP, etc.
   int client_cnter;
   for ( client_index = start_index, client_cnter = 0; client_cnter < num_clients; client_index++, client_cnter++ )
      {

#ifdef DEBUG
printf("Allocating CIArr storage for element %d\tRelative to the beginning %d\n", client_index, client_cnter); fflush(stdout);
#endif

// Allocate storage and initialize ClientInfoStruct element
      AllocateAndInitialize_CIArr(CIArr_ptr, client_index);

// Identify which of these structures corresponds to the caller.
      if ( *my_IP_pos_ptr == client_cnter )
         (*CIArr_ptr)[client_index].self = 1;
      else
         (*CIArr_ptr)[client_index].self = 0;

// Allocating maximum space for IP in case this IP is replaced in the future -- not needed really
      StringCreateAndCopy(&((*CIArr_ptr)[client_index].IP), Client_IPs[client_cnter]);

// 7_6_2022: Add this field since we have only ONE CIArr now for both TTPs and customers.
      (*CIArr_ptr)[client_index].is_TTP = is_TTP;
      }

// 7_6_2022: We read TTPs first and then customers. Add start_index to my_IP_pos_ptr since it is referenced from 0, otherwise
// it will not reference the correct CIArr element. Note that my_IP_pos_ptr is currently only used when this routine is called
// from ttp.c (not used when device_regeneration.c calls it) but it will be correct in either case. Also note that start_index
// is 0 when ttp.c call it. When device_regeneration.c call it to get TTP info, start_index is also 0 but ON THE SECOND call,
// it is offset past the TTPs read in on the first call.
   *my_IP_pos_ptr += start_index;

// Free up the list since we've copy these IP strings into the CIArr
   for ( i = 0; i < num_clients; i++ )
      if ( Client_IPs[i] != NULL )
         free(Client_IPs[i]);

#ifdef DEBUG
printf("GetClient_IPs(): DONE!\n"); fflush(stdout);
#endif

   return num_clients;
   }


// ========================================================================================================
// ========================================================================================================
// Alice and Bob (Alice and TTP) call this routine to get chip_nums and AT status from other parties. It is 
// a 3-way exchange:
//    1) Alice sends Bob/TTP her chip_num.
//    2) Bob/TTP responds with Yes/No regarding whether he has an AT for Alice, and then sends his chip_num
//    3) Alice responds with Yes/No regarding whether she has an AT for Bob/TTP

int ExchangeIDsConfirmATExists(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int chip_num_to_check, 
   int port_number, int I_am_Alice, int AliceBob_socket_desc, int *local_AT_status_ptr, int *remote_AT_status_ptr)
   {
   char request_str[max_string_len];
   int Alice_Bob_chip_num;
   int num_ATs;

   *remote_AT_status_ptr = -1;
   *local_AT_status_ptr = -1;

// Check the AT DB for a match to Alice or Bob's ID if set to 0, otherwise just get the total number of ATs in Alice's DB.
   int report_tot_num_ATs_only = 0;

// If set, we check if a specific customer AT is present (and is set as 'NOT USED'). With return_customer_AT_info set to 0, 
// we do NOT allocate storage for the AT information in the calls below.
   int get_only_customer_AT = 1;
   int return_customer_AT_info = 0;

printf("\nExchangeIDsConfirmATExists(): BEGIN\n\n"); fflush(stdout);
#ifdef DEBUG
#endif

// Sanity check
   if ( SHP_ptr->chip_num < 0 )
      { printf("ERROR: ExchangeIDsConfirmATExists(): My chip_num is NOT assigned %d!\n", SHP_ptr->chip_num); exit(EXIT_FAILURE); }

// ===================================================================================================================
// ALICE: When called by Alice, we already connected to Bob in the parent. Bob calls it to determine if Alice has an AT for Bob. 
   if ( I_am_Alice == 1 )
      {

printf("ExchangeIDsConfirmATExists(): Alice sending chip_num %d to Bob!\n", chip_num_to_check); fflush(stdout);
#ifdef DEBUG
#endif
// Send chip_num_to_check to Bob. NOTE: THIS device's chip_num is filled in by a call to GenLLK.
      sprintf(request_str, "%d", chip_num_to_check);
      if ( SockSendB((unsigned char *)request_str, strlen(request_str) + 1, AliceBob_socket_desc) < 0 )
         { printf("ERROR: ExchangeIDsConfirmATExists(): Failed to send Alice's unique id (chip_num) to Bob!\n"); exit(EXIT_FAILURE); }

// Get Bob's IA-assigned unique chip_num and whether he has a 'NOT USED' AT in his database for her.
      if ( SockGetB((unsigned char *)request_str, max_string_len, AliceBob_socket_desc) < 0 )
         { printf("ERROR: ExchangeIDsConfirmATExists(): Failed to get Bob's unique ID (chip_num) and Alice's AT status from Bob!\n"); exit(EXIT_FAILURE); }
      if ( sscanf(request_str, "%d %d", &Alice_Bob_chip_num, remote_AT_status_ptr) != 2 )
         { printf("ERROR: ExchangeIDsConfirmATExists(): Failed to extract Alice's unique ID and AT status from '%s'!\n", request_str); exit(EXIT_FAILURE); }

// Sanity check
      if ( Alice_Bob_chip_num < 0 )
         { 
         printf("ERROR: ExchangeIDsConfirmATExists(): Alice received Bob's ID but Bob does NOT have one assigned by Bank %d!\n", 
            Alice_Bob_chip_num); exit(EXIT_FAILURE); 
         }

// If Alice does NOT have an AT for Bob's Alice_Bob_chip_num, then this routine returns 0. Send 0 to Bob for 'NO'. Also, with parameters 
// 'get_only_customer_AT' set to 1 and 'return_customer_AT_info' to 0, this routine ONLY counts the number of ATs for Alice, i.e., it does 
// NOT fetch the AT and return it's fields. 
      if ( (*local_AT_status_ptr = ZeroTrustGetCustomerATs(max_string_len, SHP_ptr->DB_Trust_AT, NULL, NULL, 0, NULL, NULL,
         get_only_customer_AT, Alice_Bob_chip_num, return_customer_AT_info, report_tot_num_ATs_only, &num_ATs)) == 0 )
         sprintf(request_str, "0");
      else
         sprintf(request_str, "1");

printf("ExchangeIDsConfirmATExists(): Sending to Bob (Do you have an Alice (my) AT? 0(NO)/1(YES)) '%s'\n", request_str); fflush(stdout);
#ifdef DEBUG
#endif

      if ( SockSendB((unsigned char *)request_str, strlen(request_str) + 1, AliceBob_socket_desc) < 0 )
         { printf("ERROR: ExchangeIDsConfirmATExists(): Failed to send Alice's unique id (chip_num) and AT status to Bob!\n"); exit(EXIT_FAILURE); }

// DO NOT CLOSE THIS SOCKET. We need to interact with Bob further.
//      close(AliceBob_socket_desc);
      }

// ===================================================================================================================
// BOB: Note that OpenSocketServer in main() returned with a connection request from Alice. Wait for Alice to send her packet. 
   else
      {

printf("ExchangeIDsConfirmATExists(): Connected to Alice!\n"); fflush(stdout);
#ifdef DEBUG
#endif

// Receive Alice's unique chip_num (or Bob's unique chip_num if Alice passes a chip_num that is NOT her own) and then check to see if 
// at AT record exists in Bob's DB. 
      if ( SockGetB((unsigned char *)request_str, max_string_len, AliceBob_socket_desc) < 0 )
         { printf("ERROR: ExchangeIDsConfirmATExists(): Failed to get Alice's unique ID (chip_num) from Alice!\n"); exit(EXIT_FAILURE); }
      if ( sscanf(request_str, "%d", &Alice_Bob_chip_num) != 1 )
         { printf("ERROR: ExchangeIDsConfirmATExists(): Failed to extract Alice's unique ID from '%s'!\n", request_str); exit(EXIT_FAILURE); }

// Sanity check
      if ( Alice_Bob_chip_num < 0 )
         { printf("ERROR: ExchangeIDsConfirmATExists(): Bob received Alice's ID but is NOT assigned %d!\n", Alice_Bob_chip_num); exit(EXIT_FAILURE); }

// If Bob does NOT have an AT for Alice's Alice_Bob_chip_num, then this routine returns 0. Send 0 to Alice for 'NO'
      if ( (*local_AT_status_ptr = ZeroTrustGetCustomerATs(max_string_len, SHP_ptr->DB_Trust_AT, NULL, NULL, 0, NULL, NULL,
         get_only_customer_AT, Alice_Bob_chip_num, return_customer_AT_info, report_tot_num_ATs_only, &num_ATs)) == 0 )
         sprintf(request_str, "%d 0", SHP_ptr->chip_num);
      else
         sprintf(request_str, "%d 1", SHP_ptr->chip_num);

printf("ExchangeIDsConfirmATExists(): Sending to Alice (Bob's ID, Do I have an Alice AT? 0(NO)/1(YES)) '%s'\n", request_str); fflush(stdout);
#ifdef DEBUG
#endif

      if ( SockSendB((unsigned char *)request_str, strlen(request_str) + 1, AliceBob_socket_desc) < 0 )
         { printf("ERROR: ExchangeIDsConfirmATExists(): Failed to send Alice's unique id (chip_num) and AT status to Bob!\n"); exit(EXIT_FAILURE); }

// Get AT status from Alice on whether she has a 'NOT USED' AT for Bob in her database. 
      if ( SockGetB((unsigned char *)request_str, max_string_len, AliceBob_socket_desc) < 0 )
         { printf("ERROR: ExchangeIDsConfirmATExists(): Failed to get Bob's AT status (in Alice's DB) from Alice!\n"); exit(EXIT_FAILURE); }
      if ( sscanf(request_str, "%d", remote_AT_status_ptr) != 1 )
         { printf("ERROR: ExchangeIDsConfirmATExists(): Failed to extract Bob's AT status (in Alice's DB) from '%s'!\n", request_str); exit(EXIT_FAILURE); }

// DO NOT CLOSE THIS SOCKET. We need to interact with Alice further.
//      close(AliceBob_socket_desc);
      }


printf("ExchangeIDsConfirmATExists(): DONE!\n"); fflush(stdout);
#ifdef DEBUG
#endif

   return Alice_Bob_chip_num;
   }


// ========================================================================================================
// ========================================================================================================
// Generate a shared key between Alice and Bob, Alice and TTP using the ATs they have for each other.
// With chip_num's of the other party, fetch AT from ZeroTrust DB. We assume that the other_party_socket_desc
// is opened in the caller and that the other_party_chip_num has already been fetched from the other party.
// In fact, we've already checked that both parties have ATs on each other so the call below should never
// fail here.

int ZeroTrustGenSharedKey(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int other_party_chip_num, 
   int other_party_socket_desc, int I_am_Alice, int num_CIArr, ClientInfoStruct *Client_CIArr, 
   int My_index)
   {
   int *chip_num_arr = NULL;
   int *chlng_num_arr = NULL;
   unsigned char **ZHK_A_nonce_arr = NULL;
   unsigned char **nonce_arr = NULL;
   int num_ATs;

#ifdef DEBUG
printf("ZeroTrustGenSharedKey(): BEGIN!\n"); fflush(stdout);
#endif

// Sanity check
   if ( SHP_ptr->ZeroTrust_LLK == NULL )
      { printf("ERROR: ZeroTrustGenSharedKey(): ZeroTrust_LLK is NULL!\n"); exit(EXIT_FAILURE); }

// Sanity check
   if ( My_index < 0 || My_index >= num_CIArr )
      { 
      printf("ERROR: ZeroTrustGenSharedKey(): My_index %d in Client_CIArr out-or-range, MUST be < %d!\n",
         My_index, num_CIArr); exit(EXIT_FAILURE); 
      }

// =========================================
// Check the AT DB for a match to Alice or Bob's ID if set to 0, otherwise just get the total number of ATs in Alice's DB.
   int report_tot_num_ATs_only = 0;

// If set, we check if a specific customer AT is present (and is set as 'NOT USED') -- MUST always be true because
// we checked this in the caller). With return_customer_AT_info set to 1, we allocate storage for the AT information 
// and mark the AT as used.
   int get_only_customer_AT = 1;
   int return_customer_AT_info = 1;

// If Alice/Bob/TTP does NOT have an AT for other_party_chip_num, then this routine returns 0. Fetch the AT and mark
// it as used.
   if ( ZeroTrustGetCustomerATs(MAX_STRING_LEN, SHP_ptr->DB_Trust_AT, &chip_num_arr, &chlng_num_arr, SHP_ptr->ZHK_A_num_bytes, 
      &ZHK_A_nonce_arr, &nonce_arr, get_only_customer_AT, other_party_chip_num, return_customer_AT_info, 
      report_tot_num_ATs_only, &num_ATs) == 0 )
      return 0;

// Sanity check
   if ( num_ATs == 1 )
      { printf("ZeroTrustGenSharedKey(): ZeroTrustGetCustomerATs returned more than 1 AT!\n"); exit(EXIT_FAILURE); }

// Shared key generation involves sending the other party the nonce from the AT DB record, they use their ZeroTrust_LLK
// to hash it to produce ZHK_A_nonce_b (which should match the DB element that Alice stores). This is one of the two
// shared secrets that each have on the other.
   unsigned char *nonce_other_party = Allocate1DUnsignedChar(SHP_ptr->ZHK_A_num_bytes);

// =========================================
// EXCHANGE DB NONCES
// ALICE
   if ( I_am_Alice == 1 )
      {

#ifdef DEBUG
printf("ZeroTrustGenSharedKey(): Alice sending nonce to Bob/TTP !\n"); fflush(stdout);
#endif

// Send nonce to other party.
      if ( SockSendB(nonce_arr[0], SHP_ptr->ZHK_A_num_bytes, other_party_socket_desc) < 0 )
         { printf("ERROR: ZeroTrustGenSharedKey(): Failed to send Alice's nonce to other party!\n"); exit(EXIT_FAILURE); }
      if ( SockGetB(nonce_other_party, SHP_ptr->ZHK_A_num_bytes, other_party_socket_desc) != SHP_ptr->ZHK_A_num_bytes )
         { printf("ERROR: ZeroTrustGenSharedKey(): Failed to get other parties nonce!\n"); exit(EXIT_FAILURE); }
      }

// BOB or TTP
   else
      {

#ifdef DEBUG
printf("ZeroTrustGenSharedKey(): Bob/TTP sending nonce to Alice!\n"); fflush(stdout);
#endif

// Get nonce from other party.
      if ( SockGetB(nonce_other_party, SHP_ptr->ZHK_A_num_bytes, other_party_socket_desc) != SHP_ptr->ZHK_A_num_bytes )
         { printf("ERROR: ZeroTrustGenSharedKey(): Failed to get Alice's nonce!\n"); exit(EXIT_FAILURE); }
      if ( SockSendB(nonce_arr[0], SHP_ptr->ZHK_A_num_bytes, other_party_socket_desc) < 0 )
         { printf("ERROR: ZeroTrustGenSharedKey(): Failed to send other parties nonce to Alice!\n"); exit(EXIT_FAILURE); }
      }

// =========================================
// SHARED KEY GENERATION:
   unsigned char *key_shard = Allocate1DUnsignedChar(SHP_ptr->ZHK_A_num_bytes);
   unsigned char *key_shard_hash = Allocate1DUnsignedChar(SHP_ptr->ZHK_A_num_bytes);
   unsigned char *shared_key = Allocate1DUnsignedChar(SHP_ptr->ZHK_A_num_bytes);

// Create hash(ZeroTrust_LLK XOR nonce) to create first key_shard (the first shared secret between Alice and the other
// party). Hopefully ZeroTrust_LLK will not change!!!
   int byte_num;
   for ( byte_num = 0; byte_num < SHP_ptr->ZHK_A_num_bytes; byte_num++ )
      key_shard[byte_num] = SHP_ptr->ZeroTrust_LLK[byte_num] ^ nonce_other_party[byte_num];

   hash_256(max_string_len, SHP_ptr->ZHK_A_num_bytes, key_shard, SHP_ptr->ZHK_A_num_bytes, key_shard_hash);

// The second shared secret is the ZHK_A_nonce, which incorporates the ZeroTrust_LLK for the other party.
   for ( byte_num = 0; byte_num < SHP_ptr->ZHK_A_num_bytes; byte_num++ )
      shared_key[byte_num] = key_shard_hash[byte_num] ^ ZHK_A_nonce_arr[0][byte_num];

// Shared key should be NULL
   if ( Client_CIArr[My_index].AliceBob_shared_key != NULL )
      {
      printf("WARNING: ZeroTrustGenSharedKey(): shared key in Client_CIArr is NOT NULL -- freeing it!\n"); fflush(stdout);
      free(Client_CIArr[My_index].AliceBob_shared_key);
      }
   Client_CIArr[My_index].AliceBob_shared_key = shared_key;

#ifdef DEBUG
PrintHeaderAndHexVals("\n\tAlice/Bob ZeroTrust Shared Key:\n", SHP_ptr->ZHK_A_num_bytes, Client_CIArr[My_index].AliceBob_shared_key, 32);
#endif

// =====================================================
// AUTHENTICATION: Exchange encrypted versions of the nonces and confirm that each can decrypt it.
   int fail_or_pass;

// How does this work? 
//    If SHP_ptr->ZHK_A_num_bytes is 15 and AES_INPUT_NUM_BYTES is 16, then we get 15 + (16 - (15%16)) = 15 + (16 - 15) = 15 + 1 = 16 (round up 1 packet)
//    If SHP_ptr->ZHK_A_num_bytes is 16 and AES_INPUT_NUM_BYTES is 16, then we get 16 + (16 - (16%16)) = 16 + (16 - 0) = 16 + 16 = 32 (round up 2 packets)
//    If SHP_ptr->ZHK_A_num_bytes is 17 and AES_INPUT_NUM_BYTES is 16, then we get 17 + (16 - (17%16)) = 17 + (16 - 1) = 32 (round up 2 packets)
   int nonce_num_bytes_adj = SHP_ptr->ZHK_A_num_bytes + (AES_INPUT_NUM_BYTES - (SHP_ptr->ZHK_A_num_bytes % AES_INPUT_NUM_BYTES));
   unsigned char *nonce_enc = Allocate1DUnsignedChar(nonce_num_bytes_adj);
   unsigned char *nonce_enc_op = Allocate1DUnsignedChar(nonce_num_bytes_adj);
   unsigned char *nonce_dec = Allocate1DUnsignedChar(nonce_num_bytes_adj);

   encrypt_256(Client_CIArr[My_index].AliceBob_shared_key, SHP_ptr->AES_IV, nonce_other_party, nonce_num_bytes_adj, nonce_enc);

   if ( I_am_Alice == 1 )
      {

#ifdef DEBUG
printf("ZeroTrustGenSharedKey(): Alice sending AUTHENTICATION nonce to Bob/TTP!\n"); fflush(stdout);
#endif

// Send encrypted nonce to other party.
      if ( SockSendB(nonce_enc, nonce_num_bytes_adj, other_party_socket_desc) < 0 )
         { printf("ERROR: ZeroTrustGenSharedKey(): Failed to send Alice's ENCRYPTED nonce to other party!\n"); exit(EXIT_FAILURE); }
      if ( SockGetB(nonce_enc_op, nonce_num_bytes_adj, other_party_socket_desc) != nonce_num_bytes_adj )
         { printf("ERROR: ZeroTrustGenSharedKey(): Failed to get other parties nonce!\n"); exit(EXIT_FAILURE); }
      }

// BOB or TTP
   else
      {

#ifdef DEBUG
printf("ZeroTrustGenSharedKey(): Bob/TTP sending AUTHENTICATION nonce to Alice!\n"); fflush(stdout);
#endif

// Get nonce from other party.
      if ( SockGetB(nonce_enc_op, nonce_num_bytes_adj, other_party_socket_desc) != nonce_num_bytes_adj )
         { printf("ERROR: ZeroTrustGenSharedKey(): Failed to get Alice's nonce!\n"); exit(EXIT_FAILURE); }
      if ( SockSendB(nonce_enc, nonce_num_bytes_adj, other_party_socket_desc) < 0 )
         { printf("ERROR: ZeroTrustGenSharedKey(): Failed to send other parties nonce to Alice!\n"); exit(EXIT_FAILURE); }
      }

// Decrypt the nonce_enc_op, which must match the nonce[0] that Alice stores in her DB. Alice sent to the other party
// to encrypt.
   decrypt_256(Client_CIArr[My_index].AliceBob_shared_key, SHP_ptr->AES_IV, nonce_enc_op, nonce_num_bytes_adj, nonce_dec);

#ifdef DEBUG
PrintHeaderAndHexVals("\n\tAlice/Bob DB nonce[0]:\n", SHP_ptr->ZHK_A_num_bytes, nonce_arr[0], 32);
PrintHeaderAndHexVals("\tAlice/Bob matching decrypted nonce:\n", SHP_ptr->ZHK_A_num_bytes, nonce_dec, 32);
#endif

// If Alice and other party have the same shared secret, than these should match. 
   for ( byte_num = 0; byte_num < SHP_ptr->ZHK_A_num_bytes; byte_num++ )
      if ( nonce_dec[byte_num] != nonce_arr[0][byte_num] )
         break;
   if ( byte_num != SHP_ptr->ZHK_A_num_bytes )
      {
      fail_or_pass = 0;

#ifdef DEBUG
printf("ERROR: ZeroTrustGenSharedKey(): Alice/Bob or Alice/TTP key validation FAILED at byte %d", byte_num); fflush(stdout);
#endif
      }
   else
      fail_or_pass = 1;

// ================================
// REFRESH AT DB
   if ( fail_or_pass == 1 )
      {
      unsigned char *AT_nonce_new = Allocate1DUnsignedChar(nonce_num_bytes_adj);
      unsigned char *ZHK_A_nonce_new = Allocate1DUnsignedChar(nonce_num_bytes_adj);
      unsigned char *ZHK_A_nonce_new_hash = Allocate1DUnsignedChar(nonce_num_bytes_adj);

#ifdef DEBUG
printf("ZeroTrustGenSharedKey(): REFRESHING AT DB!\n"); fflush(stdout);
#endif

      int load_seed = 0;
      TRNG(max_string_len, SHP_ptr, FUNC_EXT_TRNG, load_seed, SHP_ptr->ZHK_A_num_bytes, AT_nonce_new);

// Compute n_r XOR ZeroTrust_LLK and hash it. 
// TO_DO: we use the same ZeroTrust_LLK here, which implies the same chlng_num element.
      for ( byte_num = 0; byte_num < SHP_ptr->ZHK_A_num_bytes; byte_num++ )
         ZHK_A_nonce_new[byte_num] = AT_nonce_new[byte_num] ^ SHP_ptr->ZeroTrust_LLK[byte_num];

      hash_256(max_string_len, SHP_ptr->ZHK_A_num_bytes, ZHK_A_nonce_new, SHP_ptr->ZHK_A_num_bytes, ZHK_A_nonce_new_hash);


#ifdef DEBUG
printf("ZeroTrustGenSharedKey(): Created new ZHK_A -- Exchanging new ZHK_As with other party!\n"); fflush(stdout);
#endif

// Encrypt and exchange the encrypted nonces first
      encrypt_256(Client_CIArr[My_index].AliceBob_shared_key, SHP_ptr->AES_IV, AT_nonce_new, nonce_num_bytes_adj, nonce_enc);

      if ( I_am_Alice == 1 )
         {
         if ( SockSendB(nonce_enc, nonce_num_bytes_adj, other_party_socket_desc) < 0 )
            { printf("ERROR: ZeroTrustGenSharedKey(): Failed to send Alice's ENCRYPTED nonce to other party!\n"); exit(EXIT_FAILURE); }
         if ( SockGetB(nonce_enc_op, nonce_num_bytes_adj, other_party_socket_desc) != nonce_num_bytes_adj )
            { printf("ERROR: ZeroTrustGenSharedKey(): Failed to get other parties nonce!\n"); exit(EXIT_FAILURE); }
         }
      else
         {
         if ( SockGetB(nonce_enc_op, nonce_num_bytes_adj, other_party_socket_desc) != nonce_num_bytes_adj )
            { printf("ERROR: ZeroTrustGenSharedKey(): Failed to get Alice's nonce!\n"); exit(EXIT_FAILURE); }
         if ( SockSendB(nonce_enc, nonce_num_bytes_adj, other_party_socket_desc) < 0 )
            { printf("ERROR: ZeroTrustGenSharedKey(): Failed to send other parties nonce to Alice!\n"); exit(EXIT_FAILURE); }
         }

// Decrypt the AT_nonce_new
      decrypt_256(Client_CIArr[My_index].AliceBob_shared_key, SHP_ptr->AES_IV, nonce_enc_op, nonce_num_bytes_adj, AT_nonce_new);


// Do the same for the ZHK_A_nonce_new
      encrypt_256(Client_CIArr[My_index].AliceBob_shared_key, SHP_ptr->AES_IV, ZHK_A_nonce_new_hash, nonce_num_bytes_adj, nonce_enc);

      if ( I_am_Alice == 1 )
         {
         if ( SockSendB(nonce_enc, nonce_num_bytes_adj, other_party_socket_desc) < 0 )
            { printf("ERROR: ZeroTrustGenSharedKey(): Failed to send Alice's ENCRYPTED nonce to other party!\n"); exit(EXIT_FAILURE); }
         if ( SockGetB(nonce_enc_op, nonce_num_bytes_adj, other_party_socket_desc) != nonce_num_bytes_adj )
            { printf("ERROR: ZeroTrustGenSharedKey(): Failed to get other parties nonce!\n"); exit(EXIT_FAILURE); }
         }
      else
         {
         if ( SockGetB(nonce_enc_op, nonce_num_bytes_adj, other_party_socket_desc) != nonce_num_bytes_adj )
            { printf("ERROR: ZeroTrustGenSharedKey(): Failed to get Alice's nonce!\n"); exit(EXIT_FAILURE); }
         if ( SockSendB(nonce_enc, nonce_num_bytes_adj, other_party_socket_desc) < 0 )
            { printf("ERROR: ZeroTrustGenSharedKey(): Failed to send other parties nonce to Alice!\n"); exit(EXIT_FAILURE); }
         }

// Decrypt the ZHK_A_nonce_new_hash
      decrypt_256(Client_CIArr[My_index].AliceBob_shared_key, SHP_ptr->AES_IV, nonce_enc_op, nonce_num_bytes_adj, ZHK_A_nonce_new_hash);

#ifdef DEBUG
printf("ZeroTrustGenSharedKey(): Adding refreshed ZHK_A to ZeroTrust DB!\n"); fflush(stdout);
#endif

// Finally, add the new AT to the DB and mark its status as 0 ('NOT USED'). 
// TO_DO: Using chlng_num read above for the AT just used for authentication.
      int status = 0;
      ZeroTrustAddCustomerATs(max_string_len, SHP_ptr->DB_Trust_AT, other_party_chip_num, chlng_num_arr[0], SHP_ptr->ZHK_A_num_bytes, 
         ZHK_A_nonce_new_hash, AT_nonce_new, status);

      if ( AT_nonce_new != NULL )
         free(AT_nonce_new); 
      if ( ZHK_A_nonce_new != NULL )
         free(ZHK_A_nonce_new); 
      if ( ZHK_A_nonce_new_hash != NULL )
         free(ZHK_A_nonce_new_hash); 
      }

// Free up the resources.
   if ( chip_num_arr != NULL )
      free(chip_num_arr); 
   if ( chlng_num_arr != NULL )
      free(chlng_num_arr);
   if ( ZHK_A_nonce_arr != NULL )
      {
      if ( ZHK_A_nonce_arr[0] != NULL )
         free(ZHK_A_nonce_arr[0]);
      free(ZHK_A_nonce_arr);
      }
   if ( nonce_arr != NULL )
      {
      if ( nonce_arr[0] != NULL )
         free(nonce_arr[0]);
      free(nonce_arr);
      }

   if ( nonce_other_party != NULL )
      free(nonce_other_party); 

   if ( nonce_enc != NULL )
      free(nonce_enc); 
   if ( nonce_enc_op != NULL )
      free(nonce_enc_op); 
   if ( nonce_dec != NULL )
      free(nonce_dec); 

// Do NOT free shared_key!!
   if ( key_shard != NULL )
      free(key_shard); 
   if ( key_shard_hash != NULL )
      free(key_shard_hash); 

#ifdef DEBUG
printf("ZeroTrustGenSharedKey(): DONE!\n"); fflush(stdout);
#endif

   return fail_or_pass;
   }


// ========================================================================================================
// ========================================================================================================
// Called from GoGetVectors below (from CommonCore). Get the vectors and masks to be applied to the functional 
// unit. Verifier will send number of rising vectors (inspects vectors as it reads them) and indicate whether 
// masks will also be sent.

int ReceiveVectors(int max_string_len, int verifier_socket_desc, unsigned char ***first_vecs_b_ptr, 
   unsigned char ***second_vecs_b_ptr, int num_PIs, int *num_rise_vecs_ptr, int *has_masks_ptr, int num_POs, 
   unsigned char ***masks_b_ptr)
   {
   int num_vecs, vec_pair_num, vec_num;
   char num_vecs_str[max_string_len];
   unsigned char *vec_ptr;

// Get the number of vectors that verifier intends to send.
   if ( SockGetB((unsigned char *)num_vecs_str, max_string_len, verifier_socket_desc) < 0 )
      { printf("ERROR: ReceiveVectors(): Failed to receive 'num_vecs_str'!\n"); exit(EXIT_FAILURE); }

   if ( sscanf(num_vecs_str, "%d %d %d", &num_vecs, num_rise_vecs_ptr, has_masks_ptr) != 3 )
      { printf("ERROR: ReceiveVectors(): Expected 'num_vecs', 'num_rise_vecs' and 'has_masks' in '%s'\n", num_vecs_str); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("ReceiveVectors(): 'num_vecs_str' received from verifier '%s'\tNum vecs %d\tNum rise vectors %d\tHas masks %d\n", 
   num_vecs_str, num_vecs, *num_rise_vecs_ptr, *has_masks_ptr); fflush(stdout);
#endif

// Allocate the base arrays based on the number of vectors we will receive.
   if ( (*first_vecs_b_ptr = (unsigned char **)malloc(sizeof(unsigned char *) * num_vecs)) == NULL )
      { printf("ERROR: ReceiveVectors(): Failed to allocate storage for first_vecs_b array!\n"); exit(EXIT_FAILURE); }
   if ( (*second_vecs_b_ptr = (unsigned char **)malloc(sizeof(unsigned char *) * num_vecs)) == NULL )
      { printf("ERROR: ReceiveVectors(): Failed to allocate storage for second_vecs_b array!\n"); exit(EXIT_FAILURE); }
   if ( *has_masks_ptr == 1 )
      if ( (*masks_b_ptr = (unsigned char **)malloc(sizeof(unsigned char *) * num_vecs)) == NULL )
         { printf("ERROR: ReceiveVectors(): Failed to allocate storage for masks_b array!\n"); exit(EXIT_FAILURE); }

// Receive the first_vecs and second_vecs sent by the verifier. 
   vec_num = 0;
   vec_pair_num = 0;
   while ( vec_num != num_vecs )
      {

// Allocate space to store the binary vectors
      if ( vec_pair_num == 0 )
         {
         if ( ((*first_vecs_b_ptr)[vec_num] = (unsigned char *)malloc(sizeof(char)*num_PIs/8)) == NULL )
            { printf("ERROR: ReceiveVectors(): Failed to allocate storage for first_vecs_b element!\n"); exit(EXIT_FAILURE); }
         vec_ptr = (*first_vecs_b_ptr)[vec_num];
         }
      else if ( vec_pair_num == 1 )
         {
         if ( ((*second_vecs_b_ptr)[vec_num] = (unsigned char *)malloc(sizeof(char)*num_PIs/8)) == NULL )
            { printf("ERROR: ReceiveVectors(): Failed to allocate storage for second_vecs_b element!\n"); exit(EXIT_FAILURE); }
         vec_ptr = (*second_vecs_b_ptr)[vec_num];
         }
      else 
         if ( ((*masks_b_ptr)[vec_num] = (unsigned char *)malloc(sizeof(char)*num_POs/8)) == NULL )
            { printf("ERROR: ReceiveVectors(): Failed to allocate storage for masks_b element!\n"); exit(EXIT_FAILURE); }

// Get the binary vector data
      if ( vec_pair_num <= 1 )
         {
         if ( SockGetB(vec_ptr, num_PIs/8, verifier_socket_desc) != num_PIs/8 )
            { printf("ERROR: ReceiveVectors(): number of vector bytes received is not equal to %d\n", num_PIs/8); exit(EXIT_FAILURE); }
         }
      else if ( SockGetB((*masks_b_ptr)[vec_num], num_POs/8, verifier_socket_desc) != num_POs/8 )
         { printf("ERROR: ReceiveVectors(): number of mask bytes received is not equal to %d\n", num_POs/8); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("Vector %d\n\t", vec_num);
int i;
for ( i = 0; i < num_PIs/8; i++ )
   printf("%02X ", vec_ptr[i]);
printf("\n");
#endif

// Increment to next vector after both vectors (first and second), and potentially the mask, have been received.
      if ( (*has_masks_ptr == 0 && vec_pair_num == 1) || (*has_masks_ptr == 1 && vec_pair_num == 2) )
         {
         vec_num++;
         vec_pair_num = 0;
         }
      else
         vec_pair_num++; 
      }

#ifdef DEBUG
printf("ReceiveVectors(): %d vector pairs received from verifier!\n", vec_num); fflush(stdout);
#endif

   return num_vecs;
   }


// ========================================================================================================
// ========================================================================================================
// Called from device_provision.c. Get the CHALLENGES and masks to be applied to the functional unit (NOT the
// VECTORS as above, which are the challenges split into two equal-sized pieces). Verifier will send number 
// of rising challenges (inspects challenges as it reads them) and indicate whether masks will also be sent.

int ReceiveChlngsAndMasks(int max_string_len, int verifier_socket_desc, unsigned char ***challenges_b_ptr, 
   int num_chlng_bits, int *num_rise_chlngs_ptr, int *has_masks_ptr, int num_POs, unsigned char ***masks_b_ptr)
   {
   int num_chlngs, chlng_mask_num, chlng_num;
   char num_chlngs_str[max_string_len];
   unsigned char *chlng_ptr;

// Get the number of challenges that verifier intends to send.
   if ( SockGetB((unsigned char *)num_chlngs_str, max_string_len, verifier_socket_desc) < 0 )
      { printf("ERROR: ReceiveChlngsAndMasks(): Failed to receive 'num_chlngs_str'!\n"); fflush(stdout); exit(EXIT_FAILURE); }

// DEBUG
#ifdef DEBUG
printf("ReceiveChlngsAndMasks(): 'num_chlngs_str' received from verifier '%s'\n", num_chlngs_str); fflush(stdout);
#endif

   if ( sscanf(num_chlngs_str, "%d %d %d", &num_chlngs, num_rise_chlngs_ptr, has_masks_ptr) != 3 )
      { printf("ERROR: ReceiveChlngsAndMasks(): Expected 'num_chlngs', 'num_rise_chlngs' and 'has_masks' in '%s'\n", num_chlngs_str); fflush(stdout); exit(EXIT_FAILURE); }

// Allocate the base arrays based on the number of challenges we will receive.
   if ( (*challenges_b_ptr = (unsigned char **)malloc(sizeof(unsigned char *) * num_chlngs)) == NULL )
      { printf("ERROR: ReceiveChlngsAndMasks(): Failed to allocate storage for challenges_b array!\n"); fflush(stdout); exit(EXIT_FAILURE); }
   if ( *has_masks_ptr == 1 )
      if ( (*masks_b_ptr = (unsigned char **)malloc(sizeof(unsigned char *) * num_chlngs)) == NULL )
         { printf("ERROR: ReceiveChlngsAndMasks(): Failed to allocate storage for masks_b array!\n"); fflush(stdout); exit(EXIT_FAILURE); }

// Receive the challenges and masks sent by the verifier. 
   chlng_num = 0;
   chlng_mask_num = 0;
   while ( chlng_num != num_chlngs )
      {

// Allocate space to store the binary challenges
      if ( chlng_mask_num == 0 )
         {
         if ( ((*challenges_b_ptr)[chlng_num] = (unsigned char *)malloc(sizeof(char)*num_chlng_bits/8)) == NULL )
            { printf("ERROR: ReceiveChlngsAndMasks(): Failed to allocate storage for challenges_b element!\n"); fflush(stdout); exit(EXIT_FAILURE); }
         chlng_ptr = (*challenges_b_ptr)[chlng_num];
         }
      else 
         if ( ((*masks_b_ptr)[chlng_num] = (unsigned char *)malloc(sizeof(char)*num_POs/8)) == NULL )
            { printf("ERROR: ReceiveChlngsAndMasks(): Failed to allocate storage for masks_b element!\n"); fflush(stdout); exit(EXIT_FAILURE); }

// Get the binary challenge data
      if ( chlng_mask_num == 0 )
         {
         if ( SockGetB(chlng_ptr, num_chlng_bits/8, verifier_socket_desc) != num_chlng_bits/8 )
            { printf("ERROR: ReceiveChlngsAndMasks(): number of challenge bytes received is not equal to %d\n", num_chlng_bits/8); fflush(stdout); exit(EXIT_FAILURE); }
         }
      else if ( SockGetB((*masks_b_ptr)[chlng_num], num_POs/8, verifier_socket_desc) != num_POs/8 )
         { printf("ERROR: ReceiveChlngsAndMasks(): number of mask bytes received is not equal to %d\n", num_POs/8); fflush(stdout); exit(EXIT_FAILURE); }

// DEBUG
// printf("Vector %d\n\t", chlng_num);
// int i;
// for ( i = 0; i < num_chlng_bits/8; i++ )
//    printf("%02X ", chlng_ptr[i]);
// printf("\n");

// Increment to next challenge, and potentially the mask, have been received.
      if ( (*has_masks_ptr == 0 && chlng_mask_num == 0) || (*has_masks_ptr == 1 && chlng_mask_num == 1) )
         {
         chlng_num++;
         chlng_mask_num = 0;
         }
      else
         chlng_mask_num++; 
      }

// DEBUG
// printf("ReceiveChlngsAndMasks(): %d challenges received from verifier!\n", chlng_num); fflush(stdout);

   return num_chlngs;
   }


// ========================================================================================================
// ========================================================================================================
// Transfer a challenge plus optionally a mask through the GPIO to the VHDL side.

void LoadChlngAndMask(int max_string_len, volatile unsigned int *CtrlRegA, volatile unsigned int *DataRegA, int chlng_num, 
   unsigned char **challenges_b, int ctrl_mask, int num_chlng_bits, int chlng_chunk_size, int has_masks, int num_POs, 
   unsigned char **masks_b)
   {
   int word_num, iter_num, load_iterations, bit_len;
   unsigned char *chlng_ptr;
   int chlng_val_chunk;

// Sanity check
   if ( (num_chlng_bits % chlng_chunk_size) != 0 )
      { printf("ERROR: LoadChlngAndMask(): Challenge size %d must be evenly divisible by %d!\n", num_chlng_bits, chlng_chunk_size); exit(EXIT_FAILURE); }

// Reset the VHDL pointers to the challenge buffers. 
   *CtrlRegA = ctrl_mask | (1 << OUT_CP_DTO_RESTART);
   usleep(1000);
   *CtrlRegA = ctrl_mask;

#ifdef DEBUG
printf("LoadChlngAndMask(): Reset VHDL challenge pointers!\n"); fflush(stdout);
#endif

   if ( has_masks == 0 )
      load_iterations = 1;
   else
      load_iterations = 2;

// Send a binary challenge, 16-bits at a time, starting with the low order to high order bits. 
   for ( iter_num = 0; iter_num < load_iterations; iter_num++ )
      {
  
// Set size of data transfer.
      if ( iter_num == 0 )
         bit_len = num_chlng_bits;
      else
         bit_len = num_POs;

#ifdef DEBUG
printf("LoadChlngAndMask(): Current control mask '%08X'\n", ctrl_mask); fflush(stdout);
#endif

// Iterate over each of the 16-bit chunks. Verifier or data orders the data from low order to high order, i.e., the exact format that we need to load it up by 
// in the VHDL. This is done in ConvertASCIIVecMaskToBinary called by enrollDB.c in DATABASE directory.
      for ( word_num = 0; word_num < bit_len/chlng_chunk_size; word_num++ )
         {

// Add 2 bytes at a time to the pointer. 
         if ( iter_num == 0 )
            chlng_ptr = challenges_b[chlng_num] + word_num*2;
         else 
            chlng_ptr = masks_b[chlng_num] + word_num*2;

         chlng_val_chunk = (chlng_ptr[1] << 8) + chlng_ptr[0]; 

#ifdef DEBUG
printf("LoadChlngAndMask(): 16-bit chunk %d in hex '%04X'\n", word_num, chlng_val_chunk); fflush(stdout);
#endif

// Four step protocol
// 1) Assert 'data_ready' while putting the 16-bit binary value on the low order bits of CtrlReg
//printf("LoadChlngAndMask(): Writing 'data_ready' with 16-bit binary value in hex '%04X'\n", chlng_val_chunk); fflush(stdout);
         *CtrlRegA = ctrl_mask | (1 << OUT_CP_DTO_DATA_READY) | chlng_val_chunk;

// 2) Wait for 'done_reading to go to 1 (it is low by default). State machine latches data in 2 clk cycles. 
//    Maintain 1 on 'data_ready' and continue to hold 16-bit binary chunk.
// printf("LoadChlngAndMask(): Waiting state machine 'done_reading' to be set to '1'\n"); fflush(stdout);
         while ( (*DataRegA & (1 << IN_SM_DTO_DONE_READING)) == 0 );

// 3) Once 'done_reading' goes to 1, set 'data_ready' to 0 and remove chunk;
// printf("LoadChlngAndMask(): De-asserting 'data_ready'\n"); fflush(stdout);
         *CtrlRegA = ctrl_mask;

// 4) Wait for 'done_reading to go to 0.
// printf("LoadChlngAndMask(): Waiting state machine 'done_reading' to be set to '0'\n"); fflush(stdout);
         while ( (*DataRegA & (1 << IN_SM_DTO_DONE_READING)) != 0 );

// printf("LoadChlngAndMask(): Done handshake associated with challenge chunk transfer\n"); fflush(stdout);
         }
      }

// 6/1/2016: Tell CollectPNs (if it is waiting) that challenge and possibly a mask have been loaded.
   *CtrlRegA = ctrl_mask | (1 << OUT_CP_DTO_VEC_LOADED);
   *CtrlRegA = ctrl_mask;

   return;
   }


// ========================================================================================================
// ========================================================================================================
// DEBUG ROUTINE. Check that the vectors received are precisely the same as the ones stored in the file on 
// the server. Write an ASCII file. 

void SaveASCIIVectors(int max_string_len, int num_vecs, unsigned char **first_vecs_b, unsigned char **second_vecs_b, 
   int num_PIs, int has_masks, int num_POs, unsigned char **masks_b)
   {
   int byte_cnter, bit_cnter;
   unsigned char *vec_ptr;
   int vec_num, vec_pair;
   FILE *OUTFILE;

   if ( (OUTFILE = fopen("ReceivedVectors.txt", "w")) == NULL )
      { printf("ERROR: SaveASCIIVectors(): Could not open ReceivedVectors.txt for writing!\n"); exit(EXIT_FAILURE); }

   for ( vec_num = 0; vec_num < num_vecs; vec_num++ )
      {
      for ( vec_pair = 0; vec_pair < 2; vec_pair++ )
         {

         if ( vec_pair == 0 )
            vec_ptr = first_vecs_b[vec_num];
         else
            vec_ptr = second_vecs_b[vec_num];

// Print ASCII version of bitstring in high order to low order. 
         for ( byte_cnter = num_PIs/8 - 1; byte_cnter >= 0; byte_cnter-- )
            {
            for ( bit_cnter = 7; bit_cnter >= 0; bit_cnter-- )
               {

// Check binary bit for 0 or 1
               if ( (vec_ptr[byte_cnter] & (unsigned char)(1 << bit_cnter)) == 0 )
                  fprintf(OUTFILE, "0");
               else
                  fprintf(OUTFILE, "1");
               }
            }
         fprintf(OUTFILE, "\n");
         }

// Extra <cr> between vector pairs.
      fprintf(OUTFILE, "\n");
      }
   fclose(OUTFILE);


// Do the same for the received masks.
   if ( has_masks == 1 )
      {
      if ( (OUTFILE = fopen("ReceivedMasks.txt", "w")) == NULL )
         { printf("ERROR: SaveASCIIVectors(): Could not open ReceivedMasks.txt for writing!\n"); exit(EXIT_FAILURE); }

      for ( vec_num = 0; vec_num < num_vecs; vec_num++ )
         {

// Print ASCII version of bitstring in high order to low order. 
         for ( byte_cnter = num_POs/8 - 1; byte_cnter >= 0; byte_cnter-- )
            {
            for ( bit_cnter = 7; bit_cnter >= 0; bit_cnter-- )
               {

// Check binary bit for 0 or 1
               if ( (masks_b[vec_num][byte_cnter] & (unsigned char)(1 << bit_cnter)) == 0 )
                  fprintf(OUTFILE, "0");
               else
                  fprintf(OUTFILE, "1");
               }
            }
         fprintf(OUTFILE, "\n");
         }
      fclose(OUTFILE);
      }

   return;
   }


// ========================================================================================================
// ========================================================================================================
// Fetch the seed that will be used to extract the set of vectors and path select masks from the database.

unsigned int GetChallengeGenSeed(int max_string_len, int verifier_socket_desc)
   {
   char DB_ChallengeGen_seed_str[max_string_len];
   unsigned int DB_ChallengeGen_seed;

   if ( SockGetB((unsigned char *)DB_ChallengeGen_seed_str, max_string_len, verifier_socket_desc) < 0 )
      { printf("ERROR: GetChallengeGenSeed(): Error receiving 'DB_ChallengeGen_seed_str' from verifier!\n"); exit(EXIT_FAILURE); }
   sscanf(DB_ChallengeGen_seed_str, "%u", &DB_ChallengeGen_seed);

#ifdef DEBUG
printf("GetChallengeGenSeed(): Got %u as ChallengeGen_seed from server!\n", DB_ChallengeGen_seed); fflush(stdout);
#endif

   return DB_ChallengeGen_seed;
   }


// ========================================================================================================
// ========================================================================================================
// Send 'GO' and get vectors and masks. NOTE: For SiRF, there is ONLY one vector, a configuration challenge.
// But I am storing two vectors in the database on the verifier side to make it compatible with the previous
// database structure.
// 11_1_2021: Added a Challenge.db to the device and TTP now so we can generate vectors locally.

int GoGetVectors(int max_string_len, int num_POs, int num_PIs, int verifier_socket_desc, int *num_rise_vecs_ptr, 
   int *has_masks_ptr, unsigned char ***first_vecs_b_ptr, unsigned char ***second_vecs_b_ptr, 
   unsigned char ***masks_b_ptr, int send_GO, int use_database_chlngs, sqlite3 *DB, int DB_design_index,
   char *DB_ChallengeSetName, int gen_or_use_challenge_seed, unsigned int *DB_ChallengeGen_seed_ptr, 
   pthread_mutex_t *GenChallenge_mutex_ptr, int debug_flag)
   {
   int num_vecs;

   struct timeval t0, t1;
   long elapsed; 

// ****************************************
// ***** Send "GO" to the verifier 
   if ( send_GO == 1 )
      {
      if ( debug_flag == 1 )
         {
         printf("GGV.1) Sending 'GO' to verifier\n");
         gettimeofday(&t0, 0);
         }
      if ( SockSendB((unsigned char *)"GO", strlen("GO")+1, verifier_socket_desc) < 0 )
         { printf("ERROR: GoGetVectors(): Send 'GO' request failed\n"); exit(EXIT_FAILURE); }
      if ( debug_flag == 1 )
         { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tElapsed %ld us\n\n", (long)elapsed); }
      }

// ****************************************
// ***** Get the vectors and select masks from verifier. 
   if ( debug_flag == 1 )
      {
      printf("GGV.2) Receiving vectors and masks from verifier\n");
      gettimeofday(&t0, 0);
      }

// Read all the vectors from the verifier into a set of string arrays. Verifier will send number of rising vectors (inspects vectors 
// as it reads them) and indicate whether masks will also be sent.
   if ( use_database_chlngs == 0 )
      {

// When the device/TTP requests actual vectors from the server, also get and store the DB_ChallengeGen_seed so we can use it locally
// to reproduce the vectors in the future if needed.
      *DB_ChallengeGen_seed_ptr = GetChallengeGenSeed(max_string_len, verifier_socket_desc);

// Get the actual vectors from the server.
      num_vecs = ReceiveVectors(max_string_len, verifier_socket_desc, first_vecs_b_ptr, second_vecs_b_ptr, num_PIs, num_rise_vecs_ptr,
         has_masks_ptr, num_POs, masks_b_ptr);
      }
   else
      {
      VecPairPOStruct *challenge_vecpair_id_PO_arr = NULL;
      int num_challenge_vecpair_id_PO = 0;

// Optionally get the challenge seed from the server. Usually (maybe always) when 'send_GO' is 0, we want to use the existing challenge
// seed, but these two flags mean something different so keeping them both (for now).
      if ( gen_or_use_challenge_seed == 0 )
         *DB_ChallengeGen_seed_ptr = GetChallengeGenSeed(max_string_len, verifier_socket_desc);

#ifdef DEBUG
printf("GoGetVectors(): use_database_chlngs is 1! Calling GenChallengeDB with Seed %u\n", *DB_ChallengeGen_seed_ptr);
fflush(stdout);
#endif

// This routine generates additional, pseudo-randomly selected challenge sets from special challenges added by add_challengeDB that use '0', 
// '1', 'u' and 'q' designators. '0' means output has no transition, '1' means we MUST use that path, 'u' (unqualifying) means the path 
// has a transition but is not 'compatible' with the elements that are marked 'q' (for qualifying). We assume the challenge set specified 
// on the command line exists already in the database (added by add_challengeDB.c). It MUST be a challenge set that has 'u' and 'q' 
// designators otherwise it is fully specified by add_challengeDB.c and there is nothing this routine can do to pseudo-randomly select
// challenges. It returns a set of binary vectors and masks as well as a data structure that allows the enrollment timing values 
// that are tested by these vectors to be looked up by the caller.
      GenChallengeDB(max_string_len, DB, DB_design_index, DB_ChallengeSetName, *DB_ChallengeGen_seed_ptr, 0, NULL, NULL, 
         first_vecs_b_ptr, second_vecs_b_ptr, masks_b_ptr, &num_vecs, num_rise_vecs_ptr, GenChallenge_mutex_ptr,
         &num_challenge_vecpair_id_PO, &challenge_vecpair_id_PO_arr);

// We always generate masks during the database vector selection process.
      *has_masks_ptr = 1;

#ifdef DEBUG
printf("GoGetVectors(): DATABASE selected vecs/masks with Seed %d\n", *DB_ChallengeGen_seed_ptr);
PrintHeaderAndHexVals("\t\n", 49, (*first_vecs_b_ptr)[0], 49);
fflush(stdout);
#endif

// Free up the challenge_vecpair_id_PO_arr. We'll free the vectors and timing data in the caller if it isn't needed again for something else.
      if ( challenge_vecpair_id_PO_arr != NULL )
         free(challenge_vecpair_id_PO_arr);
#ifdef INCLUDE_DATABASE
#endif
      }

   if ( debug_flag == 1 )
      { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tElapsed %ld us\n\n", (long)elapsed); }

// 9_18_2022: Timing tests for FSB KEK for SiRF paper. GenLLK from device_regeneration is called and then this routine.
// 9_18_2022: Taking this out temporarily for SiRF paper timing operation.
printf("\tNumber of vectors received %d\tNumber of rising vectors %d\tHas masks ? %d\n\n", num_vecs, *num_rise_vecs_ptr, *has_masks_ptr); 
fflush(stdout);
#ifdef DEBUG
#endif

#ifdef DEBUG
SaveASCIIVectors(max_string_len, num_vecs, *first_vecs_b_ptr, *second_vecs_b_ptr, num_PIs, *has_masks_ptr, num_POs, *masks_b_ptr);
#endif

   return num_vecs;
   }


// ========================================================================================================
// ========================================================================================================
// Read unsigned char data (helper data/SpreadFactors/nonces) from file. Data is expected to be in packed ASCII 
// hex format (NO spaces between pairs of consecutive hex digits) but can be on multiple lines. Allocates 
// space as needed.

int ReadFileHexASCIIToUnsignedChar(int max_string_len, char *file_name, unsigned char **bin_arr_ptr)
   {
   unsigned int tot_usc_bytes, read_num_bytes;
   char line[max_string_len+1], *char_ptr;
   int temp, HEX_TO_BYTE = 2;
   unsigned int i, j;
   FILE *INFILE;

printf("ReadFileHexASCIIToUnsignedChar(): Filename '%s'\n", file_name); fflush(stdout);
#ifdef DEBUG
#endif

   if ( (INFILE = fopen(file_name, "r")) == NULL )
      { printf("ERROR: ReadFileHexASCIIToUnsignedChar(): Failed to open file '%s'\n", file_name); exit(EXIT_FAILURE); }

// If bin_arr_ptr is NOT NULL, free up the data
   if ( *bin_arr_ptr != NULL )
      free(*bin_arr_ptr); 
   *bin_arr_ptr = NULL;

// Keep reading data a line at a time.
   tot_usc_bytes = 0;
   while ( fgets(line, max_string_len - 1, INFILE) != NULL )
      {

// Find the newline and eliminate it.
      if ((char_ptr = strrchr(line, '\n')) != NULL)
         *char_ptr = '\0';

// Skip blank lines.
      if ( strlen(line) == 0 )
         continue;

// Sanity check -- number of hex digits needs to be even.
      if ( (strlen(line) % 2) != 0 )
         { printf("ERROR: ReadFileHexASCIIToUnsignedChar(): Number of hex digits on a line in the file MUST be even!\n"); exit(EXIT_FAILURE); }

// Compute the number of unsigned char bytes needed to store the data.
      read_num_bytes = strlen(line)/HEX_TO_BYTE;

// Keep increasing the size of the array.
      if ( (*bin_arr_ptr = (unsigned char *)realloc(*bin_arr_ptr, sizeof(unsigned char) * (tot_usc_bytes + read_num_bytes))) == NULL )
         { printf("ERROR: ReadFileHexASCIIToUnsignedChar(): Failed to reallocate larger space!\n"); exit(EXIT_FAILURE); }

// Write out the data from low order to high order in the array.
      j = 0;
      for ( i = 0; i < read_num_bytes; i++ )
         {

// Convert 2-char instances of the data read into unsigned char bytes.
         sscanf(&(line[j]), "%2X", &temp);
         (*bin_arr_ptr)[tot_usc_bytes + i] = (unsigned char)temp;
         j += HEX_TO_BYTE;
         }

      tot_usc_bytes += read_num_bytes;
      }

   fclose(INFILE);

   return tot_usc_bytes;
   }


// ========================================================================================================
// ========================================================================================================
// Write unsigned char data (helper data/SpreadFactors/nonces) to file. Data will be packed as ASCII hex characters
// with NO spaces between pairs of consecutive hex digits -- all on one line. 

void WriteFileHexASCIIToUnsignedChar(int max_string_len, char *file_name, int num_bytes, unsigned char *bin_arr, 
   int overwrite_or_append)
   {
   FILE *OUTFILE = NULL;
   int byte_num;

printf("WriteFileHexASCIIToUnsignedChar(): Filename '%s'\tNumber bytes %d\n", file_name, num_bytes); fflush(stdout);
#ifdef DEBUG
#endif

   if ( overwrite_or_append == 0 && (OUTFILE = fopen(file_name, "w")) == NULL )
      { printf("ERROR: WriteFileHexASCIIToUnsignedChar(): Failed to open file '%s'\n", file_name); exit(EXIT_FAILURE); }
   else if ( overwrite_or_append == 1 && (OUTFILE = fopen(file_name, "a")) == NULL )
      { printf("ERROR: WriteFileHexASCIIToUnsignedChar(): Failed to open file '%s'\n", file_name); exit(EXIT_FAILURE); }

// Left-to-right processing of the bits makes the left-most bit in line the high order bit in the binary value. 
   for ( byte_num = 0; byte_num < num_bytes; byte_num++ )
      fprintf(OUTFILE, "%02X", bin_arr[byte_num]);
   fprintf(OUTFILE, "\n");

   fclose(OUTFILE);

   return;
   }


// ========================================================================================================
// ========================================================================================================
// Get provisioning KEK challenge information from the bank while in a secure facility, or replace the existing
// KEK challenge information with new information after authenticating and generating a session key. For the
// former, we assume a secure environment here after manufacture where we get the original challenge information 
// over an insecure channel. Alice and Bob get long-lived KEK challenge information from bank.

void GetKEKChlngInfoProvisionOrReplace(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, char *Bank_IP, 
   int port_number, int Bank_socket_desc, int provision_or_replace, int open_socket)
   {
   int LL_or_session_or_cobra_PO;

struct timeval t1, t2;
long elapsed; 
gettimeofday(&t2, 0);
#ifdef DEBUG
#endif

// ==============================
// 1) Open socket to Bank. 

printf("\nGetKEKChlngInfoProvisionOrReplace(): BEGIN: Bank at '%s':\n", Bank_IP); fflush(stdout);
#ifdef DEBUG
#endif

// Open up a socket connection to the Bank if we are a customer (device). TTP opens this connection in the caller and
// keeps it open permanently. OpenSocketClient returns -1 on failure.
   while ( open_socket == 1 && OpenSocketClient(max_string_len, Bank_IP, port_number, &Bank_socket_desc) < 0 )
      { 
      printf("INFO: GetKEKChlngInfoProvisionOrReplace(): Waiting to connect to Bank for KEK Challenge Information!\n"); fflush(stdout); 
      usleep(200000);
      }

// ==============================
// 2) Mutual authentication with Bank (ONLY IF provision_or_replace is 1). 

// Tell Bank we want KEK challenge information, WITHOUT AUTHENTICATING
// --------------
   if ( provision_or_replace == 0 )
      {

printf("\tGetKEKChlngInfoProvisionOrReplace(): Sending 'KEK-CHALLENGE-PROVISION' to Bank!\n"); fflush(stdout);
#ifdef DEBUG
#endif

      if ( SockSendB((unsigned char *)"KEK-CHALLENGE-PROVISION", strlen("KEK-CHALLENGE-PROVISION") + 1, Bank_socket_desc) < 0 )
         { printf("ERROR: GetKEKChlngInfoProvisionOrReplace(): Failed to send 'KEK-CHALLENGE-PROVISION' to Bank!\n"); exit(EXIT_FAILURE); }
      }

// --------------
// Tell Bank we want KEK challenge information, WITH mutual Authentication and Session Key gen.
   else
      {

printf("\tGetKEKChlngInfoProvisionOrReplace(): Sending 'KEK-CHALLENGE-ENROLL' to Bank!\n"); fflush(stdout);
#ifdef DEBUG
#endif

      if ( SockSendB((unsigned char *)"KEK-CHALLENGE-ENROLL", strlen("KEK-CHALLENGE-ENROLL") + 1, Bank_socket_desc) < 0 )
         { printf("ERROR: GetKEKChlngInfoProvisionOrReplace(): Failed to send 'KEK-CHALLENGE-ENROLL' to Bank!\n"); exit(EXIT_FAILURE); }

// Mutually authenticate and generate a session key. KEK_Enroll is also used to generate a session key. NOTE: We do not store challenge 
// information for session key generation, so we can NEVER regenerate a session key (there is NO regeneration function like there is 
// for KEK key with KEK_Regen). 
      int gen_session_key = 1;
      KEK_ClientServerAuthenKeyGen(max_string_len, SHP_ptr, Bank_socket_desc, gen_session_key);
      }

// ==============================
// 3) Do KEK_Enroll. The enrollment operation will fetch vectors, path select masks, SpreadFactors, XOR_nonce and iterate until the KEY size 
// is achieved.


// 9_18_2022: Timing tests for FSB KEK for SiRF paper. GenLLK from device_regeneration is called and then this routine.
//    Just saving data to a temporary file for this analysis.
#ifdef DEBUG
printf("\nKEK FSB Timing operation for SiRF paper: START\n");
gettimeofday(&t2, 0);
#endif

   LL_or_session_or_cobra_PO = 0;
   KEK_Enroll(max_string_len, SHP_ptr, LL_or_session_or_cobra_PO, Bank_socket_desc);

// 9_18_2022: Timing tests for FSB KEK for SiRF paper. GenLLK from device_regeneration is called and then this routine.
#ifdef DEBUG
gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t2.tv_sec)*1000000 + t1.tv_usec-t2.tv_usec; printf("\tKEK_ENROLL TIME %ld us\n\n", (long)elapsed);
printf("\nKEK FSB Timing operation for SiRF paper: END: Number of iterations %d\n", SHP_ptr->KEK_num_iterations);
exit(EXIT_SUCCESS);
#endif


// ==============================
// 4) Send 'ACK' to Bank to enable it to continue;
   if ( SockSendB((unsigned char *)"ACK", strlen("ACK") + 1, Bank_socket_desc) < 0  )
      { printf("ERROR: GetKEKChlngInfoProvisionOrReplace(): Failed to send 'ACK' to Bank!\n"); exit(EXIT_FAILURE); }

// Get ACK from Bank
   char ack_str[max_string_len];
   if ( SockGetB((unsigned char *)ack_str, max_string_len, Bank_socket_desc) != 4  )
      { printf("ERROR: GetKEKChlngInfoProvisionOrReplace(): Failed to get 'ACK' from Bank!\n"); exit(EXIT_FAILURE); }
   if ( strcmp(ack_str, "ACK") != 0 )
      { printf("ERROR: GetKEKChlngInfoProvisionOrReplace(): Failed to match 'ACK' string from Bank!\n"); exit(EXIT_FAILURE); }

// Free up the key -- ONLY DID this during testing.
//   if ( provision_or_replace == 1 && SHP_ptr->SE_final_key != NULL )
//      free(SHP_ptr->SE_final_key);

// Only close socket descriptor if we are a customer (Alice). TTPs keep their socket connection open permanently.
   if ( open_socket == 1 )
      close(Bank_socket_desc);

gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t2.tv_sec)*1000000 + t1.tv_usec-t2.tv_usec; printf("\tTOTAL EXEC TIME %ld us\n\n", (long)elapsed);
#ifdef DEBUG
#endif

printf("\nGetKEKChlngInfoProvisionOrReplace(): DONE!\n\n"); fflush(stdout);
#ifdef DEBUG
#endif

   return;
   }


// ========================================================================================================
// ========================================================================================================
// Read nonces/SHD from file. If user sets 'num_bytes' to a positive value (not -1), then assume each line
// that is read has exactly 'num_bytes'/2 (number of hex digits per byte) -- assume file is hex encoded ASCII.
// If user specifies 'alloc_arr' as 1, then allocate space for 'bin_arr_ptr' otherwise, assume it exists.
// One possible file structure is SHD on first line, number of RpXORn2s on second line, number of bitstrings 
// as a string on the third line and then RpXORn2s on subsequent lines, with last line storing XOR_nonce (n3).

int ReadFileHexASCIIToUnsignedCharSpecial(int max_string_len, char *file_name, int num_bytes, int alloc_arr, unsigned char **bin_arr_ptr,
   FILE *INFILE)
   {
   unsigned int tot_usc_bytes, read_num_bytes;
   char line[max_string_len+1], *char_ptr;
   int line_cnt, close_file;
   int HEX_TO_BYTE = 2;
   unsigned int temp;
   unsigned int i, j;

printf("ReadFileHexASCIIToUnsignedCharSpecial(): Filename '%s'\tNumber of bytes %d\tAlloc arr? %d\n", file_name, num_bytes, alloc_arr); fflush(stdout);
#ifdef DEBUG
#endif

// If the user passes in an open file (INFILE NOT NULL), the do NOT close it. Only close files that are opened by this routine.
   close_file = 1;
   if ( INFILE == NULL && (INFILE = fopen(file_name, "r")) == NULL )
      { printf("ERROR: ReadFileHexASCIIToUnsignedCharSpecial(): Failed to open file '%s'\n", file_name); exit(EXIT_FAILURE); }
   else
      close_file = 0;

// Assume nonce lines NEVER get longer than max_string_len, which is set to 2048 currently. If data stored as
// ASCII binary, then this allows for upto 2048 bits or 256 bytes per line.
   tot_usc_bytes = 0;
   line_cnt = 0;
   while ( fgets(line, max_string_len - 1, INFILE) != NULL )
      {

// Find the newline and eliminate it.
      if ((char_ptr = strrchr(line, '\n')) != NULL)
         *char_ptr = '\0';

// Skip blank lines.
      if ( strlen(line) == 0 )
         continue;

// When requested, check that the nonce size is consistent with input parameter. We assume 1 line here (for n3).
      if ( num_bytes != -1 && strlen(line)/HEX_TO_BYTE != (unsigned int)num_bytes )
         { 
         printf("ERROR: ReadFileHexASCIIToUnsignedCharSpecial(): Length of nonce in bytes %d is NOT equal to the required length %d!\n", (int)strlen(line)/HEX_TO_BYTE, num_bytes);
         exit(EXIT_FAILURE); 
         }

      read_num_bytes = strlen(line)/HEX_TO_BYTE;

// Allocate/reallocate storage in bin_arr if requested.
      if ( alloc_arr == 1 )
         {
         if ( tot_usc_bytes == 0 )
            *bin_arr_ptr = (unsigned char *)malloc(read_num_bytes * sizeof(unsigned char));
         else
            *bin_arr_ptr = (unsigned char *)realloc(*bin_arr_ptr, (tot_usc_bytes + read_num_bytes) * sizeof(unsigned char));
         }

// Left-to-right processing of the bits makes the left-most bit in line the high order bit in the binary value. 
      j = 0;
      for ( i = 0; i < read_num_bytes; i++ )
         {
         sscanf(&(line[j]), "%2X", &temp);
         (*bin_arr_ptr)[tot_usc_bytes + i] = (unsigned char)temp;
         j += HEX_TO_BYTE;
         }

      tot_usc_bytes += read_num_bytes;
      line_cnt++; 

// If the call specifies the number of bytes to read (they must be on one line), and we read them and exit loop.
      if ( num_bytes != -1 )
         break;
      }

   if ( close_file == 1 )
      fclose(INFILE);

printf("ReadFileHexASCIIToUnsignedCharSpecial(): Total number of nonce bytes read %d\n", tot_usc_bytes); fflush(stdout);
#ifdef DEBUG
#endif

   return tot_usc_bytes;
   }


