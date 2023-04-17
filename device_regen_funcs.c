// ========================================================================================================
// ========================================================================================================
// ***************************************** device_regen_funcs.c *****************************************
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

#include "aes_128_ecb_openssl.h"
#include "aes_256_cbc_openssl.h"

// ====================== DATABASE STUFF =========================
#include <sqlite3.h>
#include "commonDB.h"

// ====================== SHA-3 =========================
#include <openssl/bn.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

#include "sha_3_256_openssl.h"


// ========================================================================================================
// ========================================================================================================
// For handling Ctrl-C. We MUST exit gracefully to keep the hardware from quitting at a point where the
// fine phase of the MMCM is has not be set back to 0. If it isn't, then re-running this program will
// likely fail because my local fine phase register (which is zero initially after a RESET) is out-of-sync 
// with the MMCM phase (which is NOT zero). If we are in the middle of running the SRF PUF, then I set
// SAFE_TO_QUIT to 0, so this does not leave SRF in an undefined state, otherwise exit immediately.

int SAFE_TO_QUIT = 1;

void intHandler(int dummy) 
   { 
   printf("!!!!!!!!!!!!!!!! Ctrl-C pressed -- quitting program!\n");
   fflush(stdout);
   keepRunning = 0; 

// Exit the loops in ttp_DB.c so we can save the database. Also just exit the loops in device_regeneration
// with the 'keepRunning' flag set to 0.
   if ( SAFE_TO_QUIT == 1 )
      exit(EXIT_SUCCESS);
   }


// ========================================================================================================
// ========================================================================================================
// This converts the 2 vector sequences stored in the database and transmitted by the server to this device into
// one vector challenges. NOTE: num_PIs is num_chlng_bits/2.
// *** VEC_CHLNG ***

unsigned char **ConvertVecsToChallenge(int max_string_len, int num_vecs, int num_PIs, unsigned char **first_vecs_b, 
   unsigned char **second_vecs_b, int num_chlng_bits)
   {
   unsigned char **challenges_b;
   int vec_num, i, j;

   if ( (challenges_b = (unsigned char **)malloc(sizeof(unsigned char *) * num_vecs)) == NULL )
      { printf("ERROR: ConvertVecsToChallenge(): Failed to allocate storage for challenges_b array!\n"); exit(EXIT_FAILURE); }

   for ( vec_num = 0; vec_num < num_vecs; vec_num++ )
      {
      if ( (challenges_b[vec_num] = (unsigned char *)malloc(sizeof(unsigned char)*num_chlng_bits/8)) == NULL )
         { printf("ERROR: ConvertVecsToChallenge(): Failed to allocate storage for challenges_b element!\n"); exit(EXIT_FAILURE); }

      for ( i = 0, j = 0; i < num_PIs/8; i++, j++ )
         challenges_b[vec_num][j] = first_vecs_b[vec_num][i];

      for ( i = 0; i < num_PIs/8; i++, j++ )
         challenges_b[vec_num][j] = second_vecs_b[vec_num][i];
      }

   return challenges_b;
   }


// ========================================================================================================
// ========================================================================================================
// Collect all PNs. This is the longer operation associated with SRF (depending on the number of samples).

int CollectPNs(int max_string_len, int num_POs, int num_PIs, int vec_chunk_size, int max_generated_nonce_bytes, 
   volatile unsigned int *CtrlRegA, volatile unsigned int *DataRegA, unsigned int ctrl_mask, int num_vecs, 
   int num_rise_vecs, int has_masks, unsigned char **first_vecs_b, unsigned char **second_vecs_b, 
   unsigned char **masks_b, unsigned char *device_n1, int DUMP_BITSTRINGS, int debug_flag)
   {
   int vec_num, generated_device_num_n1_bytes; 

// *** VEC_CHLNG ***
   int num_chlng_bits = num_PIs * 2;
   unsigned char **challenges_b;

   struct timeval t0, t1;
   long elapsed; 

// ****************************************
// ***** Collect PNs 
   if ( debug_flag == 1 )
      {
      printf("CPN.1) Collecting ALL PNs and Generating Device Nonces in Parallel\n");
      gettimeofday(&t0, 0);
      }

// WARNING: IN_SIM_DONE_ALL_VECS is connected to the ready signal in the state machine and therefore will be 1 UNTIL the CollectPN state 
// machine is started. In this C code, WE ALWAYS START THE hardware MstCtrl state machines BEFORE CALLING THIS ROUTINE (assert/deassert 
// OUT_CP_PUF_START). I've added this while-loop check BEFORE the main while loop to wait for IN_SM_DONE_ALL_VECS to go low BEFORE entering 
// the main while loop that delivers vectors to the hardware because this is technically a race condition. If the race is ever lost, where 
// this C code executes the main while loop BEFORE MstCtrl has a chance to start CollectPNs, then you would get all zeros for the timing 
// data (no vectors would have been delivered). This is prevented with this additional while loop check, which waits for IN_SM_DONE_ALL_VECS 
// to got low.
   while ( ((*DataRegA) & (1 << IN_SM_DONE_ALL_VECS)) != 0 );

// I store the challenges in the database as two vector sequences even though for SRF, there is only ONE configuration challenge. 
// I'll eventually change the database structure, but right now, I simply split the one challenge into two pieces and store
// the first half in first_vecs_b and the second half in second_vecs_b. This routine simply joins these vectors pairs and
// returns 'challenges_b'.
// *** VEC_CHLNG ***
   challenges_b = ConvertVecsToChallenge(max_string_len, num_vecs, num_PIs, first_vecs_b, second_vecs_b, num_chlng_bits);

// Vectors are requested as needed by the CollectPNs.vhd routine (no internal vector storage).
   generated_device_num_n1_bytes = 0;

// Nasty BUG 6_3_2016 here -- VHDL was setting IN_SM_DONE_ALL_VECS BEFORE the last potential NONCE byte was generated and was hanging the 
// VHDL/C code. 
   vec_num = 0;
   while ( ((*DataRegA) & (1 << IN_SM_DONE_ALL_VECS)) == 0 )
      {

// Transfer a vector to VHDL registers once it is requested. NOTE: It is the responsibility of the verifier to provide exactly enough rising vectors 
// to supply 2048 rising PNs (falling vectors don't really matter since we exit this loop when CollectPNs indicates that it has all the timing 
// values it needs). There can be more than 2048 rising PNs but once the limit is exceeded, no more rising vectors should be applied, i.e., the 
// next vector MUST be a falling vector.
      if ( ((*DataRegA) & (1 << IN_SM_LOAD_VEC_PAIR)) != 0 )
         {

#ifdef DEBUG
printf("CollectPNs(): CPN ready %d\tPNDiff ready %d\tSHD_BG ready %d\tLM_ULM ready %d\tGPEVCAL ready %d\tDONE ALL VECS %d\n", 
   ((*DataRegA) & (1 << IN_DEBUG_CPN_READY)) >> IN_DEBUG_CPN_READY,
   ((*DataRegA) & (1 << IN_DEBUG_PNDIFF_READY)) >> IN_DEBUG_PNDIFF_READY,
   ((*DataRegA) & (1 << IN_DEBUG_SHD_BG_READY)) >> IN_DEBUG_SHD_BG_READY,
   ((*DataRegA) & (1 << IN_DEBUG_LM_ULM_READY)) >> IN_DEBUG_LM_ULM_READY,
   ((*DataRegA) & (1 << IN_DEBUG_GPEVCAL_READY)) >> IN_DEBUG_GPEVCAL_READY,
   ((*DataRegA) & (1 << IN_SM_DONE_ALL_VECS)) >> IN_SM_DONE_ALL_VECS
   ); fflush(stdout);
#endif

// Sanity check
         if ( vec_num == num_vecs )
            { 
            printf("ERROR: CollectPNs(): Request for vec %d BEYOND largest available!\n", vec_num); 
// Check for errors in overflow
            if ( ((*DataRegA) & (1 << IN_PNDIFF_OVERFLOW_ERR)) != 0 )
               printf("ERROR: CollectPNs(): PN Overflow error in hardware!\n");
            exit(EXIT_FAILURE); 
            }

// *** VEC_CHLNG ***
         LoadChlngAndMask(max_string_len, CtrlRegA, DataRegA, vec_num, challenges_b, ctrl_mask, num_chlng_bits, vec_chunk_size, 
            has_masks, num_POs, masks_b);

#ifdef DEBUG
PrintHeaderAndBinVals("", num_POs, masks_b[vec_num], 32);
#endif

#ifdef DEBUG
printf("Loaded challenge %d\n", vec_num); fflush(stdout);
#endif

         vec_num++;
         }

// While PNs are being generated, I simultaneously generate Nonce bytes. Variable number so be sure the array is large enough. 
// Keep checking 'stopped' until the next vector request or the PN termination condition is met. WARNING: SECOND CONDITION
// MUST BE HERE OTHERWISE THIS MAY END UP 'stealing' A HD BYTE. If you see an error below 'PROGRAM ERROR: Expected helper data num 
// bytes to be 256 -- READ 255 instead!', then this stole a byte.
      if ( ((*DataRegA) & (1 << IN_SM_HANDSHAKE)) != 0 && ((*DataRegA) & (1 << IN_SM_DONE_ALL_VECS)) == 0 )
         {
// BYTE-TO-WORD
         if ( generated_device_num_n1_bytes + 1 >= max_generated_nonce_bytes )
            { printf("WARNING: Too many nonce bytes generated by hardware -- increase array size in program!\n"); fflush(stdout); }

// 7/1/2017: Note: In VHDL, I consistently fill in 16-bit words from low-order to high order so this makes the most sense, i.e., to
// read the low-order byte first (and store in a lower address) and then the high order byte. Note that when the number of bits is
// NOT a multiple of 8, we need to eliminate high order bits in the last byte. 
         else
            {
            device_n1[generated_device_num_n1_bytes] = (unsigned char)((*DataRegA) & 0x000000FF);
            generated_device_num_n1_bytes++;
            device_n1[generated_device_num_n1_bytes] = (unsigned char)(((*DataRegA) & 0x0000FF00) >> 8);
            generated_device_num_n1_bytes++;
            }

#ifdef DEBUG
printf("Got nonce word (16-bits) -- current number of nonce bytes %d\n", generated_device_num_n1_bytes); fflush(stdout);
#endif

         *CtrlRegA = ctrl_mask | (1 << OUT_CP_HANDSHAKE);
         while ( ((*DataRegA) & (1 << IN_SM_HANDSHAKE)) != 0 );
         *CtrlRegA = ctrl_mask;
         }
      }

   if ( vec_num != num_vecs )
      { printf("WARNING: CollectPNs(): NOT ALL VECTORS were processed: Processed only %d of %d!\n", vec_num, num_vecs); fflush(stdout); }

// Be sure control mask is restored after vector transfer is complete.
   *CtrlRegA = ctrl_mask;



// EITHER THIS BE INCLUDED OR THE STUFF IN THE DEBUG statement DIRECTLY BELOW WHILE THE DEBUG code exists in the bitstream.
#ifdef DEBUG
while ( ((*DataRegA) & (1 << IN_SM_HANDSHAKE)) == 0 );
*CtrlRegA = ctrl_mask | (1 << OUT_CP_HANDSHAKE);
while ( ((*DataRegA) & (1 << IN_SM_HANDSHAKE)) != 0 );
*CtrlRegA = ctrl_mask | (1 << OUT_CP_LM_ULM_DONE);
*CtrlRegA = ctrl_mask;
#endif

#ifdef DEBUG
int PNs_stored[4096];
int i;
for ( i = 0; i < 4096; i++ )
   {
   while ( ((*DataRegA) & (1 << IN_SM_HANDSHAKE)) == 0 );
   PNs_stored[i] = (int)((*DataRegA) & 0x0000FFFF);
   printf("%4d) %9.4f\n", i, (float)PNs_stored[i]/16); fflush(stdout);
   
   *CtrlRegA = ctrl_mask | (1 << OUT_CP_HANDSHAKE);
   while ( ((*DataRegA) & (1 << IN_SM_HANDSHAKE)) != 0 );
   if ( i == 4095 )
      *CtrlRegA = ctrl_mask | (1 << OUT_CP_LM_ULM_DONE);
   else
      *CtrlRegA = ctrl_mask;
   }

// Deassert 'DONE'
*CtrlRegA = ctrl_mask;
#endif



// Print out the nonces if requested
   if ( DUMP_BITSTRINGS == 1 )
      {
      char header_str[max_string_len];
      sprintf(header_str, "\n\tGenerated Device nonces n1:\n");
      PrintHeaderAndHexVals(header_str, generated_device_num_n1_bytes, device_n1, 32);
      }

   if ( debug_flag == 1 )
      { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tElapsed %ld us\n\n", (long)elapsed); }
   fflush(stdout);

// Free up the challenges_b.
// *** VEC_CHLNG ***
   for ( vec_num = 0; vec_num < num_vecs; vec_num++ )
      if ( challenges_b[vec_num] != NULL )
         free(challenges_b[vec_num]);

// Check for errors in overflow
   if ( ((*DataRegA) & (1 << IN_PNDIFF_OVERFLOW_ERR)) != 0 )
      { printf("ERROR: CollectPNs(): PN Overflow error in hardware!\n"); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("CollectPNs(): CPN ready %d\tPNDiff ready %d\tSHD_BG ready %d\tLM_ULM ready %d\tGPEVCAL ready %d\tDONE ALL VECS %d\n", 
   ((*DataRegA) & (1 << IN_DEBUG_CPN_READY)) >> IN_DEBUG_CPN_READY,
   ((*DataRegA) & (1 << IN_DEBUG_PNDIFF_READY)) >> IN_DEBUG_PNDIFF_READY,
   ((*DataRegA) & (1 << IN_DEBUG_SHD_BG_READY)) >> IN_DEBUG_SHD_BG_READY,
   ((*DataRegA) & (1 << IN_DEBUG_LM_ULM_READY)) >> IN_DEBUG_LM_ULM_READY,
   ((*DataRegA) & (1 << IN_DEBUG_GPEVCAL_READY)) >> IN_DEBUG_GPEVCAL_READY,
   ((*DataRegA) & (1 << IN_SM_DONE_ALL_VECS)) >> IN_SM_DONE_ALL_VECS
   ); fflush(stdout);
#endif

   return generated_device_num_n1_bytes;
   }


// ========================================================================================================
// ========================================================================================================
// Get verifier nonce, XOR with device nonce, send XOR nonce to verifier.

void NonceExchange(int max_string_len, int verifier_socket_desc, int num_required_nonce_bytes, 
   unsigned char *device_n1, int num_device_n1_nonces, unsigned char *verifier_n2, unsigned char *XOR_nonce, 
   int DUMP_BITSTRINGS, int debug_flag)
   {
   int i;

   struct timeval t0, t1;
   long elapsed; 

// Sanity check. 
   if ( num_device_n1_nonces < num_required_nonce_bytes )
      printf("WARNING: NonceExchange(): Hardware NONCE generation did not return enough binary bytes: returned %d require %d!\n", 
         num_device_n1_nonces, num_required_nonce_bytes); 

// ****************************************
// ***** Receive nonce n2 from verifier
   if ( debug_flag == 1 )
      {
      printf("NExch.1) Receiving verifier nonce n2\n");
      gettimeofday(&t0, 0);
      }
   if ( SockGetB(verifier_n2, num_required_nonce_bytes, verifier_socket_desc) != num_required_nonce_bytes )
      { printf("ERROR: NonceExchange(): 'verifier_n2' bytes received is not equal to %d\n", num_required_nonce_bytes); exit(EXIT_FAILURE); }
   if ( debug_flag == 1 )
      { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tElapsed %ld us\n\n", (long)elapsed); }

// DEBUG: Dump out the values as hex
   if ( debug_flag == 1 )
      {
      char header_str[max_string_len];
      sprintf(header_str, "\tReceived Verifier nonces n2 (high to low):\n");
      PrintHeaderAndHexVals(header_str, num_required_nonce_bytes, verifier_n2, 8);
      }

// ****************************************
// ***** Create XOR nonce 
   if ( debug_flag == 1 )
      {
      printf("NExch.2) Creating XOR nonce (n1 XOR n2)\n");
      gettimeofday(&t0, 0);
      }
   for ( i = 0; i < num_required_nonce_bytes; i++ ) 
      XOR_nonce[i] = device_n1[i] ^ verifier_n2[i];
   if ( debug_flag == 1 )
      { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tElapsed %ld us\n\n", (long)elapsed); }

// Print out the final XOR nonce if requested
   if ( DUMP_BITSTRINGS == 1 )
      {
      char header_str[max_string_len];
      sprintf(header_str, "\tSending device XOR nonces (n1 XOR n2), high to low:\n");
      PrintHeaderAndHexVals(header_str, num_required_nonce_bytes, XOR_nonce, 8);
      }

// ****************************************
// ***** Send the XOR nonce (n1 XOR n2) to the verifier
   if ( debug_flag == 1 )
      {
      printf("NExch.3) Sending XOR nonce (n1 XOR n2)' \n");
      gettimeofday(&t0, 0);
      }
   if ( SockSendB(XOR_nonce, num_required_nonce_bytes, verifier_socket_desc) < 0 )
      { printf("ERROR: NonceExchange(): Send 'XOR_nonce' failed\n"); exit(EXIT_FAILURE); }
   if ( debug_flag == 1 )
      { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tElapsed %ld us\n\n", (long)elapsed); }
   fflush(stdout);

   return;
   }


// ========================================================================================================
// ========================================================================================================
// Convenience function that sets the PN reuse flag in the hardware, restarts the SRF engine and then sends
// a request to the server for more SpreadFactors if SpreadFactor mode is pop or pop+perchip

void SetSRFReuseModeStartSRFRequestSpreadFactors(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, 
   int do_server_SpreadFactors_next, int verifier_socket_desc)
   {
   char request_str[max_string_len];

   struct timeval t0, t1;
   long elapsed; 

// Sanity check. PUF engine MUST be 'ready'
   if ( (*(SHP_ptr->DataRegA) & (1 << IN_SM_READY)) == 0 )
      { printf("ERROR: SetSRFReuseModeStartSRFRequestSpreadFactors(): PUF Engine is NOT ready!\n"); exit(EXIT_FAILURE); }

// Re-start the PUF engine with the next LFSR seed. NOTE: This is not confirmed via a handshake, which it should be. Adding a usleep to make 
// sure a 'slow' version of the hardware state machine sees the start signal.
   SHP_ptr->ctrl_mask = SHP_ptr->ctrl_mask | (1 << OUT_CP_REUSE_PNS_MODE);

// Start SRF
   *(SHP_ptr->CtrlRegA) = SHP_ptr->ctrl_mask | (1 << OUT_CP_PUF_START); 
   usleep(1000);
   *(SHP_ptr->CtrlRegA) = SHP_ptr->ctrl_mask;

#ifdef DEBUG
printf("SetSRFReuseModeStartSRFRequestSpreadFactors(): RESTARTING PUF(): Sending SpreadFactors request!\n"); fflush(stdout);
#endif

// Tell server we need more SpreadFactors
   if ( do_server_SpreadFactors_next == 1 )
      {
      strcpy(request_str, "SPREAD_FACTORS NEXT");
      if ( SHP_ptr->DEBUG_FLAG == 1 )
         {
         printf("\tSending '%s'\n", request_str);
         gettimeofday(&t0, 0);
         }
      if ( SockSendB((unsigned char *)request_str, strlen(request_str)+1, verifier_socket_desc) < 0 )
         { printf("ERROR: Send '%s' request failed\n", request_str); exit(EXIT_FAILURE); }
      if ( SHP_ptr->DEBUG_FLAG == 1 )
         { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tTOTAL EXEC TIME %ld us\n\n", (long)elapsed); }
      }

#ifdef DEBUG
printf("SetSRFReuseModeStartSRFRequestSpreadFactors(): Sent SpreadFactors REQUEST -- returning!\n"); fflush(stdout);
#endif

   return;
   }


// ========================================================================================================
// ========================================================================================================
// Convenience function that simply sends 'done' request to server to stop computing and sending SpreadFactors.

void SendSpreadFactorsDone(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int verifier_socket_desc)
   {
   char request_str[max_string_len];

   struct timeval t0, t1;
   long elapsed; 

   strcpy(request_str, "SPREAD_FACTORS DONE");
   if ( SHP_ptr->DEBUG_FLAG == 1 )
      {
      printf("\tSending '%s'\n", request_str);
      gettimeofday(&t0, 0);
      }
   if ( SockSendB((unsigned char *)request_str, strlen(request_str)+1, verifier_socket_desc) < 0 )
      { printf("ERROR: Send '%s' request failed\n", request_str); exit(EXIT_FAILURE); }
   if ( SHP_ptr->DEBUG_FLAG == 1 )
      { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tTOTAL EXEC TIME %ld us\n\n", (long)elapsed); }

   return;
   }


// ========================================================================================================
// ========================================================================================================
// Get SpreadFactors from verifier. NOTE: This function is NOT called if current_function is DA or LL_Enroll
// and PBD mode is requested.

void GetSpreadFactors(int max_string_len, int num_SF_words, int num_SF_bytes, int verifier_socket_desc,
   signed char *iSpreadFactors, int iSpreadFactorScaler, int current_function, int debug_flag)
   {
   int PND_num;

#ifdef DEBUG
printf("GetSpreadFactor(): CALLED\tFunction %d! (If called, we are retrieving SF of some type!)\n", current_function); fflush(stdout);
#endif


#ifdef DEBUG
int limit = 20;
#endif

   struct timeval t0, t1;
   long elapsed; 

// Make sure iSpreadFactors is all zeros 
   for ( PND_num = 0; PND_num < num_SF_words; PND_num++ )
      iSpreadFactors[PND_num] = 0;

// Get Population SpreadFactors from the verifier
   if ( debug_flag == 1 )
      {
      printf("CO.1) Receiving SpreadFactors\n");
      gettimeofday(&t0, 0);
      }
   if ( SockGetB((unsigned char *)iSpreadFactors, num_SF_bytes, verifier_socket_desc) != num_SF_bytes )
      { printf("ERROR: GetSpreadFactors(): 'SpreadFactor' bytes received is not equal to %d\n", num_SF_bytes); exit(EXIT_FAILURE); }
   if ( debug_flag == 1 )
      PrintHeaderAndHexVals((char *)"SpreadFactors:\n", num_SF_bytes, (unsigned char *)iSpreadFactors, 64);
   if ( debug_flag == 1 )
      { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tElapsed %ld us\n\n", (long)elapsed); }
   fflush(stdout);

#ifdef DEBUG
printf("GetSpreadFactors(): num_SF_words %d\tnum_SF_bytes %d\n", num_SF_words, num_SF_bytes); fflush(stdout); 
for ( PND_num = 0; PND_num < limit; PND_num++ )
   printf("%4d)\tiSpreadFactors %+4d\tfSpreadFactors (DIV %d) %+9.4f\n", PND_num, iSpreadFactors[PND_num], iSpreadFactorScaler,
      (float)iSpreadFactors[PND_num]/iSpreadFactorScaler);
#endif

#ifdef DEBUG
printf("GetSpreadFactor(): DONE!\n"); fflush(stdout);
#endif

   return;
   }


// ========================================================================================================
// ========================================================================================================
// Select and then transfer parameters to hardware. 'target_attempts' is used to increment the first LFSR
// seed (canNOT increment both otherwise we get the same sequence SpreadConstant by 1). When this routine called 
// repeatedly to generate a 'target_num_key_bits', we use the same parameters except for the seeds.
//
// 10_17_2021: Added flags in hardware (3 more parameters) to do control options for the functions (from log pp. 6062).
// Load_SF:         1 when SFs need to be loaded
// computeSF:       1 when SFs need to be computed by the device
// PCR_PBD_PO mode: 0, 1 or 2 to indicate mode
// modify_PO mode:  1 when PO offsets loaded need to be modified to do inversion 
//                     FUNC_DA            FUNC_VA           FUNC_SE            LL_Enroll          LL_Regen           TRNG
//                 PO  PCR    PBD     PO  PCR    PBD     PO  PCR    PBD     PO  PCR    PBD     PO  PCR    PBD     PO  PCR    PBD 
// =======================================================================================================================
// SF:             PO  PO     None    PO  PCR    PBD     PO  PCR    PBD     PO  PO    None     PO  PCR    PBD     None None None
// ASF1:            Y   Y       N      Y    Y      Y      Y    Y      Y      Y   Y      N       Y    Y      Y      N   N     N
// Load_SF   
//
// ASF2:            N   Y       Y      N    N      N      N    N      N      N   Y      Y       N    N      N      Y   Y     Y
// compute_PCR_PBD
//
// PCR_PBD_PO       2   0       1      2    0      1      2    0      1      2    0     1       2    0      1      1   1     1
// modify_PO        Y   Y       N*     N    N      N      N    N      N      Y    Y     N*      N    N      N      N   N     N
// dump_updated_SF  Y   Y       Y      N    N      N      N    N      N      Y    Y     Y       N    N      N      N   N     N
//
// * means setting this is irrelevant b/c PO SF are NOT loaded.

void SelectSetParams(int max_string_len, int num_required_PNDiffs, volatile unsigned int *CtrlRegA, 
   volatile unsigned int *DataRegA, unsigned int ctrl_mask, int num_required_nonce_bytes, int nonce_base_address, 
   unsigned char *XOR_nonce, unsigned int target_attempts, int force_threshold_zero, int fix_params, 
   unsigned int RangeConstant, unsigned short SpreadConstant, unsigned short Threshold, unsigned short TrimCodeConstant,
   unsigned int ScalingConstant, int XMR_val, int num_KEK_authen_nonce_bits_remaining, int load_SF, int compute_PCR_PBD, 
   int modify_SF, int dump_updated_SF, int param_PCR_or_PBD_or_PO, int current_function, unsigned int *LFSR_seed_low_ptr, 
   unsigned int *LFSR_seed_high_ptr, int do_scaling, int debug_flag)
   {
   unsigned int LFSR_seed_low, LFSR_seed_high; 
   int num_params, param_num;

   struct timeval t0, t1;
   long elapsed; 

   num_params = 14;

// ****************************************
// ***** Select parameter values 
   if ( debug_flag == 1 )
      {
      printf("SPrms.1) Selecting parameters\n");
      gettimeofday(&t0, 0);
      }

// NOTE: WE DO NOT CHANGE RangeConstant, SpreadConstant, Threshold or TrimCodeConstant formal parameters above in this routine
// since I need to set RangeConstant to specific value in the Device Authentication functions.
   if ( fix_params == 0 )
      SelectParams(num_required_nonce_bytes, XOR_nonce, nonce_base_address, &LFSR_seed_low, &LFSR_seed_high, &RangeConstant, 
         &SpreadConstant, &Threshold, &TrimCodeConstant);

// If user wants to 'fix the parameters'
   else
      {
      LFSR_seed_low = FIXED_LFSR_SEED_LOW;
      LFSR_seed_high = FIXED_LFSR_SEED_HIGH;
      RangeConstant = FIXED_RANGE_CONSTANT;
      SpreadConstant = FIXED_SPREAD_CONSTANT;
      Threshold = FIXED_THRESHOLD;
      TrimCodeConstant = FIXED_TRIMCODE_CONSTANT;

// The equivalent of 1.0 (1 << SCALING_PRECISION_NB)
      ScalingConstant = FIXED_SCALING_CONSTANT;
      }

// 10_28_2022: Force Scaling Constant to 1 (which will prevent it from being used in the Verilog code) for PCR and PBD mode.
// It is NOT needed here because it REPLACES PCR mode and PBD uses low order integer bit to determine bit value.
// 11_12_2022: Added a 'do_scaling' flag. If this is 0, disable scaling. Set to 1 in the calling function. Currently this
// is done for COBRA and possibly for PARCE (SKE). It is 0 by default which forces a 1.0 for scaling, disabling it.
   if ( do_scaling == 0 ) // || param_PCR_or_PBD_or_PO != SF_MODE_POPONLY )
      {

// Cannot use 0.0 here -- it is a hardware parameter error. Using (scaled) 1.0 as the factor SKIPS any scaling in the hardware.
      ScalingConstant = (1 << SCALING_PRECISION_NB);
#ifdef DEBUG
printf("SelectSetParams(): Mode is NOT PopOnly -- FORCING ScalingConstant to 1.0 => FixedPoint should be (1 << %d): %d!\n", SCALING_PRECISION_NB, ScalingConstant); fflush(stdout);
#endif
      }
   else
      {
#ifdef DEBUG
printf("SelectSetParams(): PopOnly MODE -- Using ScalingConstant (FixedPoint) %d!\n", ScalingConstant); fflush(stdout);
#endif
      }

   if ( debug_flag == 1 )
      { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tElapsed %ld us\n\n", (long)elapsed); }

// For iterating until we reach a 'target_num_key_bits'. Assume same 'XOR_nonce' bytes are used repeatedly. Just increment the first LFSR seed 
// (do NOT increment BOTH otherwise you get the same sequence).
   LFSR_seed_high = (LFSR_seed_high + target_attempts) % num_required_PNDiffs;

   if ( force_threshold_zero == 1 )
      Threshold = 0;

   *LFSR_seed_low_ptr = LFSR_seed_low;
   *LFSR_seed_high_ptr = LFSR_seed_high;

#ifdef DEBUG
printf("\tLFSR low %4u  high %4u  RC %3d  SC %3d  TH %2u  TCC %2u SCC %5d XMR %2d  Auth bits left %3d  PCR/PBD/PO %d  Load SF %d  CompPCR/PBD %d  Mod SF %d Dump SF %d\n", 
   LFSR_seed_low, LFSR_seed_high, RangeConstant, SpreadConstant, Threshold, TrimCodeConstant, ScalingConstant, XMR_val, num_KEK_authen_nonce_bits_remaining, param_PCR_or_PBD_or_PO, 
   load_SF, compute_PCR_PBD, modify_SF, dump_updated_SF); fflush(stdout);
#endif

// ****************************************
// ***** Transfer parameters into hardware.
   if ( debug_flag == 1 )
      {
      printf("SPrms.2) Transferring params to hardware\n");
      gettimeofday(&t0, 0);
      }
          
// Wait for hardware to ask for first parameter. 4/28/2018: THIS USED TO BE A 'for loop' -- NO GOOD!!!!!! Made it a while loop.
// Must have been 'just getting lucky' in the past.
   param_num = 0;
   while ( param_num < num_params )
      {
      int out_val;

// NOTE: RangeConstant is an unsigned integer no bigger than the number of hardware bits in PNL_BRAM for the integer portion, i.e., 11 bits can hold 
// (-1023 to +1023).
      if ( ((*DataRegA) & (1 << IN_SM_HANDSHAKE)) != 0 )
         {
         if ( param_num == 0 )
            out_val = LFSR_seed_low;
         else if ( param_num == 1 )
            out_val = LFSR_seed_high;
         else if ( param_num == 2 )
            out_val = RangeConstant;
         else if ( param_num == 3 )
            out_val = SpreadConstant;  
         else if ( param_num == 4 )
            out_val = Threshold;  
         else if ( param_num == 5 )
            out_val = XMR_val;
         else if ( param_num == 6 )
            out_val = num_KEK_authen_nonce_bits_remaining;
         else if ( param_num == 7 )
            {

// We MUST force PBD off unless we are doing DA and LL_ENROLL enrollment functions (NOTE: we also force PBD mode for the TRNG modes but that is done within
// the Verilog code). THIS ONLY determines if we run AddSpreadFactors in PCR or PBD mode in the hardware. compute_PCR_PBD controls whether we use PopOnly
// SF or not in the hardware. Here in the software, we use this parameter to determine if the user wants PopOnly (PO) and set 'compute_PCR_PBD' appropriately.
// NOTE: In the hardware, we use ONLY the low order bit of param_PCR_or_PBD_or_PO to determine PCR or PBD mode so when set to 2 for PopOnly, we would run
// PCR mode. HOWEVER, the hardware does NOT run AddSpreadFactors.v unless 'compute_PCR_PBD' is 1, which will NOT be the case if we are using PopOnly SF.
            if ( current_function == FUNC_DA || current_function == FUNC_LL_ENROLL )
               out_val = param_PCR_or_PBD_or_PO;
            else
               out_val = 0;
            }
         else if ( param_num == 8 )
            out_val = load_SF;
         else if ( param_num == 9 )
            out_val = compute_PCR_PBD;
         else if ( param_num == 10 )
            out_val = modify_SF;
         else if ( param_num == 11 )
            out_val = dump_updated_SF;
         else if ( param_num == 12 )
            out_val = TrimCodeConstant;
         else 
            out_val = ScalingConstant;

// 'OR' in the value into the low order 16 bits preserving the signed/unsigned nature of the value.
         *CtrlRegA = ctrl_mask | (1 << OUT_CP_HANDSHAKE) | (0x0000FFFF & out_val);
         while ( ((*DataRegA) & (1 << IN_SM_HANDSHAKE)) != 0 );
         *CtrlRegA = ctrl_mask;
         param_num++; 
         }
      }

   usleep(1000);
   if ( ((*DataRegA) & (1 << IN_PARAM_ERR)) != 0 )
      { printf("ERROR: SelectSetParams(): Parameter error in hardware!\n"); exit(EXIT_FAILURE); }

   if ( debug_flag == 1 )
      { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tElapsed %ld us\n\n", (long)elapsed); }
   fflush(stdout);

   return;
   }


// ========================================================================================================
// ========================================================================================================
// Load BRAM with data. We ALWAYS read or write 16-bit words from BRAM. If 'byte_or_word_data' is 0, then
// we use the ByteData array (8-bits each byte) and load a 16-bit word in the low-order byte to high_order
// byte order, i.e., low order byte of 16-bit word goes into byte 0, high order byte of 16-bit word goes
// into byte 1, etc. WE MUST INCREMENT val_num (the index into ByteData) BY 2, NOT 1. When 'byte_or_word_data'
// is 1, we transfer 16-bits to 16-bits. NOTE: I switched the meaning of 'byte_or_word' from the old code
// here.

void LoadUnloadBRAM(int max_string_len, int num_vals, volatile unsigned int *CtrlRegA, volatile unsigned int *DataRegA, 
   unsigned int ctrl_mask, unsigned char *ByteData, signed short *WordData, int load_or_unload, int byte_or_word_data, 
   int debug_flag)
   {
   int val_num, locked_up, increment;

// BYTE-TO-WORD
// Sanity check. When byte_or_word_data is 0, then we are transferring in byte data two bytes at-a-time, i.e., we transfer 16-bits at a time 
// into the PL side so ensure num_vals is an even number.
   if ( byte_or_word_data == 0 && (num_vals % 2) != 0 )
      { printf("ERROR: LoadUnloadBRAM(): 'num_vals' MUST BE an even number for ByteData transfers to BRAM!\n"); exit(EXIT_FAILURE); }

// ****************************************
// ***** Load BRAM with data
   if ( debug_flag == 1 )
      {
      if ( load_or_unload == 0 )
         printf("LB.1) Loading BRAM: Number of values to load %d\n", num_vals); 
      else
         printf("LB.1) UnLoading BRAM: Number of values to unload %d\n", num_vals); 
      }

   if ( byte_or_word_data == 0 )
      increment = 2;
   else
      increment = 1;

   for ( val_num = 0; val_num < num_vals; val_num += increment )
      {

#ifdef DEBUG
printf("%4d) Load/unload %d\t\n", val_num, load_or_unload); fflush(stdout);
#endif

// Wait for 'stopped' from hardware to be asserted, which indicates that the hardware is ready to receive a byte.
      locked_up = 0;
      while ( ((*DataRegA) & (1 << IN_SM_HANDSHAKE)) == 0 )
         {
         locked_up++;
         if ( locked_up > 10000000 )
            { 
            printf("ERROR: LoadUnloadBRAM(): 'stopped' has not been asserted for the threshold number of cycles -- Locked UP?\n"); 
            fflush(stdout); 
            locked_up = 0;
            }
         }

// Put the data bytes into the register and assert 'continue' (OUT_CP_HANDSHAKE). iSpreadFactors are loaded one in each 16-bit word of PNL BRAM, so 
// byte_or_word_data is set to 1 for SpreadFactor loads/unloads
      if ( load_or_unload == 0 )
         {
         if ( byte_or_word_data == 0 )
            *CtrlRegA = ctrl_mask | (1 << OUT_CP_HANDSHAKE) | (0x000000FF & ByteData[val_num]) | (0x0000FF00 & (ByteData[val_num+1] << 8));
         else
            *CtrlRegA = ctrl_mask | (1 << OUT_CP_HANDSHAKE) | (0x0000FFFF & WordData[val_num]);
         }

// When 'stopped' is asserted, the data is ready on the output register from the PNL BRAM -- get it.
      else
         {
         if ( byte_or_word_data == 0 )
            {
            ByteData[val_num] = (0x000000FF & *DataRegA);
            ByteData[val_num+1] = ((0x0000FF00 & *DataRegA) >> 8);
            }
         else
            WordData[val_num] = (0x0000FFFF & *DataRegA);

         *CtrlRegA = ctrl_mask | (1 << OUT_CP_HANDSHAKE); 
         }

// Wait for hardware to de-assert 'stopped' (it got the byte).
      while ( ((*DataRegA) & (1 << IN_SM_HANDSHAKE)) != 0 );

// De-assert 'continue'. ALSO, assert 'done' (OUT_CP_LM_ULM_DONE) SIMULTANEOUSLY to tell hardware this is the last word.
      if ( val_num == num_vals - increment )
         *CtrlRegA = ctrl_mask | (1 << OUT_CP_LM_ULM_DONE);
      else
         *CtrlRegA = ctrl_mask;
      }

// Handle case where 'num_vals' is 0.
   if ( num_vals == 0 )
      *CtrlRegA = ctrl_mask | (1 << OUT_CP_LM_ULM_DONE);

// De-assert 'OUT_CP_LM_ULM_DONE'
   *CtrlRegA = ctrl_mask;

   fflush(stdout);

   return;
   }


// ========================================================================================================
// ========================================================================================================
// Run the SRF engine, all processes including PNDiffs, GPEVCal, Load/AddSpreadFactors. 

//#define DEBUG2 1

void RunSRFEngine(int max_string_len, int num_SF_words, volatile unsigned int *CtrlRegA, 
   volatile unsigned int *DataRegA, unsigned int ctrl_mask, signed char *iSpreadFactors, 
   int iSpreadFactorScaler, int current_function, int load_SF, int dump_updated_SF, int debug_flag)
   {
   int load_or_unload, byte_or_word_data;

   struct timeval t0, t1;
   long elapsed; 

   signed short *sSpreadFactors;
   int SF_num;

   float fSF;

// Sanity check. WARNING: THIS VARIABLE MUST BE SET TO 2 or 1.
   if ( iSpreadFactorScaler != 1 && iSpreadFactorScaler != 2 )
      { printf("ERROR: RunSRFEngine(): iSpreadFactorScaler MUST BE set to 1 or 2!\n"); exit(EXIT_FAILURE); }

   if ( (sSpreadFactors = (signed short *)calloc(num_SF_words, sizeof(signed short))) == NULL )
      { printf("ERROR: RunSRFEngine(): Failed to allocate storage for sSpreadFactors!\n"); exit(EXIT_FAILURE); }

#ifdef DEBUG2
int limit = 20;
#endif

// ****************************************
// ***** SRF engine starts once last param is loaded
   if ( debug_flag == 1 )
      printf("HE.1) Running PNDiff and GPEVCal\n\n");

// ****************************************
// ***** Load SpreadFactors. NOTE: THIS MUST BE DONE AFTER GPEVCal since the SpreadFactors are loaded in the same portion of memory.
   if ( debug_flag == 1 )
      {
      printf("HE.2) Loading SpreadFactors\n");
      gettimeofday(&t0, 0);
      }

// Load up the server's PopSF when ((DA or LL_Enroll) and PCR) or any mode when Verifier Authentication, Session Key Gen or KEK Regeneration. 
// 'num_SF_words' MUST be an even number. iSpreadFactors are loaded into a 16-bit word of PNL BRAM. Use the 'word' mode transfer for 
// LoadUnloadBRAM. Do NOT load anything if ((DA or LL_Enroll) and PCB) or for either of the TRNG modes (which currently do NOT call RunSRFEngine 
// so not needed really).
   if ( load_SF == 1)
      {
      load_or_unload = 0;
      byte_or_word_data = 1;

// With the conversion of SF to (signed char), I need to convert them here from (signed char) to (signed short) with the proper number of binary 
// precision (we are using 4 binary digits of precision in the hardware). When the TrimCodeConstant is <= 32, the server preserves 1 binary decimal
// place in the (signed char) SF, otherwise NONE are preserved. So iSpreadFactorScaler is set to 2 when TrimCodeConstant <= 32 and 1 otherwise.
// Multiply the iSpreadFactors by 8  when iSpreadFactorScaler is 2, which adds three low order binary 0s to the sSpreadFactors. 
// Multiply the iSpreadFactors by 16 when iSpreadFactorScaler is 1, which adds four  low order binary 0s to the sSpreadFactors.
//    i.e., 4 - 2 + 1 = 3, shift by 3 or multiply by 8, or 4 - 1 + 1 = 4, which is multiply by 16.
// NOTE: The verifier has already trimmed off the lower order precision bits and rounded appropriately.
      for ( SF_num = 0; SF_num < num_SF_words; SF_num++ )
         sSpreadFactors[SF_num] = (signed short)iSpreadFactors[SF_num] << (4 - iSpreadFactorScaler + 1);

      LoadUnloadBRAM(max_string_len, num_SF_words, CtrlRegA, DataRegA, ctrl_mask, NULL, sSpreadFactors, load_or_unload, byte_or_word_data, debug_flag);
      if ( debug_flag == 1 )
         { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tElapsed %ld us\n\n", (long)elapsed); }

#ifdef DEBUG2
int i;
for ( i = 0; i < limit; i++ )
   printf("%d)\tServer iSF %3d\tSHIFT RIGHT %d: fSF %9.4f\n", i, iSpreadFactors[i], (4 - iSpreadFactorScaler + 1), (float)sSpreadFactors[i]/16.0); 
fflush(stdout);
#endif

      }

#ifdef DEBUG
PrintHeaderAndHexVals("RunSRFEngine(): Pop. SpreadFactors (INPUT):\n", num_SF_words*SF_WORDS_TO_BYTES_MULT, (unsigned char *)iSpreadFactors, 32);
#endif

// Get computed PCR/PBD SpreadFactors from hardware engine if requested, overwriting the PopSF sent by the server earlier in the case of PCR (always done for
// DA or LL_Enroll mode). 
//   if ( current_function == FUNC_DA || current_function == FUNC_LL_ENROLL )
   if ( dump_updated_SF == 1 )
      {

#ifdef DEBUG2
printf("\nRunSRFEngine(): Getting updated SF\n"); fflush(stdout);
#endif

      load_or_unload = 1;
      byte_or_word_data = 1;
      LoadUnloadBRAM(max_string_len, num_SF_words, CtrlRegA, DataRegA, ctrl_mask, NULL, sSpreadFactors, load_or_unload, byte_or_word_data, debug_flag);

// With the conversion of SF to (signed char), I need to convert them here from (signed short) to (signed char) with the proper number of binary 
// precision (we are using 4 binary digits of precision in the hardware). When the TrimCodeConstant is <= 32, we can preserve 1 binary decimal
// place in the (signed char) SF, otherwise NONE are preserved. So iSpreadFactorScaler is set to 2 when TrimCodeConstant <= 32 and 1 otherwise.
      for ( SF_num = 0; SF_num < num_SF_words; SF_num++ )
         {

// First convert the (signed short) SF computed by the hardware to float, and then do the same conversion as we do in verifer_regen_funcs. 
// Round off appropriately. With iSpreadFactorScaler at 2, and if I have 35.6875, then convert to 35.5000. But if I have 16.9375, convert to 17.000 
// (anything larger than 16.75 should be 17.0, Anything larger than 16.25 should be 16.5, etc). Similarly, with iSpreadFactorScaler at 1, 
// than anything larger than 16.5 should be 17, etc. NOTE: Use 0.5 here for all cases, i.e., when iSpreadFactorScaler is 2, we need to add 0.5 and 
// NOT 0.25!
         fSF = (float)sSpreadFactors[SF_num]/16.0; 

         if ( sSpreadFactors[SF_num] >= 0 )
            iSpreadFactors[SF_num] = (signed char)(fSF * (float)iSpreadFactorScaler + 0.5);
         else 
            iSpreadFactors[SF_num] = (signed char)(fSF * (float)iSpreadFactorScaler - 0.5);
//         iSpreadFactors[SF_num] = (signed char)(sSpreadFactors[SF_num] >> (4 - iSpreadFactorScaler + 1));
         }

#ifdef DEBUG
PrintHeaderAndHexVals("RunSRFEngine(): PCR (OUTPUT):\n", num_SF_words*SF_WORDS_TO_BYTES_MULT, (unsigned char *)iSpreadFactors, 32);
#endif
      }

#ifdef DEBUG2
int i;
for ( i = 0; i < limit; i++ )
   {
   fSF = (float)sSpreadFactors[i]/16.0; 
   printf("Device fSF %9.4f\tiSF %4d\n", fSF, iSpreadFactors[i]);
   }
fflush(stdout);
#endif


// ****************************************
// ***** Continue with PNDc
   if ( debug_flag == 1 )
      printf("HE.3) Running PNDc\n\n");

// ****************************************
// Check error flags. Should be done after full computation is completed but no way of knowing that at this point. Should be checked at the
// end of a function. 'PNDIFF' errors can result in PNs or PNDiffs exceeding max. GPEVCal includes errors related to failing to find the bounds
// of the distribution + parameter errors (range of 0)
   usleep(1000);
   if ( ((*DataRegA) & (1 << IN_PNDIFF_OVERFLOW_ERR)) != 0 )
      { printf("ERROR: RunSRFEngine(): PNDiff Overflow error in hardware!\n"); exit(EXIT_FAILURE); }
   if ( ((*DataRegA) & (1 << IN_GPEVCAL_ERR)) != 0 )
      { printf("ERROR: RunSRFEngine(): GPEVCal Overflow error in hardware!\n"); exit(EXIT_FAILURE); }
   fflush(stdout);

   if ( sSpreadFactors != NULL )
      free(sSpreadFactors); 

//exit(EXIT_SUCCESS);

   return;
   }


// ========================================================================================================
// ========================================================================================================
// Convenience function that get SpreadFactors from server, selects parameters (LFSR_seed_low based on target_attempts),
// transfers the parameters to the Help engine and then loads the SpreadFactors and checks for hardware errors.

void GetSpreadFactorsSelectSetParamsRunSRF(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int target_attempts, 
   int force_threshold_zero, int current_function, int verifier_socket_desc)
   {

// Get Pop SpreadFactors from Server. No SpreadFactors needed when function is DA or LL_Enroll under PBD mode.
   if ( !((current_function == FUNC_DA || current_function == FUNC_LL_ENROLL) && SHP_ptr->param_PCR_or_PBD_or_PO == SF_MODE_PBD) )
      GetSpreadFactors(max_string_len, SHP_ptr->num_SF_words, SHP_ptr->num_SF_bytes, verifier_socket_desc, 
         SHP_ptr->iSpreadFactors, SHP_ptr->iSpreadFactorScaler, current_function, SHP_ptr->DEBUG_FLAG);

// Select parameters based on the XOR_nonce and then transfer them into the hardware.
   SelectSetParams(max_string_len, SHP_ptr->num_required_PNDiffs, SHP_ptr->CtrlRegA, SHP_ptr->DataRegA, SHP_ptr->ctrl_mask, 
      SHP_ptr->num_required_nonce_bytes, SHP_ptr->nonce_base_address, SHP_ptr->XOR_nonce, target_attempts, force_threshold_zero, 
      SHP_ptr->fix_params, SHP_ptr->param_RangeConstant, SHP_ptr->param_SpreadConstant, SHP_ptr->param_Threshold, 
      SHP_ptr->param_TrimCodeConstant, SHP_ptr->MyScalingConstant, SHP_ptr->XMR_val, SHP_ptr->num_KEK_authen_nonce_bits_remaining, 
      SHP_ptr->load_SF, SHP_ptr->compute_PCR_PBD, SHP_ptr->modify_PO, SHP_ptr->dump_updated_SF, SHP_ptr->param_PCR_or_PBD_or_PO, 
      current_function, &(SHP_ptr->param_LFSR_seed_low), &(SHP_ptr->param_LFSR_seed_high), SHP_ptr->do_scaling, SHP_ptr->DEBUG_FLAG);

// Run the SRF 'full comp' component, PNDiff, GPEVCal, LoadSpreadFactors (and retrieve SpreadFactors if Device Authentication).
   RunSRFEngine(max_string_len, SHP_ptr->num_SF_words, SHP_ptr->CtrlRegA, SHP_ptr->DataRegA, SHP_ptr->ctrl_mask, 
      SHP_ptr->iSpreadFactors, SHP_ptr->iSpreadFactorScaler, current_function, SHP_ptr->load_SF, SHP_ptr->dump_updated_SF, 
      SHP_ptr->DEBUG_FLAG);

   return;
   }


// ========================================================================================================
// ========================================================================================================
// Function that transfers the authentication nonce into the SRF hardware for encoding with XMR_SHD within 
// device authentication and for comparing with regenerated nonce within verifier authentication.

void TransferAuthenNonce(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, unsigned char *nonce)
   {
   int load_or_unload, byte_or_word_data; 

#ifdef DEBUG
printf("TransferAuthenNonce(): CALLED\n"); fflush(stdout);
#endif

   load_or_unload = 0;
   byte_or_word_data = 0;
   LoadUnloadBRAM(max_string_len, SHP_ptr->num_KEK_authen_nonce_bits/8, SHP_ptr->CtrlRegA, SHP_ptr->DataRegA, SHP_ptr->ctrl_mask, 
      nonce, NULL, load_or_unload, byte_or_word_data, SHP_ptr->DEBUG_FLAG);

#ifdef DEBUG
printf("TransferAuthenNonce(): DONE\n"); fflush(stdout);
#endif

   return; 
   }


// ========================================================================================================
// ========================================================================================================
// Fetch SHD or SBS from the hardware and optionally transfer it to verifier. 

int FetchTransSHD_SBS(int max_string_len, int target_bytes, volatile unsigned int *CtrlRegA, 
   volatile unsigned int *DataRegA, unsigned int ctrl_mask, int verifier_socket_desc, unsigned char *SHD_SBS, 
   int also_do_transfer, int SHD_or_SBS, int bit_cnt_valid, int DUMP_BITSTRINGS, int debug_flag)
   {
   int SHD_SBS_num_bytes, SHD_SBS_num_bits;
   int load_or_unload, byte_or_word_data;

   struct timeval t0, t1;
   long elapsed; 

   SHD_SBS_num_bits = 0;

// ****************************************
// ***** Wait for Helper data to become available. There are 2048 PNDc values generated with the vectors, each requires 1 bit of 
//       helper data. So we SHOULD always collect 256 bytes of helper data here.
   if ( debug_flag == 1 )
      {
      if ( SHD_or_SBS == 0 ) 
         printf("FT.1) Fetching device SHD\n"); 
      else
         printf("FT.1) Fetching device SBS\n"); 
      gettimeofday(&t0, 0);
      }

// 'target_bytes' MUST be an even number. With byte_or_word_data set to 0, we process unsigned char data.
// 16-bit words.
   load_or_unload = 1;
   byte_or_word_data = 0;
   LoadUnloadBRAM(max_string_len, target_bytes, CtrlRegA, DataRegA, ctrl_mask, SHD_SBS, NULL, load_or_unload, byte_or_word_data, debug_flag);
   SHD_SBS_num_bytes = target_bytes;
   if ( debug_flag == 1 )
      { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tElapsed %ld us\n\n", (long)elapsed); }

// Print the bitstring if requested.
   if ( DUMP_BITSTRINGS == 1 )
      {
      char header_str[max_string_len];
      if ( SHD_or_SBS == 0 )
         sprintf(header_str, "\n\tDevice SHD\n");
      else
         sprintf(header_str, "\n\tDevice SBS\n");
      PrintHeaderAndHexVals(header_str, SHD_SBS_num_bytes, SHD_SBS, 32);
      }

// SHD always has 2048 for number of bits of helper data
   if ( SHD_or_SBS == 0 )
      SHD_SBS_num_bits = 2048;

// Get the ACTUAL SBS size in bits from the hardware and report it. When running KEK mode and fetching the SBS after SHD is run (NOT XMR),
// this count is not valid because as soon as we finish getting the SBS above, KEK FSB/SKE is started immediately in the hardware.
   if ( SHD_or_SBS == 1 && bit_cnt_valid == 1 )
      {
      SHD_SBS_num_bits = (*DataRegA) & 0x0000FFFF; 
      if ( SHD_SBS_num_bits % 8 == 0 )
         SHD_SBS_num_bytes = SHD_SBS_num_bits/8; 
      else
         SHD_SBS_num_bytes = SHD_SBS_num_bits/8 + 1;
      if ( DUMP_BITSTRINGS == 1 )
         printf("\tHelp Engine reports strong bits read %d\n\n", SHD_SBS_num_bits);
      }

// ****************************************
//****** Transfer device SHD or SBS to verifier
   if ( also_do_transfer == 1 )
      {
      if ( debug_flag == 1 )
         {
         printf("FT.2) Transferring Device SHD or SBS to server\n");
         gettimeofday(&t0, 0);    
         }
      if ( SockSendB(SHD_SBS, SHD_SBS_num_bytes, verifier_socket_desc) < 0 )
         { printf("ERROR: FetchTransSHD_SBS(): Device helper data send failed\n"); exit(EXIT_FAILURE); }
      if ( debug_flag == 1 )
         { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tElapsed %ld us\n\n", (long)elapsed); }
      }
   fflush(stdout);

   return SHD_SBS_num_bits;
   }


// ========================================================================================================
// ========================================================================================================
// Convenience function that fetches SHD or SBS or both from the hardware.

int FetchSendSHDAndSBS(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int SBS_bit_cnt_valid, 
   int also_do_transfer, int get_SHD_SBS_both, int *num_SBS_bits_ptr, int verifier_socket_desc)
   {
   int SHD_or_SBS, bit_cnt_valid; 
   int num_SHD_bits = -1;

   *num_SBS_bits_ptr = -1;

// Fetch from the hardware the device SHD (always num_required_PNDiffs/8 bytes). 
   if ( get_SHD_SBS_both == 0 || get_SHD_SBS_both == 2 )
      {
      SHD_or_SBS = 0;
      bit_cnt_valid = 1;
      num_SHD_bits = FetchTransSHD_SBS(max_string_len, SHP_ptr->num_required_PNDiffs/8, SHP_ptr->CtrlRegA, SHP_ptr->DataRegA, SHP_ptr->ctrl_mask, 
         verifier_socket_desc, SHP_ptr->device_SHD, also_do_transfer, SHD_or_SBS, bit_cnt_valid, SHP_ptr->DUMP_BITSTRINGS, SHP_ptr->DEBUG_FLAG);
      }

   if ( get_SHD_SBS_both == 1 || get_SHD_SBS_both == 2 )
      {

// Fetch from the hardware the device SBS (variable in size -- not in increments of bytes). 
      SHD_or_SBS = 1;
      *num_SBS_bits_ptr = FetchTransSHD_SBS(max_string_len, SHP_ptr->num_required_PNDiffs/8, SHP_ptr->CtrlRegA, SHP_ptr->DataRegA, SHP_ptr->ctrl_mask, 
         verifier_socket_desc, SHP_ptr->device_SBS, also_do_transfer, SHD_or_SBS, SBS_bit_cnt_valid, SHP_ptr->DUMP_BITSTRINGS, SHP_ptr->DEBUG_FLAG);
      }

// HERE FOR DEBUG
#ifdef DEBUG
PrintHeaderAndHexVals("\tSHD:\n", SHP_ptr->num_required_PNDiffs/8, SHP_ptr->device_SHD, 32);
PrintHeaderAndHexVals("\tSBS:\n", SHP_ptr->num_required_PNDiffs/8, SHP_ptr->device_SBS, 32);
#endif

#ifdef DEBUG
printf("FetchSendSHDAndSBS(): SHD bits %d\tSBS bits %d\n", num_SHD_bits, *num_SBS_bits_ptr); fflush(stdout);
#endif

   return num_SHD_bits;
   }


// ========================================================================================================
// ========================================================================================================
// Common operations carried out which are independent of the security function. 
//    1) Check READY status of MstCtrl hardware state machine.
//    2) Start MstCtrl state machine. 
//    3) Get vectors and path select masks from verifier
//    4) Run CollectPNs which measures the entropy source and stores values in BRAM.
//    5) Exchange nonces with verifier to create XOR_nonce.
//    6) If requested, get SpreadFactors from server (which depend on the XOR_nonce).
//    7) If requested, select parameters (based on XOR_nonce) and transfer to hardware.
//    8) If requested, run the SRF algorithm, ComputePNDiffs, TVComp, AddSpreadFactors

void CommonCore(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int verifier_socket_desc, int target_attempts, 
   int force_threshold_zero, int do_all_calls, int current_function)
   {

// Sanity check. PUF engine MUST be 'ready'
   if ( (*(SHP_ptr->DataRegA) & (1 << IN_SM_READY)) == 0 )
      { printf("ERROR: CommonCore(): PUF Engine is NOT ready!\n"); exit(EXIT_FAILURE); }

// Start the PUF engine. NOTE: This is not confirmed via a handshake, which it should be. Adding a usleep to make sure a 'slow' version of
// the hardware state machine sees the start signal.
   *(SHP_ptr->CtrlRegA) = SHP_ptr->ctrl_mask | (1 << OUT_CP_PUF_START); 
   usleep(1000);
   *(SHP_ptr->CtrlRegA) = SHP_ptr->ctrl_mask;

// Get vectors and masks from verifier (or a seed to read them from the DB_Challenges DB when 'use_database_chlngs' is 1) -- allocate memory 
// for them dynamically. Assume previous allocation (if any) have been freed already. The flag 'gen_or_use_challenge_seed' must be 0 here
// since we will 'get' the seed from the verifier if 'use_database_chlngs' is 1. This flag set to 1 only when we run LLK regeneration
// which has no interaction with the server.
   int send_GO_request = 1;
   int gen_or_use_challenge_seed = 0;
   SHP_ptr->num_vecs = GoGetVectors(max_string_len, SHP_ptr->num_POs, SHP_ptr->num_PIs, verifier_socket_desc, &(SHP_ptr->num_rise_vecs),
      &(SHP_ptr->has_masks), &(SHP_ptr->first_vecs_b), &(SHP_ptr->second_vecs_b), &(SHP_ptr->masks_b), send_GO_request, 
      SHP_ptr->use_database_chlngs, SHP_ptr->DB_Challenges, SHP_ptr->DB_design_index, SHP_ptr->DB_ChallengeSetName, gen_or_use_challenge_seed,
      &(SHP_ptr->DB_ChallengeGen_seed), SHP_ptr->GenChallenge_mutex_ptr, SHP_ptr->DEBUG_FLAG);

#ifdef DEBUG
SaveASCIIVectors(max_string_len, SHP_ptr->num_vecs, SHP_ptr->first_vecs_b, SHP_ptr->second_vecs_b, SHP_ptr->num_PIs, 
   SHP_ptr->has_masks, SHP_ptr->num_POs, SHP_ptr->masks_b);
#endif

// Set this global variable to prevent Ctrl-C from exiting while the SRF PUF is running. Record the number of hardware generated nonce bytes.
   SAFE_TO_QUIT = 0;
   SHP_ptr->num_device_n1_nonces = CollectPNs(max_string_len, SHP_ptr->num_POs, SHP_ptr->num_PIs, SHP_ptr->vec_chunk_size, 
      SHP_ptr->max_generated_nonce_bytes, SHP_ptr->CtrlRegA, SHP_ptr->DataRegA, SHP_ptr->ctrl_mask, SHP_ptr->num_vecs, SHP_ptr->num_rise_vecs, 
      SHP_ptr->has_masks, SHP_ptr->first_vecs_b, SHP_ptr->second_vecs_b, SHP_ptr->masks_b, SHP_ptr->device_n1, SHP_ptr->DUMP_BITSTRINGS, 
      SHP_ptr->DEBUG_FLAG);
   SAFE_TO_QUIT = 1;

#ifdef DEBUG
printf("Finished CollectPNs\n"); fflush(stdout);
#endif

// Get verifier nonce, XOR with device nonce, transmit XOR to verifier.
   NonceExchange(max_string_len, verifier_socket_desc, SHP_ptr->num_required_nonce_bytes, SHP_ptr->device_n1, SHP_ptr->num_device_n1_nonces, 
      SHP_ptr->verifier_n2, SHP_ptr->XOR_nonce, SHP_ptr->DUMP_BITSTRINGS, SHP_ptr->DEBUG_FLAG);

// Currently, I am not calling CommonCore with 'do_all_calls' set to 1 anywhere.
   if ( do_all_calls == 1 )
      {

// Get SpreadFactors from server. When current function is ((DA or LL_Enroll) and PBD), we don't need SpreadFactors. 
      if ( !((current_function == FUNC_DA || current_function == FUNC_LL_ENROLL) && SHP_ptr->param_PCR_or_PBD_or_PO == SF_MODE_PBD) )
         GetSpreadFactors(max_string_len, SHP_ptr->num_SF_words, SHP_ptr->num_SF_bytes, verifier_socket_desc, SHP_ptr->iSpreadFactors, 
            SHP_ptr->iSpreadFactorScaler, current_function, SHP_ptr->DEBUG_FLAG);

#ifdef DEBUG
PrintHeaderAndHexVals("\tServer's Population SpreadFactors:\n", SHP_ptr->num_SF_bytes, (unsigned char *)SHP_ptr->iSpreadFactors, 32);
#endif

// Select parameters based on the XOR_nonce and then transfer them into the hardware.
      SelectSetParams(max_string_len, SHP_ptr->num_required_PNDiffs, SHP_ptr->CtrlRegA, SHP_ptr->DataRegA, SHP_ptr->ctrl_mask, 
         SHP_ptr->num_required_nonce_bytes, SHP_ptr->nonce_base_address, SHP_ptr->XOR_nonce, target_attempts, force_threshold_zero, 
         SHP_ptr->fix_params, SHP_ptr->param_RangeConstant, SHP_ptr->param_SpreadConstant, SHP_ptr->param_Threshold, 
         SHP_ptr->param_TrimCodeConstant, SHP_ptr->MyScalingConstant, SHP_ptr->XMR_val, SHP_ptr->num_KEK_authen_nonce_bits_remaining, 
         SHP_ptr->load_SF, SHP_ptr->compute_PCR_PBD, SHP_ptr->modify_PO, SHP_ptr->dump_updated_SF, SHP_ptr->param_PCR_or_PBD_or_PO, 
         current_function, &(SHP_ptr->param_LFSR_seed_low), &(SHP_ptr->param_LFSR_seed_high), SHP_ptr->do_scaling, SHP_ptr->DEBUG_FLAG);

// Run the SRF 'full comp' component, PNDiff, GPEVCal, LoadSpreadFactors
      RunSRFEngine(max_string_len, SHP_ptr->num_SF_words, SHP_ptr->CtrlRegA, SHP_ptr->DataRegA, SHP_ptr->ctrl_mask, SHP_ptr->iSpreadFactors, 
         SHP_ptr->iSpreadFactorScaler, current_function, SHP_ptr->load_SF, SHP_ptr->dump_updated_SF, SHP_ptr->DEBUG_FLAG);
      }

#ifdef DEBUG
printf("Finished CommonCore\n"); fflush(stdout);
#endif

   return;
   }


// ========================================================================================================
// ========================================================================================================
// A convenience function to store KEK enrollment information in dedicated fields so it is preserved across
// multiple regenerations. Note that we can do other security functions in between, which will overwrite the
// the primary fields. Normally, this information stored in an NVM on the chip for regeneration.

void CopyToKEKFields(SRFHardwareParamsStruct *SHP_ptr)
   {
   int vec_num, byte_num, i;

// 10_31_2021: Free up the KEK vectors and masks 
   FreeVectorsAndMasks(&(SHP_ptr->KEK_num_vecs), &(SHP_ptr->KEK_num_rise_vecs), &(SHP_ptr->KEK_first_vecs_b), 
      &(SHP_ptr->KEK_second_vecs_b), &(SHP_ptr->KEK_masks_b));

// Copy the vector number fields
   SHP_ptr->KEK_num_vecs = SHP_ptr->num_vecs; 
   SHP_ptr->KEK_num_rise_vecs = SHP_ptr->num_rise_vecs; 
   SHP_ptr->KEK_has_masks = SHP_ptr->has_masks;

// Allocate the base arrays. NOTE: Although multiple iterations may be needed to meet the key length, the SAME set of vectors 
// are ALWAYS used.
   if ( (SHP_ptr->KEK_first_vecs_b = (unsigned char **)malloc(sizeof(unsigned char *) * SHP_ptr->num_vecs)) == NULL )
      { printf("ERROR: CopyToKEKFields(): Failed to allocate storage for first_vecs_b array!\n"); exit(EXIT_FAILURE); }
   if ( (SHP_ptr->KEK_second_vecs_b = (unsigned char **)malloc(sizeof(unsigned char *) * SHP_ptr->num_vecs)) == NULL )
      { printf("ERROR: CopyToKEKFields(): Failed to allocate storage for second_vecs_b array!\n"); exit(EXIT_FAILURE); }
   if ( SHP_ptr->has_masks == 1 )
      if ( (SHP_ptr->KEK_masks_b = (unsigned char **)malloc(sizeof(unsigned char *) * SHP_ptr->num_vecs)) == NULL )
         { printf("ERROR: CopyToKEKFields(): Failed to allocate storage for masks_b array!\n"); exit(EXIT_FAILURE); }

   for ( vec_num = 0; vec_num < SHP_ptr->num_vecs; vec_num++ )
      {
      if ( (SHP_ptr->KEK_first_vecs_b[vec_num] = (unsigned char *)malloc(sizeof(unsigned char)*SHP_ptr->num_PIs/8)) == NULL )
         { printf("ERROR: CopyToKEKFields(): Failed to allocate storage for first_vecs_b element!\n"); exit(EXIT_FAILURE); }
      for ( byte_num = 0; byte_num < SHP_ptr->num_PIs/8; byte_num++ )
         SHP_ptr->KEK_first_vecs_b[vec_num][byte_num] = SHP_ptr->first_vecs_b[vec_num][byte_num];

      if ( (SHP_ptr->KEK_second_vecs_b[vec_num] = (unsigned char *)malloc(sizeof(unsigned char)*SHP_ptr->num_PIs/8)) == NULL )
         { printf("ERROR: CopyToKEKFields(): Failed to allocate storage for second_vecs_b element!\n"); exit(EXIT_FAILURE); }
      for ( byte_num = 0; byte_num < SHP_ptr->num_PIs/8; byte_num++ )
         SHP_ptr->KEK_second_vecs_b[vec_num][byte_num] = SHP_ptr->second_vecs_b[vec_num][byte_num];

      if ( SHP_ptr->has_masks == 1 )
         {
         if ( (SHP_ptr->KEK_masks_b[vec_num] = (unsigned char *)malloc(sizeof(unsigned char)*SHP_ptr->num_POs/8)) == NULL )
            { printf("ERROR: CopyToKEKFields(): Failed to allocate storage for masks_b element!\n"); exit(EXIT_FAILURE); }
         for ( byte_num = 0; byte_num < SHP_ptr->num_POs/8; byte_num++ )
            SHP_ptr->KEK_masks_b[vec_num][byte_num] = SHP_ptr->masks_b[vec_num][byte_num];
         }
      }

// Copy the XOR_nonce. If multiple iterations are needed to achieve the KEK key length, the same XOR_nonce is used and only the LFSR seeds are 
// incremented. NOTE: SpreadFactors are NOT saved here because they are generated dynamically based on the size of the key and the number of required 
// iterations to meet that key length.
   for ( i = 0; i < SHP_ptr->num_required_nonce_bytes; i++ )
      SHP_ptr->KEK_XOR_nonce[i] = SHP_ptr->XOR_nonce[i];

   return;
   }


// ========================================================================================================
// ========================================================================================================
// Last component of Device Authentication. Called by Device Authentication and Session Key Gen when
// Cobra is enabled.

int DA_Report(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int verifier_socket_desc)
   {
   char request_str[max_string_len], success_fail_str[max_string_len];
   struct timeval t0, t1;
   long elapsed; 

// ------------------------------------------------------------------
// ***** The verifier will authenticate the device and then receive this string 
   if ( SHP_ptr->DEBUG_FLAG == 1 )
      {
      printf("\tSending 'ACK'\n");
      gettimeofday(&t0, 0);
      }
   if ( SockSendB((unsigned char *)"ACK", strlen("ACK") + 1, verifier_socket_desc) < 0 )
      { printf("ERROR: DA_Report(): Send 'ACK' request failed\n"); exit(EXIT_FAILURE); }
   if ( SHP_ptr->DEBUG_FLAG == 1 )
      { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tElapsed %ld us\n\n", (long)elapsed); }
   fflush(stdout);

// Server send 'SUCCESS' or 'FAILURE' -- both 7 characters long. Add 1 for the newline character. 11_1_2021: Added the chip_num
// field to this packet so cannot check the size any longer.
   if ( SockGetB((unsigned char *)request_str, max_string_len, verifier_socket_desc) < 0 )
      { printf("DA_Report(): Receive request failed!\n"); exit(EXIT_FAILURE); }

// 11_1_2021: Added the fetch to get the verifier's chip_num, which is a unique number from its provisioning database that Alice 
// can use as her ID
   if ( sscanf(request_str, "%s %d", success_fail_str, &(SHP_ptr->chip_num)) != 2 )
      { printf("DA_Report(): Expected 'SUCCESS' or 'FAILURE' AND chip_num!\n"); exit(EXIT_FAILURE); }

   if ( strstr(request_str, "FAILURE") != NULL )
      { 
      printf("\tServer FAILED to authenticate device\tChip Num received %d!\n\n", SHP_ptr->chip_num); fflush(stdout); 
      return 0;
      }
   else
      { 
      printf("\tServer SUCCEEDED to authenticate device\tChip Num received %d!\n\n", SHP_ptr->chip_num); fflush(stdout); 
      return 1;
      }
   }


// ========================================================================================================
// ========================================================================================================
// Basic process steps for device authentication:
//    1) Set KEK mode in hardware
//    2) Allocate storage for local copy of KEK_authentication_nonce
//    3) Loop attempting to authenticate upto MAX_DA_RETRIES times.
//       a) Get verifier KEK_authentication_nonce
//       b) Make a local copy for manipulation
//       c) Do full computation
//          i) Check READY status of MstCtrl hardware state machine.
//         ii) Start MstCtrl state machine. 
//        iii) Get vectors and path select masks from verifier
//         iv) Run CollectPNs which measures the entropy source and stores values in BRAM.
//          v) Exchange nonces with verifier to create XOR_nonce.
//       d) Loop over LFSR seed increments until KEK_authentication_nonce is fully encoded in KEK_authen_XMR_SHD
//          i) Get population SpreadFactors from server (which depend on the XOR_nonce and LFSR seed).
//         ii) Select parameters (based on XOR_nonce) and transfer to hardware. 
//        iii) Transfer nonce (or generate it) to hardware.
//         iv) Run the SRF algorithm on portion of nonce, ComputePNDiffs, TVComp, AddSpreadFactors, KEK SKI Enroll
//          v) Fetch PCR Spreadfactors, SHD and SBS from hardware 
//         vi) Call EliminatePackedBitsFromBS to eliminate bits from KEK_authentication_nonce that were encoded
//        vii) Transmit PCR SpreadFactors to verifier (if COBRA is disabled)
//        vii) Add KEK_authen_XMR_SHD_chunk to KEK_authen_XMR_SHD
//       viii) Check if number of bits remaining in KEK_authentication_nonce is non-zero, if so restart the SRF engine, go to d)
//       e) Send KEK_authen_XMR_SHD to server
//       f) Wait for Pass/Fail decision

int KEK_DeviceAuthentication_SKE(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int verifier_socket_desc)
   {
   int target_attempts, force_threshold_zero, do_all_calls;
   int former_ctrl_mask, current_function; 
   int also_do_transfer;

   int bits_remaining;
   int num_SBS_bits;

   unsigned char *KEK_authentication_nonce;

   unsigned char *KEK_authen_XMR_SHD;
   int current_XMR_SHD_num_bytes; 

   int SBS_bit_cnt_valid, get_SHD_SBS_both, do_server_SpreadFactors_next;

// 10_22_2022: From ZED experiments, I found that PopOnly, No flip with personalized range factors works best. Forcing that here.
   int prev_PCR_PBD_PO_mode = SHP_ptr->param_PCR_or_PBD_or_PO;
   SHP_ptr->param_PCR_or_PBD_or_PO = SF_MODE_POPONLY;

// 11_12_2022: RE-ENABLING IT. Tried WITHOUT scaling and got same results -- higher reliability but same margin between worst case AE 
// and NE (about 17% in BOTH cases). Benefit with scaling ENABLED is anonymous SHD.
// !!!!!!!!!!!!!! NOTE: YOU MUST DO THE SAME THING IN verifier_regen_funcs.c to ENABLE/DISABLE THIS. !!!!!!!!!!!!!!
   int prev_do_scaling = SHP_ptr->do_scaling;
   SHP_ptr->do_scaling = 0;

   int i, j;

//   struct timeval t0, t1;
//   long elapsed; 

   printf("\n\t\t\t******************* DEVICE SKE MODE AUTHENTICATION BEGINS  *******************\n");

// Sanity check: COBRA MUST be 0 in this routine. We call KEK_SessionKeyGen when cobra is 1.
   if ( SHP_ptr->do_COBRA == 1 )
      { printf("ERROR: KEK_DeviceAuthentication_SKE(): Called with do_COBRA set to 1!\n"); exit(EXIT_FAILURE); }

// Save existing mask so we can restore on exit.
   former_ctrl_mask = SHP_ptr->ctrl_mask;

   current_function = FUNC_DA;

// Use the XMR and RangeConstant values for SKE (defined in common.h).
   SHP_ptr->XMR_val = DEVICE_SKE_AUTHEN_XMR_VAL;

//   SHP_ptr->param_RangeConstant = DEVICE_SKE_AUTHEN_RANGE_CONSTANT; 

// Load SF if PO or PCR mode, compute PCR/PBD SF if NOT PO mode, and modify the loaded PO if PO or PCR mode
// PCR
   if ( SHP_ptr->param_PCR_or_PBD_or_PO == SF_MODE_PCR )
      {
      SHP_ptr->load_SF = 1;
      SHP_ptr->compute_PCR_PBD = 1;
      SHP_ptr->modify_PO = 1;
      SHP_ptr->dump_updated_SF = 1;
      }
// PBD
   else if ( SHP_ptr->param_PCR_or_PBD_or_PO == SF_MODE_PBD )
      {
      SHP_ptr->load_SF = 0;
      SHP_ptr->compute_PCR_PBD = 1;
      SHP_ptr->modify_PO = 0;
      SHP_ptr->dump_updated_SF = 1;
      }

// PopOnly
// 10_22_2022: From ZED experiments, I found that PopOnly, No flip with personalized range factors works best. Forcing that here.
   else if ( SHP_ptr->param_PCR_or_PBD_or_PO == SF_MODE_POPONLY )
      {
      SHP_ptr->load_SF = 1;
      SHP_ptr->compute_PCR_PBD = 0;
//      SHP_ptr->modify_PO = 1;
      SHP_ptr->modify_PO = 0;
      SHP_ptr->dump_updated_SF = 1;
      }
   else
      { printf("ERROR: KEK_DeviceAuthentication_SKE(): Illegal mode %d\n", SHP_ptr->param_PCR_or_PBD_or_PO); exit(EXIT_FAILURE); }

// Set hardware function "000"
   SHP_ptr->ctrl_mask = ((SHP_ptr->ctrl_mask & ~(1 << OUT_CP_KEK)) & ~(1 << OUT_CP_MODE1)) & ~(1 << OUT_CP_MODE0);


// Allocate space for temporary copy of KEK_authentication_nonce (that will be destroyed). 
   if ( (SHP_ptr->num_KEK_authen_nonce_bits % 8) != 0 )
      { printf("ERROR: KEK_DeviceAuthentication_SKE(): SHP_ptr->num_KEK_authen_nonce_bits MUST be divisible by 8!\n"); exit(EXIT_FAILURE); }
   if ( (KEK_authentication_nonce = (unsigned char *)malloc(sizeof(unsigned char) * SHP_ptr->num_KEK_authen_nonce_bits/8)) == NULL )
      { printf("ERROR: KEK_DeviceAuthentication_SKE(): Failed to allocate storage for KEK_authentication_nonce!\n"); exit(EXIT_FAILURE); }

// 12_2_20220: Original version get the KEK_authentication_nonce in plain form from the server.
//   if ( do_two_way_encryption == 0 )
   if ( SockGetB(SHP_ptr->KEK_authentication_nonce, SHP_ptr->num_KEK_authen_nonce_bits/8, verifier_socket_desc) != SHP_ptr->num_KEK_authen_nonce_bits/8 )
      { printf("KEK_DeviceAuthentication_SKE(): KEK_authentication_nonce receive failed!\n"); exit(EXIT_FAILURE); }

// 12_2_222: Latest thoughts here after writing up the background section of SiRF_Authentication is to send an encrypted version of the 
// KEK_authentication_nonce to the device. Note this is ONLY possible if we drop anonymity since we do NOT know how to encrypt the nonce
// i.e., which device data set should be used. Note if we run COBRA first, we'll have the ID that we need for SKE. 
// The order of operations is:
//    1) Get the ID of the authenticating device
//    2) Encrypt the nonce, i.e., generate SF and HD, and send encrypted nonce, SF and HD to device
//    3) Device decrypts nonce
//    4) Device either a) re-encrypts nonce using same challenge and SF and generates new HD or b) gets a new challenge and SF from server.
//    5) Device sends encrypted nonce and HD to server
//    6) Server does NOT need to search (since ID was sent earlier by device) so it decryptes and compares to a threshold
//   else
// Not doing this now since I don't want to drop anonymity. Probably better just to do a PUF-based encryption paper as a follow-up to
// PUF-based authentication.

// Create local copies of authentication nonce information.
   bits_remaining = SHP_ptr->num_KEK_authen_nonce_bits; 

// This is the number loaded into the SRF engine in SelectSetParams.
   SHP_ptr->num_KEK_authen_nonce_bits_remaining = SHP_ptr->num_KEK_authen_nonce_bits;

// Need to make a copy of this locally because it is destroyed below.
   for ( i = 0; i < SHP_ptr->num_KEK_authen_nonce_bits/8; i++ )
      KEK_authentication_nonce[i] = SHP_ptr->KEK_authentication_nonce[i];

// Get only the challenge vectors, run CollectPNs to get timing data and nonces and do the nonce exchange with the verifier for 
// parameter selection.
   target_attempts = 0;
   force_threshold_zero = 0;
   do_all_calls = 0;
   CommonCore(max_string_len, SHP_ptr, verifier_socket_desc, target_attempts, force_threshold_zero, do_all_calls, current_function);

// Loop incrementing LFSR seed until we succeed in generating XMR_SHD that completely encodes the verifier's authentication nonce. 
   current_XMR_SHD_num_bytes = 0;
   KEK_authen_XMR_SHD = NULL;
   while ( bits_remaining > 0 )
      {

// Convenience function that calls GetSpreadFactors(), SelectSetParams() and RunSRFEngine(). Note that the PopOnly SF received from the
// server are converted to PCR by the device. Also note that NO SpreadFactors are needed from the server when PBD mode. 
      GetSpreadFactorsSelectSetParamsRunSRF(max_string_len, SHP_ptr, target_attempts, force_threshold_zero, current_function, verifier_socket_desc);

// Generate and transfer a chunk of the authentication nonce to the hardware. On subsequent iterations, we remove bits from the front
// of this nonce (that have been encoded in previous iterations) and re-load the shorter nonce bitstring into the hardware. The hardware
// always starts at the beginning of the nonce and encodes as many bits as possible, or whatever bits are remaining.
      TransferAuthenNonce(max_string_len, SHP_ptr, KEK_authentication_nonce);

#ifdef DEBUG
printf("\n\n\nTARGET ATTEMPTS: %d\n", target_attempts); fflush(stdout);
for ( i = 0; i < SHP_ptr->num_required_PNDiffs/8; i++ )
   SHP_ptr->KEK_authen_XMR_SHD_chunk[i] = 0;
#endif

// Get the SBG_SHD and SBG_SBS from the hardware. The num_SBS_bits are not valid here (YET).
      also_do_transfer = 0;
      SBS_bit_cnt_valid = 1;
      get_SHD_SBS_both = 2;
      FetchSendSHDAndSBS(max_string_len, SHP_ptr, SBS_bit_cnt_valid, also_do_transfer, get_SHD_SBS_both, &num_SBS_bits, verifier_socket_desc);

#ifdef DEBUG
PrintHeaderAndHexVals("Current authen_nonce\n", SHP_ptr->num_KEK_authen_nonce_bits/8, KEK_authentication_nonce, 16);
#endif

#ifdef DEBUG
PrintHeaderAndHexVals("SOFTWARE: XMR_SHD_chunk\n", SHP_ptr->num_required_PNDiffs/8, SHP_ptr->KEK_authen_XMR_SHD_chunk, 32);
#endif


// Hardware runs KEK SKE Enrollment, which uses authentication nonce, SBG_SHD and SGB_SBS as input and produces XMR_SHD and num_nonce_bits_encoded
// as output. Get the XMR_SHD, XMR_SBS and num_nonce_bits_encoded.
      also_do_transfer = 0;
      SBS_bit_cnt_valid = 1;
      get_SHD_SBS_both = 2;
      FetchSendSHDAndSBS(max_string_len, SHP_ptr, SBS_bit_cnt_valid, also_do_transfer, get_SHD_SBS_both, &num_SBS_bits, verifier_socket_desc);

// Now we need to eliminate 'num_SBS_bits' from KEK_authentication_nonce and move all the remaining bits to start at the first bit/byte. 
      bits_remaining = EliminatePackedBitsFromBS(bits_remaining, KEK_authentication_nonce, num_SBS_bits);
      SHP_ptr->num_KEK_authen_nonce_bits_remaining = bits_remaining;

#ifdef DEBUG
PrintHeaderAndHexVals("KEK_DeviceAuthentication_SKE(): HARDWARE: XMR_SHD_chunk\n", SHP_ptr->num_required_PNDiffs/8, SHP_ptr->device_SHD, 32);
#endif


#ifdef DEBUG
printf("\tTarget attempt %2d\tMode %d\tXMR %2d\tLFSR low %4d\tLFSR high %4d\tRC %3d\tSC %2d\tTH %d\tTCC %2d\tBits remaining %d\n\n", 
   target_attempts, SHP_ptr->param_PCR_or_PBD_or_PO, SHP_ptr->XMR_val, SHP_ptr->param_LFSR_seed_low, SHP_ptr->param_LFSR_seed_high,
   SHP_ptr->param_RangeConstant, SHP_ptr->param_SpreadConstant, SHP_ptr->param_Threshold, SHP_ptr->param_TrimCodeConstant, bits_remaining); fflush(stdout);
#endif

// Re-allocate KEK_authen_XMR_SHD array -- add 256 bytes.
      if ( (KEK_authen_XMR_SHD = (unsigned char *)realloc(KEK_authen_XMR_SHD, sizeof(unsigned char)*(current_XMR_SHD_num_bytes + 
         SHP_ptr->num_required_PNDiffs/8))) == NULL )
         { printf("ERROR: KEK_DeviceAuthentication_SKE(): Allocation for 'KEK_authen_XMR_SHD' failed!\n"); exit(EXIT_FAILURE); }

// Add the XMR_SHD to the larger array to be sent to the server.
      for ( i = 0, j = current_XMR_SHD_num_bytes; i < SHP_ptr->num_required_PNDiffs/8; i++, j++ )
         KEK_authen_XMR_SHD[j] = SHP_ptr->device_SHD[i];
      current_XMR_SHD_num_bytes += SHP_ptr->num_required_PNDiffs/8;

#ifdef DEBUG
int DV_num;
if ( target_attempts == 0 )
   for ( DV_num = 0; DV_num < 50; DV_num++ ) 
      printf("XMR_SHD bit [%d] is %d\n", DV_num, GetBitFromByte(KEK_authen_XMR_SHD[DV_num/8], DV_num % 8));
fflush(stdout);
#endif

// Check if bits remaining to be encoded become zero. If so, we are done. If not, get more population SpreadFactors from server.
      target_attempts++;
      if ( bits_remaining > 0 )
         {

// Sanity check -- something is wrong. Population SpreadFactors used and only one chip in database?
         if ( target_attempts == SHP_ptr->num_required_PNDiffs )
            { printf("ERROR: KEK_DeviceAuthentication_SKE(): Seed increment reached max value -- FAILED TO GET ENOUGH BITS!\n"); exit(EXIT_FAILURE); }

// Set PN reuse mode in hardware, start SRF engine and request additional SpreadFactors from server. 
// 2_20_2022: This was not conditional and needs to be b/c GetSpreadFactorsSelectSetParamsRunSRF() above uses this to determine if we
// need to go to server for SpreadFactors, which does NOT happend when function is DA or LL_Enroll under PBD mode.
// But then again, the verifier_regen_funcs.c GenChlngDeliverSpreadFactorsToDevice() may use this to count the number of target_attempts
// and uses this to determine when this routine is done sending spread factors for other modes.
//         if ( !((current_function == FUNC_DA || current_function == FUNC_LL_ENROLL) && SHP_ptr->param_PCR_or_PBD_or_PO == SF_MODE_PBD) )
            do_server_SpreadFactors_next = 1;
//         else
//            do_server_SpreadFactors_next = 0;
         SetSRFReuseModeStartSRFRequestSpreadFactors(max_string_len, SHP_ptr, do_server_SpreadFactors_next, verifier_socket_desc);
         }

// Tell server we are done.
      else
         SendSpreadFactorsDone(max_string_len, SHP_ptr, verifier_socket_desc);

// Transmit the SpreadFactors to verifier. NOT NEEDED ANY LONGER because we are using pure PopOnly mode -- NO changes are made to the SF.
// But this is required for PCR mode because device modifies server-generated SF.
      if ( SockSendB((unsigned char *)SHP_ptr->iSpreadFactors, SHP_ptr->num_SF_bytes, verifier_socket_desc) < 0 )
         { printf("ERROR: KEK_DeviceAuthentication_SKE(): Send iSpreadFactors failed\n"); exit(EXIT_FAILURE); }
      }

printf("\tNum nonce bits %d\tNumber of iterations %d\n", SHP_ptr->num_KEK_authen_nonce_bits, target_attempts); fflush(stdout);
#ifdef DEBUG
#endif

// ------------------------------------------------------------------
// Send server the KEK_authen_XMR_SHD.
   if ( SockSendB(KEK_authen_XMR_SHD, current_XMR_SHD_num_bytes, verifier_socket_desc) < 0 )
      { printf("ERROR: KEK_DeviceAuthentication_SKE(): Send KEK_authen_XMR_SHD failed\n"); exit(EXIT_FAILURE); }

// Sanity check. PUF engine MUST be 'ready'
   if ( (*(SHP_ptr->DataRegA) & (1 << IN_SM_READY)) == 0 )
      { printf("ERROR: KEK_DeviceAuthentication_SKE(): PUF Engine is NOT ready!\n"); exit(EXIT_FAILURE); }

// ----------------------------------------
// Free up the vectors and masks. 
   FreeVectorsAndMasks(&(SHP_ptr->num_vecs), &(SHP_ptr->num_rise_vecs), &(SHP_ptr->first_vecs_b), &(SHP_ptr->second_vecs_b), &(SHP_ptr->masks_b));

// Free up locally generated storage
   if ( KEK_authen_XMR_SHD != NULL )
      free(KEK_authen_XMR_SHD);
   if ( KEK_authentication_nonce != NULL )
      free(KEK_authentication_nonce);
// ----------------------------------------

// Restore the ctrl_mask in the structure if in fact it was changed above.
   SHP_ptr->ctrl_mask = former_ctrl_mask;

// Reset to 'normal' values.
   SHP_ptr->XMR_val = XMR_VAL;

// 10_22_2022 updates.
   SHP_ptr->param_RangeConstant = RANGE_CONSTANT; 
   SHP_ptr->param_PCR_or_PBD_or_PO = prev_PCR_PBD_PO_mode;

// 11_12_2022
   SHP_ptr->do_scaling = prev_do_scaling;

   return DA_Report(max_string_len, SHP_ptr, verifier_socket_desc);
   }


// ========================================================================================================
// ========================================================================================================
// Device authentication verifier.

int KEK_VerifierAuthentication(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int verifier_socket_desc)
   {
   int target_attempts, force_threshold_zero, do_all_calls;
   int former_ctrl_mask, current_function; 
   int also_do_transfer;

   unsigned char *KEK_authentication_nonce_reproduced;
   unsigned char *KEK_authentication_nonce;

   char received_XMR_SHD_num_bytes_str[max_string_len];

   int SBS_bit_cnt_valid, get_SHD_SBS_both, do_server_SpreadFactors_next;
   int regen_num_SBS_bits; 

   unsigned char *KEK_authen_XMR_SHD;
   int received_XMR_SHD_num_bytes, actual_XMR_SHD_num_bytes; 

   int bits_remaining, current_num_strong_bits;
   int num_minority_bit_flips; 

   int num_mismatches, fail_or_pass, true_mismatch_count;

   int i, j;

   struct timeval t0, t1;
   long elapsed; 

   printf("\n\t\t\t******************* VERIFIER AUTHENTICATION BEGINS  ******************* \n");

// Save existing mask so we can restore on exit.
   former_ctrl_mask = SHP_ptr->ctrl_mask;

   current_function = FUNC_VA;

// Use the 'normal' XMR value.
   SHP_ptr->XMR_val = XMR_VAL;
   SHP_ptr->param_RangeConstant = RANGE_CONSTANT; 

// ALWAYS load SF, NEVER compute PCR/PBD SF (computed by server), and NEVER modify the loaded SF. The server implements
// the SF mode and sends the SF to the device. Device loads them and does NOT modify them.
   SHP_ptr->load_SF = 1;
   SHP_ptr->compute_PCR_PBD = 0;
   SHP_ptr->modify_PO = 0;
   SHP_ptr->dump_updated_SF = 0;

// Set hardware function "001"
   SHP_ptr->ctrl_mask = ((SHP_ptr->ctrl_mask & ~(1 << OUT_CP_KEK)) & ~(1 << OUT_CP_MODE1)) | (1 << OUT_CP_MODE0);

// Get only the challenge vectors, run CollectPNs to get timing data and nonces and do the nonce exchange with the verifier for 
// parameter selection. NOTE: WE MUST DO THIS HERE to generate the KEK_authentication_nonce from the hardware.
   target_attempts = 0;
   force_threshold_zero = 0;
   do_all_calls = 0;
   CommonCore(max_string_len, SHP_ptr, verifier_socket_desc, target_attempts, force_threshold_zero, do_all_calls, current_function);

// Construct KEK_authentication_nonce. Sanity check on the number of nonce bytes generated by the hardware. Note, the first 
// 'SHP_ptr->num_required_nonce_bytes' bytes are used in the XOR_nonce to generate random parameters. If we have enough, then skip the 
// first 8 bytes. We ALWAYS get 46 nonce bytes from the hardware (4096 PNR/PNF, 12 PNx pre-bit = 4096/12 = 341.3 bits/8 = 42 bytes.
   if ( SHP_ptr->num_device_n1_nonces >= SHP_ptr->num_required_nonce_bytes + SHP_ptr->num_KEK_authen_nonce_bits/8 )
      {
      for ( i = 0; i < SHP_ptr->num_KEK_authen_nonce_bits/8; i++ )
         SHP_ptr->KEK_authentication_nonce[i] = SHP_ptr->device_n1[i + SHP_ptr->num_required_nonce_bytes];
      }

// Otherwise, reuse the device generated nonce bytes also used in the XOR_nonce.
   else if ( SHP_ptr->num_device_n1_nonces >= SHP_ptr->num_KEK_authen_nonce_bits/8 )
      {
      for ( i = 0; i < SHP_ptr->num_KEK_authen_nonce_bits/8; i++ )
         SHP_ptr->KEK_authentication_nonce[i] = SHP_ptr->device_n1[i];
      }
   else
      { 
      printf("ERROR: KEK_VerifierAuthentication(): Hardware generated only %d nonce bytes -- NOT enough for verifier KEK_authentication nonce of size %d\n",
         SHP_ptr->num_device_n1_nonces, SHP_ptr->num_KEK_authen_nonce_bits/8); exit(EXIT_FAILURE); 
      }

#ifdef DEBUG
printf("KEK_VerifierAuthentication(): CollectPNs generated %d nonce bytes\n", SHP_ptr->num_device_n1_nonces); fflush(stdout);
#endif

#ifdef DEBUG
PrintHeaderAndHexVals("KEK_VerifierAuthentication(): ORIGINAL device generated nonce\n", SHP_ptr->num_KEK_authen_nonce_bits/8, SHP_ptr->KEK_authentication_nonce, 16);
#endif

// ------------------------------------------------------------------
// Send the KEK_authentication_nonce to the verifier.
   if ( SockSendB(SHP_ptr->KEK_authentication_nonce, SHP_ptr->num_KEK_authen_nonce_bits/8, verifier_socket_desc) < 0 )
      { printf("ERROR: KEK_VerifierAuthentication(): Verifier KEK_authentication_nonce send failed\n"); exit(EXIT_FAILURE); }

// Wait for verifier to generate the KEK_authen_XMR_SHD. Get the size first so we can allocate space for the KEK_authen_XMR_SHD.
   if ( SockGetB((unsigned char *)received_XMR_SHD_num_bytes_str, max_string_len, verifier_socket_desc) < 0 )
      { printf("ERROR: KEK_VerifierAuthentication(): Error receiving 'received_XMR_SHD_num_bytes_str' from verifier!\n"); exit(EXIT_FAILURE); }
   sscanf(received_XMR_SHD_num_bytes_str, "%d", &received_XMR_SHD_num_bytes);

// Allocate space for KEK_authen_XMR_SHD array
   if ( (KEK_authen_XMR_SHD = (unsigned char *)malloc(sizeof(unsigned char)*(received_XMR_SHD_num_bytes))) == NULL )
      { printf("ERROR: KEK_VerifierAuthentication(): Allocation for 'KEK_authen_XMR_SHD' failed!\n"); exit(EXIT_FAILURE); }

   if ( (actual_XMR_SHD_num_bytes = SockGetB(KEK_authen_XMR_SHD, received_XMR_SHD_num_bytes, verifier_socket_desc)) != received_XMR_SHD_num_bytes )
      { 
      printf("KEK_VerifierAuthentication(): Receive 'KEK_authen_XMR_SHD' request failed: received %d -- expected %d!\n", 
         actual_XMR_SHD_num_bytes, received_XMR_SHD_num_bytes); 
      exit(EXIT_FAILURE); 
      }

#ifdef DEBUG
printf("KEK_VerifierAuthentication(): Verifier returned %d received_XMR_SHD_num_bytes\n", received_XMR_SHD_num_bytes); fflush(stdout);
#endif

// Note, we are (eventually) going to compare the device generated nonce sent to the server with the 'nonce_reproduced' in the hardware.
// This will be used to transfer increasingly smaller chunks of the nonce into the hardware
   if ( (KEK_authentication_nonce = (unsigned char *)calloc(SHP_ptr->num_KEK_authen_nonce_bits/8, sizeof(unsigned char))) == NULL )
      { printf("ERROR: KEK_VerifierAuthentication(): Failed to allocate storage for KEK_authentication_nonce!\n"); exit(EXIT_FAILURE); }
   if ( (KEK_authentication_nonce_reproduced = (unsigned char *)calloc(SHP_ptr->num_KEK_authen_nonce_bits/8, sizeof(unsigned char))) == NULL )
      { printf("ERROR: KEK_VerifierAuthentication(): Failed to allocate storage for KEK_authentication_nonce!\n"); exit(EXIT_FAILURE); }

// Need to make a copy of this locally because it is destroyed below.
   for ( i = 0; i < SHP_ptr->num_KEK_authen_nonce_bits/8; i++ )
      KEK_authentication_nonce[i] = SHP_ptr->KEK_authentication_nonce[i];

// ------------------------------------------------------------------
// Now do the regeneration component. ASSUME the above CommonCore call fetched the challenge vectors from the verifier, has generated 
// and stored the timing vals (PNR and PNF) in BRAM and the XOR_nonce has been computed and exchanged. We need to finish the device
// authentication that we started above by getting SpreadFactors from server, transferring parameters to hardware (after setting the LFSR_seed_low 
// according to the value of target attempts) 

// NOTE: Unlike KEK Regeneration, the function in the hardware here is set to device authentication. When we do KEK regeneration, the
// hardware AUTOMATICALLY sets the Threshold in the hardware to 0 despite what we send in via SelectSetParams, so we don't need to force
// it to 0 as we do here.
   force_threshold_zero = 1;
   bits_remaining = SHP_ptr->num_KEK_authen_nonce_bits; 

// This is the number loaded into the SRF engine
   SHP_ptr->num_KEK_authen_nonce_bits_remaining = SHP_ptr->num_KEK_authen_nonce_bits;

   num_minority_bit_flips = 0;
   true_mismatch_count = 0;
   num_mismatches = 0;

   target_attempts = 0;
   current_num_strong_bits = 0;
   while ( current_num_strong_bits < SHP_ptr->num_KEK_authen_nonce_bits )
      {

// Sanity check. The number of iterations here should NEVER exceed what the server did to generate the received_XMR_SHD_num_bytes.
      if ( target_attempts*SHP_ptr->num_required_PNDiffs/8 >= received_XMR_SHD_num_bytes )
         { printf("ERROR: KEK_VerifierAuthentication(): Number of iterations larger than server -- unexpected!\n"); exit(EXIT_FAILURE); }

// Convenience function that calls GetSpreadFactors(), SelectSetParams() and RunSRFEngine().
      GetSpreadFactorsSelectSetParamsRunSRF(max_string_len, SHP_ptr, target_attempts, force_threshold_zero, current_function, verifier_socket_desc);

// Transfer a chunk of the authentication nonce into the hardware. We compare the 'nonce_reproduced' with this nonce and count the
// number of mismatches in the hardware. 
      TransferAuthenNonce(max_string_len, SHP_ptr, KEK_authentication_nonce);

// Fetch from the hardware the device SHD and SBS. NOTE: the num of SBS bits reported by FetchTransSHD_SBS IS NOT YET valid here -- reported as the
// number of KEK_FSB_SKE bits from a previous operation.
      also_do_transfer = 0;
      SBS_bit_cnt_valid = 0;
      get_SHD_SBS_both = 2;
      FetchSendSHDAndSBS(max_string_len, SHP_ptr, SBS_bit_cnt_valid, also_do_transfer, get_SHD_SBS_both, &regen_num_SBS_bits, verifier_socket_desc);

// Load server's XMR_SHD. Add 2048 bits (256 bytes) to the base address on each iteration to get the appropriate helper data.
      int load_or_unload = 0;
      int byte_or_word_data = 0;
      LoadUnloadBRAM(max_string_len, SHP_ptr->num_required_PNDiffs/8, SHP_ptr->CtrlRegA, SHP_ptr->DataRegA, SHP_ptr->ctrl_mask, 
         KEK_authen_XMR_SHD + target_attempts*SHP_ptr->num_required_PNDiffs/8, NULL, load_or_unload, byte_or_word_data, SHP_ptr->DEBUG_FLAG);

// TEMPORARY: SOFTWARE VERSION: 
// The PRODUCT of KEK_FSB_SKE() during regeneration mode is KEK_authentication_nonce_reproduced, which uses the XMR SHD helper data generated 
// during enrollment and the raw bitstring device_SBS. Each iteration generates a portion of the KEK_authentication_nonce. It returns a portion of 
// KEK_authentication_nonce_reproduced that was generated. Note that 'bits_remaining' during regeneration is used to exit the loop early when the
// number of bits produced reaches the max (same thing that happens during enrollment when we are encoding KEK_authentication_nonce). This gives us
// an accurate count of how many minority bit flips occurred, which can be used for additional evidence of correct authentication. NOTE: PASS
// THE ENTIRE SHP_ptr->KEK_authentication_nonce in as the 'KEK_enroll_key' parameter (5th to last), NOT THE TRUNCATED nonce.
#ifdef DEBUG
int do_mismatch_count = 1;
int FSB_or_SKE = 1;
int enroll_or_regen = 1;
int num_strong_bits;
num_strong_bits = KEK_FSB_SKE(SHP_ptr->num_required_PNDiffs, SHP_ptr->XMR_val, 
   KEK_authen_XMR_SHD + target_attempts*SHP_ptr->num_required_PNDiffs/8, SHP_ptr->device_SBS, NULL, bits_remaining, 
   KEK_authentication_nonce_reproduced, enroll_or_regen, do_mismatch_count, &num_minority_bit_flips, 
   current_num_strong_bits, SHP_ptr->KEK_authentication_nonce, &true_mismatch_count, FSB_or_SKE, 0, 0);
#endif

// Hardware runs KEK SKE Regeneration, which uses XMR_SHD as input and reproduces the nonce (XMR_SBS, which stored in the device_SBS field) and num_strong_bits
// as output. Get the XMR_SBS and num_strong_bits.
      also_do_transfer = 0;
      SBS_bit_cnt_valid = 1;
      get_SHD_SBS_both = 1;
      FetchSendSHDAndSBS(max_string_len, SHP_ptr, SBS_bit_cnt_valid, also_do_transfer, get_SHD_SBS_both, &regen_num_SBS_bits, verifier_socket_desc);

// Now we need to eliminate 'num_strong_bits' from KEK_authentication_nonce and move all the remaining bits to start at the first bit/byte. 
//      bits_remaining = EliminatePackedBitsFromBS(bits_remaining, KEK_authentication_nonce, num_strong_bits);
      bits_remaining = EliminatePackedBitsFromBS(bits_remaining, KEK_authentication_nonce, regen_num_SBS_bits);
      SHP_ptr->num_KEK_authen_nonce_bits_remaining = bits_remaining;

#ifdef DEBUG
PrintHeaderAndHexVals("KEK_VerifierAuthentication(): Device nonce that remain\n", SHP_ptr->num_KEK_authen_nonce_bits/8, KEK_authentication_nonce, 16);
#endif

#ifdef DEBUG
PrintHeaderAndHexVals("KEK_VerifierAuthentication(): SOFTWARE: nonce reproduced\n", SHP_ptr->num_KEK_authen_nonce_bits/8, KEK_authentication_nonce_reproduced, 16);
#endif

#ifdef DEBUG
printf("KEK_VerifierAuthentication(): SOFTWARE: Number of authentication bits reproduced %d\n", num_strong_bits); fflush(stdout);
#endif

#ifdef DEBUG
printf("\tBits remaining %d\n", bits_remaining); fflush(stdout);
#endif

// Compute the number of mismatched bits, hopefully 0.
//      for ( i = current_num_strong_bits, j = 0; i < current_num_strong_bits + num_strong_bits && i < SHP_ptr->num_KEK_authen_nonce_bits; i++, j++ )
      for ( i = current_num_strong_bits, j = 0; i < current_num_strong_bits + regen_num_SBS_bits && i < SHP_ptr->num_KEK_authen_nonce_bits; i++, j++ )
         if ( GetBitFromByte(SHP_ptr->device_SBS[j/8], j % 8) != GetBitFromByte(SHP_ptr->KEK_authentication_nonce[i/8], i % 8) )
            {
printf("\tMISMATCH on bit %d\n", i); fflush(stdout);
#ifdef DEBUG
#endif
            num_mismatches++;
            }

#ifdef DEBUG
printf("\tNum mismatches %d\n", num_mismatches); fflush(stdout);
#endif

// Keep adding to the current number of strong bits processed. 
//      current_num_strong_bits += num_strong_bits;
      current_num_strong_bits += regen_num_SBS_bits;
      target_attempts++;

// Set number of bits matched to max size when we processed all bits in the authentication nonce.
      if ( i == SHP_ptr->num_KEK_authen_nonce_bits )
         current_num_strong_bits = SHP_ptr->num_KEK_authen_nonce_bits;

// Set PN reuse mode in hardware, start SRF engine and request additional SpreadFactors from server.
      else
         {
         do_server_SpreadFactors_next = 1;
         SetSRFReuseModeStartSRFRequestSpreadFactors(max_string_len, SHP_ptr, do_server_SpreadFactors_next, verifier_socket_desc);
         }

      for ( i = 0; i < SHP_ptr->num_KEK_authen_nonce_bits/8; i++ )
         KEK_authentication_nonce_reproduced[i] = 0;
      }

// ------------------------------------------------------------------
// Tell server we are done.
   SendSpreadFactorsDone(max_string_len, SHP_ptr, verifier_socket_desc);

// Sanity check. PUF engine MUST be 'ready'
   if ( (*(SHP_ptr->DataRegA) & (1 << IN_SM_READY)) == 0 )
      { printf("ERROR: KEK_VerifierAuthentication(): PUF Engine is NOT ready!\n"); exit(EXIT_FAILURE); }

   if ( num_mismatches <= AUTHENTICATION_ALLOWED_NUM_MISMATCH_BITS )
      {
      fail_or_pass = 1;

printf("\t\tMATCHED***\tTotal bits mismatched %5d\tFrom total %5d\tRemaining %4d\tTotal minority flips %d\tTrue mismatch count %d\n",
   num_mismatches, current_num_strong_bits, bits_remaining, num_minority_bit_flips, true_mismatch_count); fflush(stdout);
#ifdef DEBUG
#endif
      }
   else
      {
      fail_or_pass = 0;

printf("\t\tMISMATCHED\tTotal bits mismatched %5d\tFrom total %5d\tRemaining %4d\tTotal minority flips %d\tTrue mismatch count %d\n",
   num_mismatches, current_num_strong_bits, bits_remaining, num_minority_bit_flips, true_mismatch_count); fflush(stdout);
#ifdef DEBUG
#endif
      }

// ------------------------------------------------------------------
// ***** The verifier will wait before closing the socket for this string.
   if ( SHP_ptr->DEBUG_FLAG == 1 )
      {
      if ( fail_or_pass == 0 )
         printf("\tSending 'FAIL'\n");
      else
         printf("\tSending 'PASS'\n");
      gettimeofday(&t0, 0);
      }
   if ( fail_or_pass == 0 )
      {
      if ( SockSendB((unsigned char *)"FAIL", strlen("FAIL")+1, verifier_socket_desc) < 0 )
         { printf("ERROR: KEK_VerifierAuthentication(): Send 'FAIL' request failed\n"); exit(EXIT_FAILURE); }
      }
   else
      {
      if ( SockSendB((unsigned char *)"PASS", strlen("PASS")+1, verifier_socket_desc) < 0 )
         { printf("ERROR: KEK_VerifierAuthentication(): Send 'PASS' request failed\n"); exit(EXIT_FAILURE); }
      }
   if ( SHP_ptr->DEBUG_FLAG == 1 )
      { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tElapsed %ld us\n\n", (long)elapsed); }
   fflush(stdout);

// Free up the vectors and masks. 
   FreeVectorsAndMasks(&(SHP_ptr->num_vecs), &(SHP_ptr->num_rise_vecs), &(SHP_ptr->first_vecs_b), &(SHP_ptr->second_vecs_b), &(SHP_ptr->masks_b));

// Free up locally generated storage
   if ( KEK_authen_XMR_SHD != NULL )
      free(KEK_authen_XMR_SHD);
   if ( KEK_authentication_nonce != NULL )
      free(KEK_authentication_nonce);
   if ( KEK_authentication_nonce_reproduced != NULL )
      free(KEK_authentication_nonce_reproduced);

   SHP_ptr->ctrl_mask = former_ctrl_mask;

   return fail_or_pass;
   }


// ========================================================================================================
// ========================================================================================================
// Basic process steps of the 'first strong bit' (FSM) version of KEK enrollment:
//    1) Free up data structures storing information about previous enrollment.
//    2) Set either Long-lived key mode or session key mode in hardware
//    3) Do full computation
//       a) Check READY status of MstCtrl hardware state machine.
//       b) Start MstCtrl state machine. 
//       c) Get vectors and path select masks from verifier
//       d) Run CollectPNs which measures the entropy source and stores values in BRAM.
//       e) Exchange nonces with verifier to create XOR_nonce.
//    4) Loop over LFSR seed increments until key length is met.
//       a) Get Pop-only SpreadFactors or nothing (PBD) from server if Long-lived and PCR SpreadFactors if session key
//       b) Select parameters and transfer to hardware.
//       c) Run the SRF algorithm, ComputePNDiffs, TVComp, AddSpreadFactors (twice for long-lived key to generate PCR, once for session keygen)
//       d) Fetch SHD and SBS from hardware BEFORE XMR is run. 
//       e) Run KEK FSB
//       f) Fetch XMR SHD, XMR SBS (KEK key) and SpreadFactors (if Long-lived key) 
//    5) If long-lived, store KEK challenge information, vectors, masks, SpreadFactors to special KEK_xxx fields. Note that KEK helper data and
//          KEK SpreadFactors are already stored in special KEK fields as 4) above executes. Regeneration will use these KEK 
//          challenge fields to do regeneration. Send XMR_SHD to server if Session Key (or Device Authenication/COBRA).

int KEK_Enroll(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int LL_or_session_or_cobra_PO, 
   int verifier_socket_desc)
   {
   int target_attempts, force_threshold_zero, do_all_calls;
   int enroll_num_key_bits, enroll_num_XMR_HD_bits;
   int also_do_transfer;

   int SBS_bit_cnt_valid, get_SHD_SBS_both, do_server_SpreadFactors_next;

   int former_ctrl_mask, current_function, num_SBS_bits;

   unsigned int target_num_key_bytes, current_num_key_bits; 
   unsigned int current_XMR_SHD_num_bytes, current_XSpreadFactors_num_words;

   unsigned char *XMR_SHD = NULL;
   signed char *SpreadFactors = NULL;

   unsigned char **XMR_SHD_ptr = NULL;
   signed char **SpreadFactors_ptr = NULL;
   unsigned char **key_ptr = NULL;

   unsigned int i, j;

// 9_18_2022: Timing tests for FSB KEK for SiRF paper. GenLLK from device_regeneration is called and then this routine.
// 9_18_2022: Taking this out temporarily for SiRF paper timing operation.
printf("\n\t\t\t******************* KEK BEGINS: ENROLL  *******************\n"); fflush(stdout);
#ifdef DEBUG
#endif

// Save existing mask so we can restore on exit.
   former_ctrl_mask = SHP_ptr->ctrl_mask;

// 10_28_2022: Saving so we can restore if Cobra is run below.
   int prev_PCR_PBD_PO_mode = SHP_ptr->param_PCR_or_PBD_or_PO;

// 11_12_2022: Restore old value if it is changed below (for COBRA).
   int prev_do_scaling = SHP_ptr->do_scaling;

// ==================================
// For LL_ENROLL
   if ( LL_or_session_or_cobra_PO == 0 )
      {
      current_function = FUNC_LL_ENROLL;
      SHP_ptr->ctrl_mask = ((SHP_ptr->ctrl_mask | (1 << OUT_CP_KEK)) | (1 << OUT_CP_MODE1)) | (1 << OUT_CP_MODE0);
      }

// For SE and Cobra
   else
      {
      current_function = FUNC_SE;
      SHP_ptr->ctrl_mask = ((SHP_ptr->ctrl_mask & ~(1 << OUT_CP_KEK)) | (1 << OUT_CP_MODE1)) & ~(1 << OUT_CP_MODE0);
      }

// ==================================
   if ( LL_or_session_or_cobra_PO == 0 )
      {
      if ( (SHP_ptr->KEK_target_num_key_bits % 8) != 0 )
         { printf("ERROR: KEK_Enroll(): KEK_target_num_key_bits %d MUST be divisible by 8!\n", SHP_ptr->KEK_target_num_key_bits); exit(EXIT_FAILURE); }
      target_num_key_bytes = SHP_ptr->KEK_target_num_key_bits/8;

// Free up arrays from previous enroll operations. Probably not needed because we use realloc below and at start-up these arrays are 
// initialized to NULL.
      SHP_ptr->KEK_num_iterations = 0;
      if ( SHP_ptr->KEK_final_XMR_SHD != NULL )
         free(SHP_ptr->KEK_final_XMR_SHD);
      SHP_ptr->KEK_final_XMR_SHD = NULL;

      XMR_SHD_ptr = &(SHP_ptr->KEK_final_XMR_SHD);

      if ( SHP_ptr->KEK_final_SpreadFactors_enroll != NULL )
         free(SHP_ptr->KEK_final_SpreadFactors_enroll); 
      SHP_ptr->KEK_final_SpreadFactors_enroll = NULL;

      SpreadFactors_ptr = &(SHP_ptr->KEK_final_SpreadFactors_enroll);

      if ( SHP_ptr->KEK_final_enroll_key != NULL )
         free(SHP_ptr->KEK_final_enroll_key);
      SHP_ptr->KEK_final_enroll_key = NULL;

      key_ptr = &(SHP_ptr->KEK_final_enroll_key);

// LLE uses the 'normal' XMR value.
      SHP_ptr->XMR_val = XMR_VAL;
      SHP_ptr->param_RangeConstant = RANGE_CONSTANT; 

// Load SF if PO or PCR mode, compute PCR/PBD SF if NOT PO mode, and modify the loaded PO if PO or PCR mode
// PCR
      if ( SHP_ptr->param_PCR_or_PBD_or_PO == SF_MODE_PCR )
         {
         SHP_ptr->load_SF = 1;
         SHP_ptr->compute_PCR_PBD = 1;
         SHP_ptr->modify_PO = 1;
         SHP_ptr->dump_updated_SF = 1;
         }
// PBD
      else if ( SHP_ptr->param_PCR_or_PBD_or_PO == SF_MODE_PBD )
         {
         SHP_ptr->load_SF = 0;
         SHP_ptr->compute_PCR_PBD = 1;
         SHP_ptr->modify_PO = 0;
         SHP_ptr->dump_updated_SF = 1;
         }
// PO
      else if ( SHP_ptr->param_PCR_or_PBD_or_PO == SF_MODE_POPONLY )
         {
         SHP_ptr->load_SF = 1;
         SHP_ptr->compute_PCR_PBD = 0;
         SHP_ptr->modify_PO = 1;
         SHP_ptr->dump_updated_SF = 1;
         }
      else
         { printf("ERROR: KEK_Enroll(): Illegal mode %d\n", SHP_ptr->param_PCR_or_PBD_or_PO); exit(EXIT_FAILURE); }
      }

// Note: For session key generation, we do NOT need to do regeneration, ONLY ENROLLMENT. However, we do need to store the XMR_SHD data 
// so we can transmit it to the server, so it can run regeneration of this 'first strong bit' (FSB) version of the algorithm. Since 
// the server generates and sends SpreadFactors, it already has them so no need to store the SpreadFactors for FUNC_SE as is true 
// for FUNC_LL_ENROLL.
   else if ( LL_or_session_or_cobra_PO == 1 )
      {
      if ( (SHP_ptr->SE_target_num_key_bits % 8) != 0 )
         { printf("ERROR: KEK_Enroll(): SE_target_num_key_bits %d MUST be divisible by 8!\n", SHP_ptr->SE_target_num_key_bits); exit(EXIT_FAILURE); }
      target_num_key_bytes = SHP_ptr->SE_target_num_key_bits/8;
      XMR_SHD_ptr = &XMR_SHD;

// We do NOT need to save SpreadFactors for Session Key Gen but we use this for Other protocol Enroll functions 
      SpreadFactors_ptr = &SpreadFactors;
      if ( SHP_ptr->SE_final_key != NULL )
         free(SHP_ptr->SE_final_key);
      SHP_ptr->SE_final_key = NULL;
      key_ptr = &(SHP_ptr->SE_final_key);

// SE uses the 'normal' XMR value.
      SHP_ptr->XMR_val = XMR_VAL;
      SHP_ptr->param_RangeConstant = RANGE_CONSTANT; 

      SHP_ptr->load_SF = 1;
      SHP_ptr->compute_PCR_PBD = 0;
      SHP_ptr->modify_PO = 0;
      SHP_ptr->dump_updated_SF = 0;
      }

// 10_17_2021: For Cobra authentication, the server does NOT know which chip is authenticating so it can NOT compute the PNDco_po values properly with inversion 
// so we MUST modify the PO SF here on the device.
// 10_10_2022: UPDATE: FROM ZED experiments, I found my new metric for authentication in verifier_regen_funcs.c do NOT require FLIP.
   else 
      {
      if ( (SHP_ptr->num_KEK_authen_nonce_bits % 8) != 0 )
         { printf("ERROR: KEK_Enroll(): num_KEK_authen_nonce_bits %d MUST be divisible by 8!\n", SHP_ptr->num_KEK_authen_nonce_bits); exit(EXIT_FAILURE); }
      target_num_key_bytes = SHP_ptr->num_KEK_authen_nonce_bits/8;
      XMR_SHD_ptr = &XMR_SHD;
      SpreadFactors_ptr = &SpreadFactors;
      if ( SHP_ptr->DA_cobra_key != NULL )
         free(SHP_ptr->DA_cobra_key);
      SHP_ptr->DA_cobra_key = NULL;
      key_ptr = &(SHP_ptr->DA_cobra_key);

// Cobra MUST use XMR value of 1.
      SHP_ptr->XMR_val = DEVICE_COBRA_AUTHEN_XMR_VAL;

// 10_22_2022: From ZED experiments, I found that PopOnly, No flip with personalized range factors works best. Forcing that here.
      SHP_ptr->param_PCR_or_PBD_or_PO = SF_MODE_POPONLY;

// HERE 11_6_2022: Wondering if I split the strong and weak regions in half that the COBRA PCCs get closer to 50%, instead of 30%.
//      SHP_ptr->param_Threshold = DEVICE_COBRA_AUTHEN_THRESHOLD_CONSTANT; 

// 11_12_2022: ALWAYS do scaling THIS FOR COBRA. 
      SHP_ptr->do_scaling = 1;

#ifdef DEBUG
printf("KEK_Enroll(): COBRA: Loading RangeConstant %d\n", SHP_ptr->param_RangeConstant); fflush(stdout);
#endif

// **********************************************
// Load server computed pure PopOnly SF (no flip operation applied) because this is Device authentication (we do not know which device is authenticating).
// 10_17_2021: We should be able to use any SF mode here (currently disabling PCR and PBD).
// 10_10_2022: UPDATE: FROM ZED experiments, I found PopOnly, No Flip works best, so force NO SF updates here.
//             I do NOT need to DUMP SF and send the SF back to the server since they are NOT modified.
      SHP_ptr->load_SF = 1;
      SHP_ptr->compute_PCR_PBD = 0;
      SHP_ptr->modify_PO = 0;
      SHP_ptr->dump_updated_SF = 1;
      }

// Operations common to ALL functions. Do only the first part, fetch vectors, etc.
   target_attempts = 0;
   force_threshold_zero = 0;
   do_all_calls = 0;
   CommonCore(max_string_len, SHP_ptr, verifier_socket_desc, target_attempts, force_threshold_zero, do_all_calls, current_function);

// Loop incrementing LFSR seeds until 'KEK_target_num_key_bits' is met
   current_num_key_bits = 0;

// These fields ONLY relevant for KEK enrollment, NOT session key generation
   current_XMR_SHD_num_bytes = 0;
   current_XSpreadFactors_num_words = 0;
   while (1)
      {

// Convenience function that calls GetSpreadFactors(), SelectSetParams() and RunSRFEngine().
      GetSpreadFactorsSelectSetParamsRunSRF(max_string_len, SHP_ptr, target_attempts, force_threshold_zero, current_function, verifier_socket_desc);

// Fetch from the hardware the device SHD (always num_required_PNDiffs/8 bytes). DO NOT TRANSFER TO verifier -- this SHD helper data is NOT needed -- 
// it is returned because state machines in hardware assume we are doing authentication. Also fetch from the hardware the device SBS (variable in size -- 
// not in increments of bytes). Also NOT needed -- see note above. NOTE: the num of SBS bits reported by FetchTransSHD_SBS is NOT valid here 
// so 0 is returned instead with 'SBS_bit_cnt_valid' set to 0.
      also_do_transfer = 0;
      SBS_bit_cnt_valid = 0;
      get_SHD_SBS_both = 2;
      FetchSendSHDAndSBS(max_string_len, SHP_ptr, SBS_bit_cnt_valid, also_do_transfer, get_SHD_SBS_both, &num_SBS_bits, verifier_socket_desc);

// ****************************************
// ***** RUN KEK FSB mode
      if ( SHP_ptr->DEBUG_FLAG == 1 )
         printf("KEK.1) Running KEK FSB mode (ENROLL)\n\n");

// For KEK Enrollment, we now can fetch the KEK_SHD followed by the KEK_SBS AFTER XMR has been run. This data needs to be saved. The KEK_SHD encodes as many bits
// as possible and may have a specification for the last partial bit (one that does not exist in the KEK_SBS).
      also_do_transfer = 0;
      SBS_bit_cnt_valid = 1;
      get_SHD_SBS_both = 2;
      enroll_num_XMR_HD_bits = FetchSendSHDAndSBS(max_string_len, SHP_ptr, SBS_bit_cnt_valid, also_do_transfer, get_SHD_SBS_both, &enroll_num_key_bits, 
         verifier_socket_desc);

// Sanity check.
      if ( enroll_num_XMR_HD_bits != SHP_ptr->num_required_PNDiffs )
         { printf("ERROR: Expected number of enroll_num_XMR_HD_bits to be %d\tRead %d\n", SHP_ptr->num_required_PNDiffs, enroll_num_XMR_HD_bits); exit(EXIT_FAILURE); }

// Copy the helper data into the dynamically allocated array (for LLK, use dedicated for the LongLivedEnroll key in data structure). NOTE: We do NOT know how many 
// iterations we will need to get to the target number of key bits. Also the same is true for PCR SpreadFactors. 
      if ( (*XMR_SHD_ptr = (unsigned char *)realloc(*XMR_SHD_ptr, sizeof(unsigned char)*(current_XMR_SHD_num_bytes + enroll_num_XMR_HD_bits/8))) == NULL)
         { printf("ERROR: KEK_Enroll(): Allocation for 'XMR_SHD' failed!\n"); exit(EXIT_FAILURE); }

// Add new helper data to array
      for ( i = current_XMR_SHD_num_bytes, j = 0; i < enroll_num_XMR_HD_bits/8 + current_XMR_SHD_num_bytes; i++, j++ )
         (*XMR_SHD_ptr)[i] = SHP_ptr->device_SHD[j];
      current_XMR_SHD_num_bytes += enroll_num_XMR_HD_bits/8;

// Note: Technically we don't need to do this for Session Key Gen but with Other protocol Enroll functions we do need to do it.
//      if ( LL_or_session_or_cobra_PO == 0 || LL_or_session_or_cobra_PO == 2 )
         {
         if ( (*SpreadFactors_ptr = (signed char *)realloc(*SpreadFactors_ptr, sizeof(signed char)*(current_XSpreadFactors_num_words + enroll_num_XMR_HD_bits))) == NULL )
            { printf("ERROR: KEK_Enroll(): Allocation for 'SpreadFactors' failed!\n"); exit(EXIT_FAILURE); }

         for ( i = current_XSpreadFactors_num_words, j = 0; i < enroll_num_XMR_HD_bits + current_XSpreadFactors_num_words; i++, j++ )
            (*SpreadFactors_ptr)[i] = SHP_ptr->iSpreadFactors[j];
         current_XSpreadFactors_num_words += enroll_num_XMR_HD_bits;
         }

// 3_14_2021: Copy Key bytes into the allocated array. We used to discard the last partial byte but that was wasteful -- now preserving them. 
// NOTE: This routine ALLOCATES space for the key as needed.
      current_num_key_bits = JoinBytePackedBitStrings(current_num_key_bits, key_ptr, enroll_num_key_bits, SHP_ptr->device_SBS);

printf("\tTarget attempt %2d\tMode %d\tXMR %2d\tLFSR low %4d\tLFSR high %4d\tRC %3d\tSC %2d\tTH %d\tTCC %2d\tCurrent num key bits %3d\n\n", 
   target_attempts, SHP_ptr->param_PCR_or_PBD_or_PO, SHP_ptr->XMR_val, SHP_ptr->param_LFSR_seed_low, SHP_ptr->param_LFSR_seed_high,
   SHP_ptr->param_RangeConstant, SHP_ptr->param_SpreadConstant, SHP_ptr->param_Threshold, SHP_ptr->param_TrimCodeConstant, current_num_key_bits); fflush(stdout);
#ifdef DEBUG
#endif

// Break when we've reached the 'KEK_target_num_key_bits'. We go a FIXED number of iterations for Cobra authentication.
      target_attempts++;
      if ( (LL_or_session_or_cobra_PO < 2 && current_num_key_bits/8 >= target_num_key_bytes) || 
           (LL_or_session_or_cobra_PO == 2 && target_attempts == NUM_COBRA_ITERATIONS) )
         break;

// Sanity check -- something is wrong. Population SpreadFactors used and only one chip in database?
      if ( target_attempts == SHP_ptr->num_required_PNDiffs )
         { printf("ERROR: KEK_Enroll(): Seed increment reached max value -- FAILED TO GET ENOUGH BITS!\n"); exit(EXIT_FAILURE); }

// Set PN reuse mode in hardware, start SRF engine and request additional SpreadFactors from server.
      do_server_SpreadFactors_next = 1;
      SetSRFReuseModeStartSRFRequestSpreadFactors(max_string_len, SHP_ptr, do_server_SpreadFactors_next, verifier_socket_desc);
      }

// ------------------------------------------------------------------
// Sanity check. PUF engine MUST be 'ready'
   if ( (*(SHP_ptr->DataRegA) & (1 << IN_SM_READY)) == 0 )
      { printf("ERROR: KEK_Enroll(): PUF Engine is NOT ready!\n"); exit(EXIT_FAILURE); }

// Tell server we are done.
   SendSpreadFactorsDone(max_string_len, SHP_ptr, verifier_socket_desc);

// Print the XMR HD if requested
   if ( SHP_ptr->DEBUG_FLAG == 1 )
      {
      char header_str[max_string_len];
      sprintf(header_str, "\n\tENROLL: XMR SHD (Bits %d)\n", current_XMR_SHD_num_bytes*8);
      PrintHeaderAndHexVals(header_str, current_XMR_SHD_num_bytes, *XMR_SHD_ptr, 32);
      }

// Print out the KEK key if requested. DO NOT PRINT OUT bytes beyond that which is allocated above. NOTE: If fewer are generated, than 
// they will be listed as zero's. DO NOT MOVE THIS DOWN. In some case, we NULL out the *key_ptr before returning.

// 9_18_2022: Timing tests for FSB KEK for SiRF paper. GenLLK from device_regeneration is called and then this routine.
// 9_18_2022: Taking this out temporarily for SiRF paper timing operation.
char header_str[max_string_len];
sprintf(header_str, "\n\tENROLL: FINAL KEK KEY: Requested Bits %d\tActual number of Bits %d\n", target_num_key_bytes*8, current_num_key_bits);
PrintHeaderAndHexVals(header_str, target_num_key_bytes, *key_ptr, 32);
printf("\tKEK_Enroll(): Total number of iterations %d\n\n", target_attempts);
fflush(stdout);
#ifdef DEBUG
#endif

// ==========================================================
// NOTE: SpreadFactor data is only saved for LLK. It is not stored for Session Key Gen and we do NOT save to KEK fields if doing 
// DeviceAuthentication Cobra.
   if ( LL_or_session_or_cobra_PO == 0 )
      {

// Print out SpreadFactors 
      if ( SHP_ptr->DEBUG_FLAG == 1 )
         {
         char header_str[max_string_len];
         sprintf(header_str, "\n\tENROLL: FINAL KEK SpreadFactors (bytes %d)\n", current_XSpreadFactors_num_words);
         PrintHeaderAndHexVals(header_str, current_XSpreadFactors_num_words*SF_WORDS_TO_BYTES_MULT, (unsigned char *)SpreadFactors_ptr, 32);
         }

// We need to keep the KEK vectors, masks and XOR_nonce for all regenerations (they are not re-transmitted by the server because 
// they are presumably stored in in NVM after enrollment). Store them into the KEK fields for regeneration. NOTE: KEK_final_SpreadFactors_enroll
// and KEK_final_XMR_SHD data is stored above and is not handled here.
      CopyToKEKFields(SHP_ptr);
      }

// ==========================================================
// If Session Key Gen or Cobra Device Authentication, then transmit XMR_SHD to server.
   if ( LL_or_session_or_cobra_PO == 1 || LL_or_session_or_cobra_PO == 2 )
      {
      if ( SockSendB(XMR_SHD, current_XMR_SHD_num_bytes, verifier_socket_desc) < 0 )
         { printf("ERROR: KEK_Enroll(): Send XMR_SHD failed\n"); exit(EXIT_FAILURE); }

// 10_17_2021: If Cobra Device Authentication, send device-computed SpreadFactors too. 10_17_2021: THIS USED TO BE DONE when set to 3 -- deleted this case.
// Currently we force PO mode, where we load pure PO from the server and send back non-pure PO computed here by the device b/c server does NOT 
// know which device is authenticating. 9_27_2022: Currently, looks like PopOnly is forced (no PCR) AND we set modify_PO to 1 (above) which means the
// device applied the (dist) bit flip operation. 
// Can we do PBD here, and eliminate SF altogether?
// 10_10_2022: UPDATE: FROM ZED experiments, I found my new metric for authentication in verifier_regen_funcs.c do NOT require FLIP, so THIS IS NOT NECESSARY.
//             THE SF from the server is UN-MODIFIED.
      if ( LL_or_session_or_cobra_PO == 2 )
         {
         if ( SockSendB((unsigned char *)SpreadFactors, target_attempts*SHP_ptr->num_SF_bytes, verifier_socket_desc) < 0 )
            { printf("ERROR: KEK_Enroll(): DeviceAuthentication Cobra: Send SpreadFactors failed\n"); exit(EXIT_FAILURE); }
         }

      if ( XMR_SHD != NULL )
         free(XMR_SHD);
      XMR_SHD = NULL;
      if ( SpreadFactors != NULL )
         free(SpreadFactors);
      SpreadFactors = NULL;
      }

// Free up the vectors and masks. We've copied the vectors, masks, XOR_nonce and SpreadFactors to dedicated 'KEK' fields above.
   FreeVectorsAndMasks(&(SHP_ptr->num_vecs), &(SHP_ptr->num_rise_vecs), &(SHP_ptr->first_vecs_b), &(SHP_ptr->second_vecs_b), &(SHP_ptr->masks_b));

   SHP_ptr->ctrl_mask = former_ctrl_mask;

// Reset to 'normal' values.
   SHP_ptr->XMR_val = XMR_VAL;
   SHP_ptr->param_RangeConstant = RANGE_CONSTANT; 

// HERE 11_6_2022: Wondering if I split the strong and weak regions in half that the COBRA PCCs get closer to 50%, instead of 30%.
//   SHP_ptr->param_Threshold = THRESHOLD_CONSTANT; 

   SHP_ptr->param_PCR_or_PBD_or_PO = prev_PCR_PBD_PO_mode;

// Default is 0 -- only COBRA, and possible PARCE, do scaling for device authentication.
   SHP_ptr->do_scaling = prev_do_scaling;

// Store the number of iterations needed to generate the KEK LLK.
   SHP_ptr->KEK_num_iterations = target_attempts;

   return current_XMR_SHD_num_bytes;
   }


// ========================================================================================================
// ========================================================================================================
// Basic process steps for regeneration:
//    1) Free up data structures storing information about previous regeneration.
//    2) Set KEK mode in hardware, and pop vs per-chip SpreadFactor param
//    3) Start MstCtrl state machine. 
//    3) Run CollectPNs using the vectors, path select masks, etc used earlier during enrollment
//    4) Loop over LFSR seed increments until key length is met.
//       a) Use existing XOR_nonce stored during enrollment to select parameters.
//       b) Run the SRF algorithm, ComputePNDiffs, TVComp, AddSpreadFactors
//       d) Fetch SHD and SBS from hardware BEFORE XMR is run. The SHD is ALL 1s so it is not useful and SBS is really the BS 
//          (raw bitstring generated WITHOUT thresholding) Store teh SBS for Special KEK mode. 
//       e) LOADs the enrollment XMR SHD and run FSB (KEK mode, regeneration) to generate XMR SBS (KEK key) from hardware.
//       f) Store the KEK key in SHP_ptr->KEK_final_regen_key. This allows it to be compared with the SHP_ptr->KEK_final_enroll_key
//          if it is available.
//       g) If we reach the target number of bits, exit, otherwise, set OUT_CP_REUSE_PNS_MODE mode in hardware and restart the SRF 
//          engine, go to 4).

int KEK_Regen(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int do_minority_bit_flip_analysis)
   {
   int also_do_transfer, load_or_unload, byte_or_word_data;
   int target_attempts, force_threshold_zero;
   int num_SBS_bits, regen_num_key_bits;

   int SBS_bit_cnt_valid, get_SHD_SBS_both, do_server_SpreadFactors_next;

   int former_ctrl_mask, current_function; 

   unsigned int target_num_key_bytes, current_num_key_bits;

   printf("\n\t\t\t******************* KEK BEGINS: REGEN  *******************\n");

// Save existing mask so we can restore on exit.
   former_ctrl_mask = SHP_ptr->ctrl_mask;

   current_function = FUNC_LL_REGEN;

// Set to the 'normal' XMR_VAL
   SHP_ptr->XMR_val = XMR_VAL;
   SHP_ptr->param_RangeConstant = RANGE_CONSTANT; 

// Load SF from storage, do NOT modify them.
   SHP_ptr->load_SF = 1;
   SHP_ptr->compute_PCR_PBD = 0;
   SHP_ptr->modify_PO = 0;
   SHP_ptr->dump_updated_SF = 0;

// Set hardware function "100"
   SHP_ptr->ctrl_mask = ((SHP_ptr->ctrl_mask | (1 << OUT_CP_KEK)) & ~(1 << OUT_CP_MODE1)) & ~(1 << OUT_CP_MODE0);

   if ( (SHP_ptr->KEK_target_num_key_bits % 8) == 0 )
      target_num_key_bytes = SHP_ptr->KEK_target_num_key_bits/8;
   else
      target_num_key_bytes = SHP_ptr->KEK_target_num_key_bits/8 + 1;

// Free storage of regeneration key if it exists.
   if ( SHP_ptr->KEK_final_regen_key != NULL )
      free(SHP_ptr->KEK_final_regen_key); 
   SHP_ptr->KEK_final_regen_key = NULL;

// Start the PUF engine.
   *(SHP_ptr->CtrlRegA) = SHP_ptr->ctrl_mask | (1 << OUT_CP_PUF_START); 
   *(SHP_ptr->CtrlRegA) = SHP_ptr->ctrl_mask;

// ASSUME the vectors are already available (not transmitted from verifier). These are stored in NVM on the device
// as part of the challenge. Set this global variable to prevent Ctrl-C from exiting while the SRF PUF is running.
   SAFE_TO_QUIT = 0;
   CollectPNs(max_string_len, SHP_ptr->num_POs, SHP_ptr->num_PIs, SHP_ptr->vec_chunk_size, SHP_ptr->max_generated_nonce_bytes, 
      SHP_ptr->CtrlRegA, SHP_ptr->DataRegA, SHP_ptr->ctrl_mask, SHP_ptr->KEK_num_vecs, SHP_ptr->KEK_num_rise_vecs, SHP_ptr->KEK_has_masks, 
      SHP_ptr->KEK_first_vecs_b, SHP_ptr->KEK_second_vecs_b, SHP_ptr->KEK_masks_b, SHP_ptr->device_n1, SHP_ptr->DUMP_BITSTRINGS, SHP_ptr->DEBUG_FLAG);
   SAFE_TO_QUIT = 1;

// Loop incrementing LFSR seeds until 'KEK_target_num_key_bits' is met
   target_attempts = 0;
   current_num_key_bits = 0;
   while (1)
      {

// Sanity check
      if ( target_attempts >= SHP_ptr->KEK_num_iterations )
         { printf("ERROR: KEK_Regen(): Program Error -- something went wrong! Number of target attempts exceeds number needed for enrollment!\n"); exit(EXIT_FAILURE); }

// 7_2_2022: This field is not used in KEK -- only authentication.
      SHP_ptr->num_KEK_authen_nonce_bits_remaining = 0;

// Select parameters based on the XOR_nonce and then transfer them into the hardware. When we do KEK regeneration, the hardware AUTOMATICALLY sets the 
// Threshold in the hardware to 0 despite what we send in via SelectSetParams.
      force_threshold_zero = 0;
      SelectSetParams(max_string_len, SHP_ptr->num_required_PNDiffs, SHP_ptr->CtrlRegA, SHP_ptr->DataRegA, SHP_ptr->ctrl_mask, 
         SHP_ptr->num_required_nonce_bytes, SHP_ptr->nonce_base_address, SHP_ptr->KEK_XOR_nonce, target_attempts, force_threshold_zero, 
         SHP_ptr->fix_params, SHP_ptr->param_RangeConstant, SHP_ptr->param_SpreadConstant, SHP_ptr->param_Threshold, SHP_ptr->param_TrimCodeConstant,
         SHP_ptr->MyScalingConstant, SHP_ptr->XMR_val, SHP_ptr->num_KEK_authen_nonce_bits_remaining, SHP_ptr->load_SF, SHP_ptr->compute_PCR_PBD, SHP_ptr->modify_PO, 
         SHP_ptr->dump_updated_SF, SHP_ptr->param_PCR_or_PBD_or_PO, current_function, &(SHP_ptr->param_LFSR_seed_low), &(SHP_ptr->param_LFSR_seed_high), 
         SHP_ptr->do_scaling, SHP_ptr->DEBUG_FLAG);

// Run the SRF 'full comp' component, PNDiff, GPEVCal, LoadSpreadFactors. 
      RunSRFEngine(max_string_len, SHP_ptr->num_SF_words, SHP_ptr->CtrlRegA, SHP_ptr->DataRegA, SHP_ptr->ctrl_mask, 
         (SHP_ptr->KEK_final_SpreadFactors_enroll + (target_attempts * SHP_ptr->num_required_PNDiffs)), SHP_ptr->iSpreadFactorScaler, 
         current_function, SHP_ptr->load_SF, SHP_ptr->dump_updated_SF, SHP_ptr->DEBUG_FLAG);

// Fetch from the hardware the device SHD (always num_required_PNDiffs/8 bytes). DO NOT TRANSFER TO verifier -- there can be NO interaction
// with verifier if vectors, masks, XOR_nonces and SpreadFactors are stored on the device. NOTE: This helper data is NOT needed -- it is returned
// because state machines in hardware assume we are doing authentication. Also note in the case of regeneration, the threshold is forced to 0
// so this helper data is ALL ONES. Fetch from the hardware the device SBS (variable in size -- not in increments of bytes). Also NOT needed.
// NOTE: the num of SBS bits reported by FetchTransSHD_SBS is NOT valid here so 0 is returned instead with 'SBS_bit_cnt_valid' set to 0.
      also_do_transfer = 0;
      SBS_bit_cnt_valid = 0;
      get_SHD_SBS_both = 2;
      FetchSendSHDAndSBS(max_string_len, SHP_ptr, SBS_bit_cnt_valid, also_do_transfer, get_SHD_SBS_both, &num_SBS_bits, -1);

// ========================
// 5_11_2021: DEBUG NOW: We store the raw bitstring (2048 bits) returned in device_BS (remember, the VHDL forces threshold to 0 during regeneration 
// so we get the raw bitstring with NO filtering. Also the device_SHD is ALL 1s here so no need to store it. 
      if ( do_minority_bit_flip_analysis == 1 )
         {
         if ( (SHP_ptr->KEK_BS_regen_arr = (unsigned char **)realloc(SHP_ptr->KEK_BS_regen_arr, sizeof(unsigned char *) * (target_attempts + 1))) == NULL )
            { printf("ERROR: KEK_Regen(): Allocation for 'KEK_BS_regen_arr' failed!\n"); exit(EXIT_FAILURE); }
         if ( (SHP_ptr->KEK_BS_regen_arr[target_attempts] = (unsigned char *)calloc(SHP_ptr->num_required_PNDiffs/8, sizeof(unsigned char))) == NULL )
            { printf("ERROR: KEK_Regen(): Allocation for 'KEK_BS_regen_arr[%d]' failed!\n", target_attempts); exit(EXIT_FAILURE); }

// Add the BS to array. We could create one large array here since the number of BS_regen bits is ALWAYS 2048, but we do it like this
// in KEK enrollment because the SBS_enroll_arr varies in size, so we do it here this way to just to be consistent. 
         int i;
         for ( i = 0; i < SHP_ptr->num_required_PNDiffs/8; i++ )
            SHP_ptr->KEK_BS_regen_arr[target_attempts][i] = SHP_ptr->device_SBS[i];
         }
// ========================

// Load XMR SHD helper data. Add 2048 bits (256 bytes) to the base address on each iteration to get the appropriate helper data.
      load_or_unload = 0;
      byte_or_word_data = 0;
      LoadUnloadBRAM(max_string_len, SHP_ptr->num_required_PNDiffs/8, SHP_ptr->CtrlRegA, SHP_ptr->DataRegA, SHP_ptr->ctrl_mask, 
         (SHP_ptr->KEK_final_XMR_SHD + (target_attempts * SHP_ptr->num_required_PNDiffs/8)), NULL, load_or_unload, byte_or_word_data, SHP_ptr->DEBUG_FLAG);

// ****************************************
// ***** RUN KEK FSB mode
      if ( SHP_ptr->DEBUG_FLAG == 1 )
         printf("KEK.2) Running KEK FSB mode (REGEN)\n\n");

// For KEK Regeneration, we now can fetch the KEK_SBS 
      also_do_transfer = 0;
      SBS_bit_cnt_valid = 1;
      get_SHD_SBS_both = 1;
      FetchSendSHDAndSBS(max_string_len, SHP_ptr, SBS_bit_cnt_valid, also_do_transfer, get_SHD_SBS_both, &regen_num_key_bits, -1);

// 3_14/2021: Changing this to utilize the last partial byte returned since it was a wasteful approach to discard it as we used to do here. We 
// use JoinBytePackedBitstrings to pack the bits from the new super strong XMR bits to the existing array. This routine re-allocates space 
// for KEK_final_enroll_key as needed. The return value is the sum of the (old) current_num_key_bits + (new) enroll_num_key_bits.
      current_num_key_bits = JoinBytePackedBitStrings(current_num_key_bits, &(SHP_ptr->KEK_final_regen_key), regen_num_key_bits, SHP_ptr->device_SBS);


// Break when we've reached the 'target_num_key_bytes'
      target_attempts++;
      if ( current_num_key_bits/8 >= target_num_key_bytes )
         break;

// Sanity check -- something is wrong. Population SpreadFactors used and only one chip in database?
      if ( target_attempts == SHP_ptr->num_required_PNDiffs )
         { printf("ERROR: KEK_Regen(): Seed increment reached max value -- FAILED TO GET ENOUGH BITS!\n"); exit(EXIT_FAILURE);; }

      do_server_SpreadFactors_next = 0;
      SetSRFReuseModeStartSRFRequestSpreadFactors(max_string_len, SHP_ptr, do_server_SpreadFactors_next, -1);
      }

// Sanity check. PUF engine MUST be 'ready'
   if ( (*(SHP_ptr->DataRegA) & (1 << IN_SM_READY)) == 0 )
      { printf("ERROR: KEK_Regen(): PUF Engine is NOT ready!\n"); exit(EXIT_FAILURE); }

// Print out the final bitstring if requested. DO NOT PRINT OUT bytes beyond that which is allocated above. NOTE: If fewer are
// generated, than they will be listed as zero's
//   if ( SHP_ptr->DUMP_BITSTRINGS == 1 )
      {
      char header_str[max_string_len];
      sprintf(header_str, "\n\tREGEN: FINAL KEK KEY: Requested Bits %d\tActual number of Bits %d\n", SHP_ptr->KEK_target_num_key_bits, current_num_key_bits);
      PrintHeaderAndHexVals(header_str, target_num_key_bytes, SHP_ptr->KEK_final_regen_key, 32);

      printf("\tKEK REGEN Total number of iterations %d\n\n", target_attempts);
      }
   fflush(stdout);

// 10_30_2021: Might need to comment this out b/c it assumes we run enrollment and then regeneration in the same run. Sanity check. 
   if ( SHP_ptr->KEK_num_iterations != target_attempts )
      { 
      printf("ERROR: Number of iterations during KEK enrollment %d MUST MATCH number during KEK regeneration %d\n", 
         SHP_ptr->KEK_num_iterations, target_attempts); exit(EXIT_FAILURE); 
      }

   SHP_ptr->ctrl_mask = former_ctrl_mask;

// Return value is meaningless. Note that there are actually at least this many bytes stored in the KEK_final_regen_key above -- there may
// in fact be a lot more with the last byte only partially filled.
   return target_num_key_bytes;
   }


// ========================================================================================================
// ========================================================================================================
// Session key validation function. Get verifier trial encryption text and compare with device's. 

int SessionKeyReport(int max_string_len, int verifier_socket_desc, SRFHardwareParamsStruct *SHP_ptr, int debug_flag)
   {
   unsigned char trial_plain_text[AES_INPUT_NUM_BYTES+1];
   unsigned char trial_encryption[AES_INPUT_NUM_BYTES+1];

   int verifier_text_num_bytes;
   int fail_or_pass;
   int i;

// Sanity check
   if ( SHP_ptr->SE_final_key == NULL )
      { printf("ERROR: SessionKeyReport(): SE_final_key is NULL!\n"); exit(EXIT_FAILURE); }

// Initialize
   for ( i = 0; i < AES_INPUT_NUM_BYTES+1; i++ )
      trial_encryption[i] = '\0';

// Get Verifier trial encryption text. 
   if ((verifier_text_num_bytes = SockGetB(trial_encryption, AES_INPUT_NUM_BYTES, verifier_socket_desc)) != AES_INPUT_NUM_BYTES )
      { printf("ERROR: SessionKeyReport(): Failed to get %d bytes of verifier encrypted text!\n", AES_INPUT_NUM_BYTES); exit(EXIT_FAILURE); }

// DEBUG: Dump out the values as hex
   if ( debug_flag == 1 )
      {
      char header_str[max_string_len];
      sprintf(header_str, "\n\tVerifier Trial Encryption (Bytes %d)\n", verifier_text_num_bytes);
      PrintHeaderAndHexVals(header_str, verifier_text_num_bytes, trial_encryption, 32);
      }

// 10_27_2021: Changed to 256-bit AES, CBC mode. Cyrus's wrapper.
   decrypt_256(SHP_ptr->SE_final_key, SHP_ptr->AES_IV, trial_encryption, AES_INPUT_NUM_BYTES, trial_plain_text);

// Make sure it is a string for compare below.
   trial_plain_text[AES_INPUT_NUM_BYTES] = '\0'; 

   printf("\n\t\t\t******************* SESSION ENCRYPTION RESULTS *******************\n\n");

   if ( strcmp((char *)trial_plain_text, "HELLO WORLD!") == 0 )
      {
      printf("SE SUCCESS: Decrypted text matches 'HELLO WORLD!' *************\n\n"); fflush(stdout);
      fail_or_pass = 1;
      }
   else
      {
      printf("SE FAILED: Decrypted text does NOT match 'HELLO WORLD! *************\n\n"); fflush(stdout);
      fail_or_pass = 0;
      }

   return fail_or_pass;
   }


// ========================================================================================================
// ========================================================================================================
// Session key generation. Note this is also used by DeviceAuthentication when DO_COBRA is set to 1.

int KEK_SessionKeyGen(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int verifier_socket_desc, 
   int session_or_DA_cobra)
   {
   int LL_or_session_or_cobra_PO;
   int fail_or_pass;

   struct timeval t0, t1;
   long elapsed; 

   if ( session_or_DA_cobra == 0 )
      printf("\n\t\t\t************************ SESSION KEY GEN BEGINS ******************************\n");
   else
      printf("\n\t\t\t******************* DEVICE COBRA AUTHENTICATION BEGINS  *******************\n");
   fflush(stdout);

// Set the flag for calling KEK_Enroll. It carries out one of three functions, LLK, SessionKey and Cobra.
   if ( session_or_DA_cobra == 0 )
      LL_or_session_or_cobra_PO = 1;
   else
      LL_or_session_or_cobra_PO = 2;

// Run KEK enrollment mode.
   if ( KEK_Enroll(max_string_len, SHP_ptr, LL_or_session_or_cobra_PO, verifier_socket_desc) == 0 )
      return 0;

// Get server trial encryption and compare for validation. DO NOT PRINT OUT MORE THAN target_num_key_bits. 
   if ( session_or_DA_cobra == 0 )
      {
      fail_or_pass = SessionKeyReport(max_string_len, verifier_socket_desc, SHP_ptr, SHP_ptr->DEBUG_FLAG);

// ****************************************
// ***** The verifier will wait before closing the socket for this string.
      if ( SHP_ptr->DEBUG_FLAG == 1 )
         {
         if ( fail_or_pass == 0 )
            printf("\tSending 'FAIL'\n");
         else
            printf("\tSending 'PASS'\n");
         gettimeofday(&t0, 0);
         }
      if ( fail_or_pass == 0 )
         {
         if ( SockSendB((unsigned char *)"FAIL", strlen("FAIL")+1, verifier_socket_desc) < 0 )
            { printf("ERROR: KEK_SessionKeyGen(): Send 'FAIL' request failed\n"); exit(EXIT_FAILURE); }
         }
      else
         {
         if ( SockSendB((unsigned char *)"PASS", strlen("PASS")+1, verifier_socket_desc) < 0 )
            { printf("ERROR: KEK_SessionKeyGen(): Send 'PASS' request failed\n"); exit(EXIT_FAILURE); }
         }
      if ( SHP_ptr->DEBUG_FLAG == 1 )
         { gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec; printf("\tElapsed %ld us\n\n", (long)elapsed); }
      fflush(stdout);
      return fail_or_pass;
      }

// Do last component of DeviceAuthentication, message exchange with the server.
   else
      return DA_Report(max_string_len, SHP_ptr, verifier_socket_desc);
   }


// ========================================================================================================
// ========================================================================================================
// TRNG runs the TRNG algorithm and either returns random numbers to this C program (FUNC_EXT_TRNG mode) or
// stores the low-order 4 bits of the random numbers in the TRNG block of BRAM (FUNC_INT_TRNG mode).

int TRNG(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int int_or_ext_mode, int load_seed,
   int store_nonce_num_bytes, unsigned char *nonce_arr)
   {
   volatile unsigned int *CtrlRegA, *DataRegA;
   unsigned int ctrl_mask;
   int current_function; 

//   struct timeval t0, t1;
//   long elapsed; 

// Copy existing mask locally so we can modify it and later restore using the original. 

   ctrl_mask = SHP_ptr->ctrl_mask;
   CtrlRegA = SHP_ptr->CtrlRegA; 
   DataRegA = SHP_ptr->DataRegA;

// Do NOT load SF, but carry out mode 1 (PBD) component of AddSpreadFactors in hardware. NOT NEEDED -- TRNG.v sets these
// directly and invokes MstCtrl, e.g., there is NO call to SelectSetParams here.
   SHP_ptr->load_SF = 0;
   SHP_ptr->compute_PCR_PBD = 1;
   SHP_ptr->modify_PO = 0;
   SHP_ptr->dump_updated_SF = 0;

   if ( int_or_ext_mode != FUNC_INT_TRNG && int_or_ext_mode != FUNC_EXT_TRNG )
      { printf("ERROR: TRNG: Mode must be Internal or External Mode!\n"); exit(EXIT_FAILURE); }

// printf("ctrl_mask %08X\n", ctrl_mask); fflush(stdout);

// Set hardware function.  Internal TRNG is "101". NOTE: We can only ever FILL UP 20 * 128 = 2560 16-bit words of 
// memory (basically what we get out of MODE_EXT_TRNG per run). So if the internal requirement ever get larger than 
// this, then you need to adjust the TRNG.vhd file.
   if ( int_or_ext_mode == FUNC_INT_TRNG )
      {

      printf("\n\t\t\t******************* TRNG INTERNAL BEGINS  ******************* \n");

      ctrl_mask = ((ctrl_mask | (1 << OUT_CP_KEK)) & ~(1 << OUT_CP_MODE1)) | (1 << OUT_CP_MODE0);
      current_function = FUNC_INT_TRNG;
      }

// External TRNG is "110" 
   else
      {

      printf("\n\t\t\t******************* TRNG EXTERNAL BEGINS  ******************* \n");

      ctrl_mask = ((ctrl_mask | (1 << OUT_CP_KEK)) | (1 << OUT_CP_MODE1)) & ~(1 << OUT_CP_MODE0);
      current_function = FUNC_EXT_TRNG;
      }

// Force number of samples to 1.
   ctrl_mask = (ctrl_mask & ~(1 << OUT_CP_NUM_SAM1)) & ~(1 << OUT_CP_NUM_SAM0);

// Load 16-bit LFSR seed. We must load it by doing a reset. We also do this at startup so probably no need to do it here. Subsequent
// calls will use the existing state of the LFSR register in the PL side as a starting point.
//
// 1_23_2022: NOTE: I use low order bits of GPIO[3:0] for the TimingDivisor, and GPIO[15:8] as LFSR seed.
//   if ( load_seed == 1 )
//      {
//      *CtrlRegA = ctrl_mask | (1 << OUT_CP_RESET) | (unsigned int)(0x0000FF00 & ((unsigned char)SHP_ptr->TRNG_LFSR_seed < 8));
//      *CtrlRegA = ctrl_mask;
//      }

// Sanity check. PUF engine MUST be 'ready'
   if ( (*DataRegA & (1 << IN_SM_READY)) == 0 )
      { printf("ERROR: TRNG(): PUF Engine is NOT ready!\n"); exit(EXIT_FAILURE); }

// Start the PUF engine.
   *CtrlRegA = ctrl_mask | (1 << OUT_CP_PUF_START); 
   *CtrlRegA = ctrl_mask;

// =========================================================================================================================================
// If running the TRNG in external mode, fetch the SBS, which is a random bitstring of length 256 bytes. Currently, the total number of
// iterations here per call to the external TRNG is set to 20 * 256 bytes (2048 bits) = 5120 bytes.
   if ( current_function == FUNC_EXT_TRNG )
      {
      int load_or_unload, byte_or_word_data;
      int i;

// If SRF does NOT return to idle, then we need to fetch more nonces.
      int num_bytes = 0;
      while ( (*DataRegA & (1 << IN_SM_READY)) == 0 )
         {
         load_or_unload = 1;
         byte_or_word_data = 0;
         LoadUnloadBRAM(max_string_len, SHP_ptr->num_required_PNDiffs/8, CtrlRegA, DataRegA, ctrl_mask, SHP_ptr->device_SBS, 
            NULL, load_or_unload, byte_or_word_data, 0);

// Compute frequency static
#ifdef DEBUG
for ( i = 0; i < SHP_ptr->num_required_PNDiffs/8; i++ )
   printf("%02X", SHP_ptr->device_SBS[i]); 
printf("\n"); 
#endif

#ifdef DEBUG
char temp_char;
int k;
for ( i = 0; i < SHP_ptr->num_required_PNDiffs/8; i++ )
   {
   temp_char = SHP_ptr->device_SBS[i];
   for ( k = 0; k < 8; k++ )
      {
      if ( (temp_char % 2) == 1 )
         (SHP_ptr->num_ones)++; 
      temp_char /= 2;
      }
   if ( temp_char != 0 )
      { printf("ERROR: Expected temp_char to be 0!\n"); exit(EXIT_FAILURE); }
   }
SHP_ptr->total_bits += SHP_ptr->num_required_PNDiffs;
printf("\tExternal TRNG: %5d) Total ones %8d\tTotal bits %8d\tFreq %6.2f\n", SHP_ptr->iteration, SHP_ptr->num_ones, SHP_ptr->total_bits, 
   (float)SHP_ptr->num_ones/(float)SHP_ptr->total_bits*100.0); fflush(stdout);
(SHP_ptr->iteration)++;
#endif

#ifdef DEBUG
PrintHeaderAndHexVals("Random Bitstring\n", SHP_ptr->num_required_PNDiffs/8, SHP_ptr->device_SBS, 32);
#endif

// Store first (of several?) chunk of external TRNG bytes in array if requested. NOTE: nonce_arr is NULL when store_nonce_num_bytes is 0.
         for ( i = 0; num_bytes < store_nonce_num_bytes && i < SHP_ptr->num_required_PNDiffs/8; num_bytes++, i++ )
            nonce_arr[num_bytes] = SHP_ptr->device_SBS[i];

// Once copied, zero out nonce array for possible next iteration -- don't want repeated nonce bytes if TRNG doesn't fill up the array
// (which I'm pretty sure it does EVERY time so no need for this really).
         for ( i = 0; i < SHP_ptr->num_required_PNDiffs/8; i++ )
            nonce_arr[num_bytes] = 0;
         }
      }

// =========================================================================================================================================
// Note that there is NO interaction with the C program (normally) when FUNC_INT_TRNG is run but we must know when it completes. 
   else
      {

// Need to wait for READY here.
      while ( (*DataRegA & (1 << IN_SM_READY)) == 0 )
         {
         usleep(100000);
         if ( ((*DataRegA) & (1 << IN_PARAM_ERR)) != 0 )
            { printf("ERROR: TRNG(): Parameter error in hardware!\n"); exit(EXIT_FAILURE); }
//         printf("TRNG(): Internal: Waiting for TRNG to finish!\n"); fflush(stdout);
         }

#ifdef DEBUG
printf("INT TRNG DONE!\n"); fflush(stdout);
#endif
      }

// Restore CtrlRegA contents (number of samples).
   *CtrlRegA = SHP_ptr->ctrl_mask;

   return 0;
   }


// ========================================================================================================
// ========================================================================================================
// KEK-based authentication and session key generation functions. 

int KEK_ClientServerAuthen(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int verifier_socket_desc)
   {
   int retries;

struct timeval t1, t2;
long elapsed; 
gettimeofday(&t2, 0);
#ifdef DEBUG
#endif

// Tell server the mode to use.
   if ( SockSendB((unsigned char *)"SKE", strlen("SKE")+1, verifier_socket_desc) < 0 )
      { printf("ERROR: KEK_ClientServerAuthen(): Send 'SKE' request failed\n"); exit(EXIT_FAILURE); }

   retries = 0;
   while ( retries < MAX_DA_RETRIES )
      {
      if ( KEK_DeviceAuthentication_SKE(max_string_len, SHP_ptr, verifier_socket_desc) == 1 )
         break;

      retries++; 
      }

   if ( retries == MAX_DA_RETRIES )
      { 
      printf("KEK_ClientServerAuthenKeyGen(): Server FAILED SKE authentication device with %d retries!\n", MAX_DA_RETRIES); fflush(stdout); 
      return 0;
      }

gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t2.tv_sec)*1000000 + t1.tv_usec-t2.tv_usec; printf("\tElapsed: DEVICE AUTHENTICATION %ld us\n\n", (long)elapsed);
#ifdef DEBUG
#endif

   return 1;
   }


// ========================================================================================================
// ========================================================================================================
// KEK-based authentication and session key generation functions. 

int KEK_ClientServerAuthenKeyGen(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int verifier_socket_desc, 
   int gen_session_key)
   {

struct timeval t1, t2;
long elapsed; 
gettimeofday(&t2, 0);
#ifdef DEBUG
#endif

// NOTE: You MUST run TRNG when using PCR mode otherwise all stored random SpreadFactors are zero in the BRAM. PCR applies server computed 
// Population Offsets, and then computes PerChip Offsets. If the Random Offsets are ALL 0, then when 3 is subtracted from the PerChip 
// values, ALL bits become weak and KEK enroll fails to generate a bitstring (ZERO BITS). NOTE: Both SpreadFactor_modes, PCR and PBD, 
// REQUIRE nonces. Note: We load the 16-bit seed into the low-order 16-bits of the 64-bit LFSR specified on RESET. Subsequent iterations 
// will use the existing value of the 64-bit LFSR.
   gettimeofday(&t2, 0);
   int load_seed = 0;
   TRNG(max_string_len, SHP_ptr, FUNC_INT_TRNG, load_seed, 0, NULL);
   gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t2.tv_sec)*1000000 + t1.tv_usec-t2.tv_usec; printf("\tTOTAL EXEC TIME %ld us\n\n", (long)elapsed);

// =========================================
// KEK SKE mode DeviceAuthentication

   if ( KEK_ClientServerAuthen(max_string_len, SHP_ptr, verifier_socket_desc) == 0 )
      return 0;

// =========================================
// KEK VerifierAuthentication
gettimeofday(&t2, 0);
#ifdef DEBUG
#endif

   if ( KEK_VerifierAuthentication(max_string_len, SHP_ptr, verifier_socket_desc) == 0 )
      return 0;

gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t2.tv_sec)*1000000 + t1.tv_usec-t2.tv_usec; printf("\tElapsed: VERIFIER AUTHENTICATION %ld us\n\n", (long)elapsed);
#ifdef DEBUG
#endif

// =========================================
   if ( gen_session_key == 1 )
      {

gettimeofday(&t2, 0);
#ifdef DEBUG
#endif

// Session Key Gen simply calls KEK Enroll to generate the session key and then tests the key to sure it is the same on both side. NOTE: We do not 
// store challenge information for session key generation, so we can NEVER regenerate a session key (there is NOT regeneration function like there 
// is for KEK key with KEK Regeneration). 
      int session_or_DA_cobra = 0;
      if ( KEK_SessionKeyGen(max_string_len, SHP_ptr, verifier_socket_desc, session_or_DA_cobra) == 0 )
         return 0;

gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t2.tv_sec)*1000000 + t1.tv_usec-t2.tv_usec; printf("\tElapsed: SESSION KEY GEN %ld us\n\n", (long)elapsed);
#ifdef DEBUG
#endif
      }

   return 1;
   }


// ========================================================================================================
// ========================================================================================================
// Generate the KEK long-lived KEK, either by running KEK_Enroll by communicating with the server to get 
// challenges (if no Chlng info exists in the AuthenticationToken.db), or by reading out the LLK Chlng information 
// and running KEK_Regen. Called by both the device and TTP during startup for generating the LLK for ZeroTrust
// and for generating the LLK for AliceWithdrawal process.

int GenLLK(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int open_socket, char *Bank_IP, int port_number,
   int Bank_socket_desc, int allow_multiple_LLK, int LLK_type, int LLK_num_bytes)
   {
   unsigned char mask[2];
   int Chlng_index = 0;

   unsigned char *Chlng_blob = NULL;
   int Chlng_blob_num_bytes;

   int do_minority_bit_flip_analysis = 0;

// Include chip_num, (skip LLK_num_bytes and LLK), v_a, XOR_nonce, num_iterations, XHD and SF.
   mask[0] = 0xF9;
   mask[1] = 0x00;

// Sanity check.
   if ( LLK_type != 2 )
      { printf("ERROR: GenLLK(): LLK_type must be 2: %d\n", LLK_type); exit(EXIT_FAILURE); }

// Free the existing LLK if it exists.
   if ( LLK_type == 2 && SHP_ptr->ZeroTrust_LLK != NULL )
      free(SHP_ptr->ZeroTrust_LLK); 

// Check the database for KEK long-lived key. If it exists, then use it to generate PT_LLK, otherwise fetch challenges
// from the IA (Bank) and store them. Use the newer DB_ChallengeGen_seed method, i.e., get the Chlng DB seed from 
// the server and NOT the challenges themselves. 11_18_2021: Switching over to using the Challenge DB to store the 
// KEK LLK
   int prev_udc = SHP_ptr->use_database_chlngs;
   SHP_ptr->use_database_chlngs = 1;

// Get the server's unique ID (chip_num) if we have stored the KEK LLK challenges from a previous run of this program 
// in the database. If no LLK records exist, PUFCashGetLLKChlngInfo returns 0. PUFCashGetLLKChlngInfo allocates space 
// for the Chlng_blob. 
   int check_exists_only = 0;
   if ( PUFCashGetLLKChlngInfo(max_string_len, SHP_ptr->DB_PUFCash_V3, &(SHP_ptr->chip_num), &(SHP_ptr->anon_chip_num), 
      &Chlng_blob, &Chlng_blob_num_bytes, allow_multiple_LLK, &Chlng_index, LLK_type, check_exists_only, mask) == 1 )
      {

#ifdef DEBUG
printf("GenLLK(): Called GenLLK() and FOUND a KEK Chlng_blob. Also fetched chip_num %d from DB. Running KEK_Regen!\n", 
   SHP_ptr->chip_num); fflush(stdout);
#endif

// Extract the parameters using the mask. NOTE: Only parameters specified by the mask will be modified. 
      int chip_num_blob;
      ExtractChlngPacket(max_string_len, SHP_ptr->num_required_nonce_bytes, SHP_ptr->num_required_PNDiffs,
         SHP_ptr->num_SF_bytes, Chlng_blob, Chlng_blob_num_bytes, &chip_num_blob, 0, NULL, &(SHP_ptr->DB_ChallengeGen_seed), 
         &(SHP_ptr->KEK_XOR_nonce), &(SHP_ptr->KEK_num_iterations), &(SHP_ptr->KEK_final_XMR_SHD), 
         &(SHP_ptr->KEK_final_SpreadFactors_enroll), mask);

// Sanity check
      if ( chip_num_blob != SHP_ptr->chip_num )
         { 
         printf("ERROR: GenLLK(): Expected Chlng_blob chip_num %d to be the same as the DB chip_num %d\n", 
            chip_num_blob, SHP_ptr->chip_num); exit(EXIT_FAILURE); 
         }

// Free the previous challenge information if these fields are non-NULL
      FreeVectorsAndMasks(&(SHP_ptr->KEK_num_vecs), &(SHP_ptr->KEK_num_rise_vecs), &(SHP_ptr->KEK_first_vecs_b), 
         &(SHP_ptr->KEK_second_vecs_b), &(SHP_ptr->KEK_masks_b));

// Re-generate the challenge based on the stored DB_ChallengeGen_seed.
      int send_GO_request = 0;
      int gen_or_use_challenge_seed = 1;
      SHP_ptr->KEK_num_vecs = GoGetVectors(max_string_len, SHP_ptr->num_POs, SHP_ptr->num_PIs, 0, &(SHP_ptr->KEK_num_rise_vecs),
         &(SHP_ptr->KEK_has_masks), &(SHP_ptr->KEK_first_vecs_b), &(SHP_ptr->KEK_second_vecs_b), &(SHP_ptr->KEK_masks_b), send_GO_request, 
         SHP_ptr->use_database_chlngs, SHP_ptr->DB_Challenges, SHP_ptr->DB_design_index, SHP_ptr->DB_ChallengeSetName, gen_or_use_challenge_seed,
         &(SHP_ptr->DB_ChallengeGen_seed), SHP_ptr->GenChallenge_mutex_ptr, SHP_ptr->DEBUG_FLAG);

// Run KEK regeneration
      KEK_Regen(max_string_len, SHP_ptr, do_minority_bit_flip_analysis);

// Move this key to LLK SHP structure field for safe keeping. KEK_enroll/regen is called by other functions in this code
// so KEK_final_enroll_key/KEK_final_regen_key structure fields are not safe to keep this key there.
      if ( LLK_type == 2 )
         SHP_ptr->ZeroTrust_LLK = SHP_ptr->KEK_final_regen_key;

      SHP_ptr->KEK_final_regen_key = NULL;
      }

// Else get challenges from IA (Bank), store them in the MakeAuthenication database and generate the LLK (run KEK FSB Enroll).
// Store zeros for the database LLK. 
   else
      {

// Here, we first mutually authenticate with Bank and generate a session key.
      int provision_or_replace = 1;

// YOU MUST call TRNG because KEK long-lived key generation (LL) function generates it's own PCR SF. You will get ALL "FF" for SBS
// if you do NOT call TRNG.
      TRNG(max_string_len, SHP_ptr, FUNC_INT_TRNG, 0, 0, NULL);
      GetKEKChlngInfoProvisionOrReplace(max_string_len, SHP_ptr, Bank_IP, port_number, Bank_socket_desc, provision_or_replace, open_socket);

// Add the KEK challenge information to the DB. If allow_only_one is 1, then any existing element is deleted. NOTE: This will NEVER
// delete an existing element because we call PUFCashGetLLKChlngInfo above and it returns 1 if an element exists, which is handled in the
// 'if stmt' branch above.
      int allow_only_one = 1;
      int check_size = 1;

// Wait until AFTER GetKEKChlngInfoProvisionOrReplace(). 
// Include chip_num, (skip LLK_num_bytes and LLK), v_a, XOR_nonce, num_iterations, XHD and SF.
      Chlng_blob_num_bytes = ComputeChlngPacketSize(max_string_len, SHP_ptr->num_required_nonce_bytes, SHP_ptr->num_required_PNDiffs,
         SHP_ptr->num_SF_bytes, SHP_ptr->KEK_LLK_num_bytes, SHP_ptr->KEK_num_iterations, mask);

      Chlng_blob = Allocate1DUnsignedChar(Chlng_blob_num_bytes);

// Construct a Chlng_blob 
      AssembleChlngPacket(max_string_len, SHP_ptr->num_required_nonce_bytes, SHP_ptr->num_required_PNDiffs, SHP_ptr->num_SF_bytes, 
         Chlng_blob, Chlng_blob_num_bytes, SHP_ptr->chip_num, 0, NULL, SHP_ptr->DB_ChallengeGen_seed, SHP_ptr->KEK_XOR_nonce, 
         SHP_ptr->KEK_num_iterations, SHP_ptr->KEK_final_XMR_SHD, SHP_ptr->KEK_final_SpreadFactors_enroll, mask, check_size);

// Store it in the DB.
      Chlng_index = PUFCashAddLLKChlngInfo(max_string_len, SHP_ptr->DB_PUFCash_V3, SHP_ptr->chip_num, SHP_ptr->anon_chip_num, 
         Chlng_blob, Chlng_blob_num_bytes, mask, LLK_type, allow_only_one);

// A one time save here.
      if ( LoadOrSaveDb(SHP_ptr->DB_PUFCash_V3, SHP_ptr->DB_name_PUFCash_V3, 1) != 0 )
         { 
         printf("GenLLK(): Failed to store 'in memory' database to %s: %s\n", SHP_ptr->DB_name_PUFCash_V3, sqlite3_errmsg(SHP_ptr->DB_PUFCash_V3)); 
         sqlite3_close(SHP_ptr->DB_PUFCash_V3); exit(EXIT_FAILURE); 
         }

// Move this key to LLK SHP structure field for safe keeping. KEK_enroll/regen is called by other functions in this code
// so KEK_final_enroll_key/KEK_final_regen_key structure fields are not safe to keep this key there.
      if ( LLK_type == 2 )
         SHP_ptr->ZeroTrust_LLK = SHP_ptr->KEK_final_enroll_key;

      SHP_ptr->KEK_final_enroll_key = NULL;
      }
   SHP_ptr->use_database_chlngs = prev_udc;

   if ( Chlng_blob != NULL )
      free(Chlng_blob); 

// Sanity check
   if ( LLK_type == 2 && SHP_ptr->ZeroTrust_LLK == NULL )
      { printf("GenLLK(): FAILED to generate a ZeroTrust_LLK!\n"); exit(EXIT_FAILURE); }

   return Chlng_index;
   }


// ========================================================================================================
// ========================================================================================================
// ZeroTrust_Enroll carries out the customer/TTP portion of the ZeroTrust Enrollment process, which is done
// at startup, and later as needed. Here, Alice/TTP generates Authentication Tokens that consist of a 
// keyed-hash of ZeroTrust_LLK + nonce (ZHK_A_nonce). This information is transmitted to IA (the Bank or 
// server or verifier). The Bank validates it and then stores it in its ZeroTrust database table. 
//
// The zero_trust_LLK_index is the index of the ZeroTrust_LLK element in the PUFCash_LLK database (type 2). 
// It is sent to the Bank as an ID for the challenge that was used by Alice to generate the AT.

void ZeroTrust_Enroll(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, char *Bank_IP, int port_number,
   int zero_trust_LLK_index, int is_TTP, int Bank_socket_desc, unsigned char *session_key)
   {

#ifdef DEBUG
struct timeval t0, t1, t2;
long long elapsed; 
gettimeofday(&t0, 0);
gettimeofday(&t2, 0);
#endif

#ifdef DEBUG
printf("\n\nZeroTrust_Enroll(): CALLED!\n"); fflush(stdout);
#endif

// Sanity check. Alice's LLK MUST have been already generated.
   if ( SHP_ptr->ZeroTrust_LLK == NULL )
      { printf("ZeroTrust_Enroll(): FAILED to generate a ZeroTrust_LLK!\n"); exit(EXIT_FAILURE); }

// Sanity checks. Basically everything is 256 bits.
   if ( HASH_IN_LEN_BITS != SHP_ptr->KEK_target_num_key_bits || HASH_OUT_LEN_BITS != SHP_ptr->KEK_target_num_key_bits )
      { 
      printf("ERROR: ZeroTrust_Enroll(): HASH_IN_LEN_BITS %d MUST be equal to HASH_OUT_LEN_BIT %d MUST be equal to KEK_target_num_key_bits %d\n", 
         HASH_IN_LEN_BITS, HASH_OUT_LEN_BITS, SHP_ptr->KEK_target_num_key_bits/8); exit(EXIT_FAILURE); 
      }

   if ( SHP_ptr->SE_target_num_key_bits != SHP_ptr->KEK_target_num_key_bits )
      { 
      printf("ERROR: ZeroTrust_Enroll(): SE_target_num_key_bits %d MUST be equal to KEK_target_num_key_bits %d\n", 
         SHP_ptr->SE_target_num_key_bits, SHP_ptr->KEK_target_num_key_bits/8); exit(EXIT_FAILURE); 
      }

// ********************************************************************************************************************
// *** ZeroTrust Enroll PART I: Mutually authenticate with IA (Bank), and generate session key. NOTE: If the TTP
// calls this, we have have a socket connection open and have ALREADY authenticated with the Bank.

// Open up a socket connection to IA if we are a customer or TTP.
   if ( is_TTP == 0 )
      {
      while ( OpenSocketClient(max_string_len, Bank_IP, port_number, &Bank_socket_desc) < 0 )
         { 
         printf("INFO: ZeroTrust_Enroll(): Waiting to connect to Bank for authentication and session key gen!\n"); fflush(stdout); 
         usleep(200000);
         }
      }

   if ( SockSendB((unsigned char *)"ZERO-TRUST-ENROLL", strlen("ZERO-TRUST-ENROLL") + 1, Bank_socket_desc) < 0 )
      { printf("ERROR: ZeroTrust_Enroll(): Failed to send 'ZERO-TRUST-ENROLL' to Bank!\n"); exit(EXIT_FAILURE); }

// Mutually authenticate and generate a session key. KEK_Enroll is also used to generate the session key. 
   if ( is_TTP == 0 )
      {
      int gen_session_key = 1;
      KEK_ClientServerAuthenKeyGen(max_string_len, SHP_ptr, Bank_socket_desc, gen_session_key);

      session_key = SHP_ptr->SE_final_key;
      SHP_ptr->SE_final_key = NULL;
      }

// ********************************************************************************************************************
// *** ZeroTrust Enroll PART II: Generate Alice's ZeroTrust Authentication Tokens. These are just her ZeroTrust_LLK XOR'ed with
//                               a set of TRNG PUF-based nonces, which are then hashed (keyed-hash) 

// Get the number of ATs to generate from the server. 
   char request_str[max_string_len];
   int num_ATs_to_generate;

   if ( SockGetB((unsigned char *)request_str, max_string_len, Bank_socket_desc) < 0 )
      { printf("ERROR: ZeroTrust_Enroll(): Failed to get 'num_ATs_to_generate' string from IA!\n"); exit(EXIT_FAILURE); }
   sscanf(request_str, "%d", &num_ATs_to_generate);

#ifdef DEBUG
printf("\tZeroTrust_Enroll(): GENERATING %d ATs!\n", num_ATs_to_generate); fflush(stdout);
#endif


#ifdef DEBUG
printf("\tZeroTrust_Enroll(): Sending IA LLK Chlng number (ZeroTrust_LLK that is used to generate AT)!\n"); fflush(stdout);
#endif
   sprintf(request_str, "%d", zero_trust_LLK_index);
   if ( SockSendB((unsigned char *)request_str, strlen(request_str) + 1, Bank_socket_desc) < 0 )
      { printf("ERROR: ZeroTrust_Enroll(): Failed to send IA 'zero_trust_LLK_num' (Chlng_num) string!\n"); exit(EXIT_FAILURE); }

// ZHK_A_num_bytes is set to SE_TARGET_NUM_KEY_BITS/8, but this MUST be equal to KEK_TARGET_NUM_KEY_BITS/8
   int ZHK_A_num_bytes = SHP_ptr->ZHK_A_num_bytes;

#ifdef DEBUG
printf("\t\tZeroTrust_Enroll(): ZHK_A_num_bytes %d\n", ZHK_A_num_bytes); fflush(stdout);
#endif

// Requires two iterations of aes since AES_INPUT_NUM_BYTES IS 16 and ZHK_A_num_bytes is 32. If not, we need to adjust 
// ZHK_A_num_bytes and pad.
   if ( (ZHK_A_num_bytes % AES_INPUT_NUM_BYTES) != 0 )
      { 
      printf("ERROR: ZeroTrust_Enroll(): ZHK_A_num_bytes %d must be a multiple of AES input size %d -- FIX ME!\n", 
         ZHK_A_num_bytes, AES_INPUT_NUM_BYTES); exit(EXIT_FAILURE); 
      }

// With each call to external TRNG, we get 20 * 256 bytes (2048 bits) = 5120 nonce bytes.
   unsigned char *nonce_buffer = Allocate1DUnsignedChar(MAX_EXT_TRNG_NUM_BYTES); 

// Allocate space for the hash input and output
   unsigned char *hash_input = Allocate1DUnsignedChar(ZHK_A_num_bytes);
   unsigned char *hash_output = Allocate1DUnsignedChar(ZHK_A_num_bytes);
   unsigned char *nonce = Allocate1DUnsignedChar(ZHK_A_num_bytes);

   unsigned char *ZHK_A_nonce_enc = Allocate1DUnsignedChar(ZHK_A_num_bytes);
   unsigned char *nonce_enc = Allocate1DUnsignedChar(ZHK_A_num_bytes);


// ============================================
// Main loop, create AT which are (LLK XOR nonce). Loop until we have generated all of the requested ATs.
   int AT_num;
   int load_seed = 0;
   int nonce_byte_pos = 0;
   int ciphertext_len_bytes;
   for ( AT_num = 0; AT_num < num_ATs_to_generate; AT_num++ )
      {

#ifdef DEBUG
printf("\t\tZeroTrust_Enroll(): Generating AT %d\n", AT_num); fflush(stdout);
#endif

// Call the SiRF External TRNG. Each n_x is 256 bits or 32 bytes (the same size as the KEK LLK size), so total number 
// of ZeroTrust ATs that can be generated per call of the external TRNG is 5120/32 = 160.
      if ( AT_num == 0 || ((AT_num+1) * ZHK_A_num_bytes) > MAX_EXT_TRNG_NUM_BYTES )
         {

#ifdef DEBUG
printf("\t\tZeroTrust_Enroll(): Calling External TRNG!\n"); fflush(stdout);
#endif

         TRNG(max_string_len, SHP_ptr, FUNC_EXT_TRNG, load_seed, MAX_EXT_TRNG_NUM_BYTES, nonce_buffer);
         nonce_byte_pos = 0;
         }

#ifdef DEBUG
PrintHeaderAndHexVals("ZeroTrust_Enroll(): LLK:\n", ZHK_A_num_bytes, SHP_ptr->ZeroTrust_LLK, 32);
#endif

// Compute (LLK XOR nonce)
      int byte_num;
      for ( byte_num = 0; byte_num < ZHK_A_num_bytes; byte_num++, nonce_byte_pos++ )
         {
         if ( nonce_byte_pos >= MAX_EXT_TRNG_NUM_BYTES )
            { 
            printf("ERROR: ZeroTrust_Enroll(): nonce_byte_pos %d beyond those available %d\n", 
               nonce_byte_pos, MAX_EXT_TRNG_NUM_BYTES); exit(EXIT_FAILURE);
            }

#ifdef DEBUG
printf("\t\tZeroTrust_Enroll(): Processing byte_num %d\tnonce_byte_pos %d!\n", byte_num, nonce_byte_pos); fflush(stdout);
#endif

// Need to encrypt and send this too to IA below.
         nonce[byte_num] = nonce_buffer[nonce_byte_pos];
         hash_input[byte_num] = SHP_ptr->ZeroTrust_LLK[byte_num] ^ nonce_buffer[nonce_byte_pos];
         }

#ifdef DEBUG
printf("\t\tZeroTrust_Enroll(): Hashing!\n"); fflush(stdout);
#endif

// Hash it
      hash_256(max_string_len, ZHK_A_num_bytes, hash_input, ZHK_A_num_bytes, hash_output);

#ifdef DEBUG
PrintHeaderAndHexVals("ZeroTrust_Enroll(): ZHK_A_nonce:\n", ZHK_A_num_bytes, hash_output, 32);
PrintHeaderAndHexVals("ZeroTrust_Enroll(): Nonce:\n", ZHK_A_num_bytes, nonce, 32);
#endif

// --------------------
// Encrypt ZHK_A_nonce and send to IA
      ciphertext_len_bytes = encrypt_256(session_key, SHP_ptr->AES_IV, hash_output, ZHK_A_num_bytes, ZHK_A_nonce_enc);

// Sanity check. ciphertext_len_bytes works ONLY for blocks sizes 1 and 2 (currently).
      if ( ciphertext_len_bytes != ZHK_A_num_bytes )
         { 
         printf("ERROR: ZeroTrust_Enroll(): Encrypted len of ZHK_A_nonce %d NOT equal to expected length %d!\n", 
            ciphertext_len_bytes, ZHK_A_num_bytes); exit(EXIT_FAILURE); 
         }

#ifdef DEBUG
PrintHeaderAndHexVals("ZeroTrust_Enroll(): Encrypted ZHK_A_nonce:\n", ciphertext_len_bytes, ZHK_A_nonce_enc, 32);
#endif

// Send encrypted ZHK_A_nonce to IA.
      if ( SockSendB((unsigned char *)ZHK_A_nonce_enc, ZHK_A_num_bytes, Bank_socket_desc) < 0 )
         { printf("ERROR: main(): Failed to send 'ZHK_A_nonce_enc' to IA!\n"); exit(EXIT_FAILURE); }

// --------------------
// Encrypt nonce and send to IA
      ciphertext_len_bytes = encrypt_256(session_key, SHP_ptr->AES_IV, nonce, ZHK_A_num_bytes, nonce_enc);

// Sanity check. ciphertext_len_bytes works ONLY for blocks sizes 1 and 2 (currently).
      if ( ciphertext_len_bytes != ZHK_A_num_bytes )
         { 
         printf("ERROR: ZeroTrust_Enroll(): Encrypted len of nonce_enc %d NOT equal to expected length %d!\n", 
            ciphertext_len_bytes, ZHK_A_num_bytes); exit(EXIT_FAILURE); 
         }

// Send encrypted nonce to IA.
      if ( SockSendB((unsigned char *)nonce_enc, ZHK_A_num_bytes, Bank_socket_desc) < 0 )
         { printf("ERROR: main(): Failed to send 'nonce_enc' to IA!\n"); exit(EXIT_FAILURE); }
      }

#ifdef DEBUG
printf("\nZeroTrust_Enroll(): DONE GENERATINGS ATs!\n\n"); fflush(stdout);
#endif

#ifdef DEBUG
printf("ZeroTrust_Enroll(): Waiting on ACK from IA\n"); fflush(stdout);
#endif

// Get ACK from Bank
   char ack_str[max_string_len];
   if ( SockGetB((unsigned char *)ack_str, max_string_len, Bank_socket_desc) != 4  )
      { printf("ERROR: ZeroTrust_Enroll(): Failed to get 'ACK' from IA!\n"); exit(EXIT_FAILURE); }
   if ( strcmp(ack_str, "ACK") != 0 )
      { printf("ERROR: ZeroTrust_Enroll(): Failed to match 'ACK' string from IA!\n"); exit(EXIT_FAILURE); }

   if ( SockSendB((unsigned char *)"ACK", strlen("ACK") + 1, Bank_socket_desc) < 0  )
      { printf("ERROR: ZeroTrust_Enroll(): Failed to send 'ACK' to IA!\n"); exit(EXIT_FAILURE); }

// Close the socket and free the session key but ONLY if we are NOT the TTP.
   if ( is_TTP == 0 )
      {
      close(Bank_socket_desc);
      if ( session_key != NULL )
         free(session_key);
      }

   if ( nonce_buffer != NULL )
      free(nonce_buffer); 
   if ( nonce != NULL )
      free(nonce); 
   if ( hash_input != NULL )
      free(hash_input); 
   if ( hash_output != NULL )
      free(hash_output); 
   if ( ZHK_A_nonce_enc != NULL )
      free(ZHK_A_nonce_enc); 
   if ( nonce_enc != NULL )
      free(nonce_enc); 

// A one time save here.
   if ( LoadOrSaveDb(SHP_ptr->DB_Trust_AT, SHP_ptr->DB_name_Trust_AT, 1) != 0 )
      { 
      printf("Failed to store 'in memory' database to %s: %s\n", SHP_ptr->DB_name_Trust_AT, sqlite3_errmsg(SHP_ptr->DB_Trust_AT)); 
      sqlite3_close(SHP_ptr->DB_Trust_AT); exit(EXIT_FAILURE); 
      }

#ifdef DEBUG
printf("ZeroTrust_Enroll(): DONE!\n"); fflush(stdout);
#endif

// NOTE: WE USE (long long) here because this might take a LONG time depending on how many AT we are enrolling.
#ifdef DEBUG
gettimeofday(&t1, 0); elapsed = (t1.tv_sec-t2.tv_sec)*1000000 + t1.tv_usec-t2.tv_usec; printf("\tZERO TRUST ENROLLMENT: TOTAL ELAPSED %lld us for %d ATs!\n\n", 
   (long long)elapsed, num_ATs_to_generate);
#endif

   return; 
   }


// ========================================================================================================
// ========================================================================================================
// Alice/TTP contacts IA (the Bank) (Alice by request using a menu option, TTP automatically when processing
// a withdrawal) to get a list of ATs, one unique AT for each customer/TTP. The IA marks the AT sent as USED
// (NOT available for re-use by others). 
//
// NOTE: Alice MUST have her OWN ATs in this database as well. And the chip_num associated with her own AT must 
// match the value retrieved in GenLLK (not checked here), which is assigned by the IA. 
//
// NOTE: When the TTP calls this, it first contacts IA to get an AT for Alice. I could first check if an AT
// exists but it will always fail. The TTP does NOT 'get one unique AT for every customer' like Alice and Bob
// do. Since it has constant connectivity with the Bank (IA), it can fetch them on demand.

void ZeroTrust_GetATs(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int Bank_socket_desc, int is_TTP,
   unsigned char *session_key, pthread_mutex_t *Trust_DB_mutex_ptr, int chip_num)
   {
   char request_str[max_string_len];

#ifdef DEBUG
printf("ZeroTrust_GetATs(): CALLED!\n"); fflush(stdout);
#endif

// Sanity checks. Basically everything is 256 bits.
   if ( HASH_IN_LEN_BITS != SHP_ptr->KEK_target_num_key_bits || HASH_OUT_LEN_BITS != SHP_ptr->KEK_target_num_key_bits )
      { 
      printf("ERROR: ZeroTrust_GetATs(): HASH_IN_LEN_BITS %d MUST be equal to HASH_OUT_LEN_BIT %d MUST be equal to KEK_target_num_key_bits %d\n", 
         HASH_IN_LEN_BITS, HASH_OUT_LEN_BITS, SHP_ptr->KEK_target_num_key_bits/8); exit(EXIT_FAILURE); 
      }

   if ( SHP_ptr->SE_target_num_key_bits != SHP_ptr->KEK_target_num_key_bits )
      { 
      printf("ERROR: ZeroTrust_GetATs(): SE_target_num_key_bits %d MUST be equal to KEK_target_num_key_bits %d\n", 
         SHP_ptr->SE_target_num_key_bits, SHP_ptr->KEK_target_num_key_bits/8); exit(EXIT_FAILURE); 
      }

// ********************************************************************************************************************
// *** ZeroTrust Get ATs PART I: Send command
   if ( SockSendB((unsigned char *)"ZERO-TRUST-GET-ATS", strlen("ZERO-TRUST-GET-ATS") + 1, Bank_socket_desc) < 0 )
      { printf("ERROR: ZeroTrust_GetATs(): Failed to send 'ZERO-TRUST-GET-ATS' to Bank!\n"); exit(EXIT_FAILURE); }

// If Alice, mutually authenticate with Bank, and generate session key. TTP does NOT do this.
   if ( is_TTP == 0 )
      {
      int gen_session_key = 1;
      KEK_ClientServerAuthenKeyGen(max_string_len, SHP_ptr, Bank_socket_desc, gen_session_key);

      session_key = SHP_ptr->SE_final_key;
      SHP_ptr->SE_final_key = NULL;
      }

// For the TTP, TTP sends Alice's chip_num to IA. The IA will fetch only one AT in this case.
   else
      {
      sprintf(request_str, "%d", chip_num);
      if ( SockSendB((unsigned char *)request_str, strlen(request_str) + 1, Bank_socket_desc) < 0  )
         { printf("ERROR: ZeroTrust_GetATs(): Failed to send 'chip_num' to Bank (for TTP)!\n"); exit(EXIT_FAILURE); }
      }

// ********************************************************************************************************************
// *** ZeroTrust Get ATs PART II: Get ATs from Bank
   int num_customers, customer_num;
   int *chip_num_arr = NULL;
   int *chlng_num_arr = NULL;
   unsigned char **ZHK_A_nonce_arr = NULL;
   unsigned char **nonce_arr = NULL;

   unsigned char *AT_packet = NULL, *AT_packet_enc = NULL;
   int AT_packet_size, AT_packet_size_enc;

// Size here is 2 integers and 2 * the size of ZHK_A and nonce (WHICH WE ASSUME ARE THE SAME SIZE).
   AT_packet_size = 2*4 + 2*SHP_ptr->ZHK_A_num_bytes;

// MAKE SURE YOU pad the size to the nearest multpiple of AES_INPUT_NUM_BYTES. When the original packet size is divisible by 
// AES_INPUT_NUM_BYTES, we ADD AN EXTRA block here.
   AT_packet_size_enc = AT_packet_size; 
   AT_packet_size_enc += AES_INPUT_NUM_BYTES - (AT_packet_size % AES_INPUT_NUM_BYTES);

   AT_packet = Allocate1DUnsignedChar(AT_packet_size_enc);
   AT_packet_enc = Allocate1DUnsignedChar(AT_packet_size_enc);

#ifdef DEBUG
printf("\tZeroTrust_GetATs(): Allocated AT_packet/enc of size %d and %d!\n", AT_packet_size, AT_packet_size_enc); fflush(stdout);
#endif

   if ( SockGetB((unsigned char *)request_str, max_string_len, Bank_socket_desc) < 0 )
      { printf("ERROR: ZeroTrust_GetATs(): Failed to get 'num_customers' string from Bank!\n"); exit(EXIT_FAILURE); }
   if ( sscanf(request_str, "%d", &num_customers) != 1 )
      { printf("ERROR: ZeroTrust_GetATs(): Failed to extract 'num_customers' from string!\n"); exit(EXIT_FAILURE); }

// It is possible that there is no customer data
   if ( num_customers > 0 )
      {

// Allocate storage
      if ( (chip_num_arr = (int *)calloc(num_customers, sizeof(int))) == NULL )
         { printf("ERROR: ZeroTrust_GetATs(): Failed to allocate chip_num_arr!\n"); exit(EXIT_FAILURE); }
      if ( (chlng_num_arr = (int *)calloc(num_customers, sizeof(int))) == NULL )
         { printf("ERROR: ZeroTrust_GetATs(): Failed to allocate chlng_num_arr!\n"); exit(EXIT_FAILURE); }

      if ( (ZHK_A_nonce_arr = (unsigned char **)malloc(num_customers*sizeof(unsigned char *))) == NULL )
         { printf("ERROR: ZeroTrust_GetATs(): Failed to allocate ZHK_A_nonce_arr!\n"); exit(EXIT_FAILURE); }
      for ( customer_num = 0; customer_num < num_customers; customer_num++ )
         ZHK_A_nonce_arr[customer_num] = Allocate1DUnsignedChar(SHP_ptr->ZHK_A_num_bytes);

      if ( (nonce_arr = (unsigned char **)malloc(num_customers*sizeof(unsigned char *))) == NULL )
         { printf("ERROR: ZeroTrust_GetATs(): Failed to allocate nonce_arr!\n"); exit(EXIT_FAILURE); }
      for ( customer_num = 0; customer_num < num_customers; customer_num++ )
         nonce_arr[customer_num] = Allocate1DUnsignedChar(SHP_ptr->ZHK_A_num_bytes);

      for ( customer_num = 0; customer_num < num_customers; customer_num++ )
         {

#ifdef DEBUG
printf("\tZeroTrust_GetATs(): Receiving IA data for customer array index %d!\n", customer_num); fflush(stdout);
#endif

         if ( SockGetB((unsigned char *)AT_packet_enc, AT_packet_size_enc, Bank_socket_desc) != AT_packet_size_enc )
            { printf("ERROR: ZeroTrust_GetATs(): Failed to AT packet from Bank!\n"); exit(EXIT_FAILURE); }

// Decrypt it and then parse out the fields
         decrypt_256(session_key, SHP_ptr->AES_IV, AT_packet_enc, AT_packet_size_enc, AT_packet);

// First two fields are integers, customer chip_num and customer chlng_num. This is followed by ZHK_A_nonce and nonce.
         int i, j = 0, k = 0, l = 0, m = 0;
         for ( i = 0; i < AT_packet_size; i++ )
            {
            if ( i < 4 )
               { chip_num_arr[customer_num] += (int)(AT_packet[i] << (j << 3)); j++; }
            else if ( i < 2*4 )
               { chlng_num_arr[customer_num] += (int)(AT_packet[i] << (k << 3)); k++; }
            else if ( i < 2*4 + SHP_ptr->ZHK_A_num_bytes )
               { ZHK_A_nonce_arr[customer_num][l] = AT_packet[i]; l++; }
            else if ( i < 2*4 + 2*SHP_ptr->ZHK_A_num_bytes )
               { nonce_arr[customer_num][m] = AT_packet[i]; m++; }
            else 
               { printf("ERROR: ZeroTrust_GetATs(): Packet byte TOO LARGER [%d]!\n", i); exit(EXIT_FAILURE); }
            }

#ifdef DEBUG
printf("\tZeroTrust_GetATs(): Decrypted IA data with customer chip_num %d!\n", chip_num_arr[customer_num]); fflush(stdout);
#endif

         }

// ********************************************************************************************************************
// *** ZeroTrust Get ATs PART III: Add customer ATs to Alice/TTP DB

#ifdef DEBUG
printf("ZeroTrust_GetATs(): Inserting customer data into DB for %d customers!\n", num_customers); fflush(stdout);
#endif

// Store them in the ZeroTrust table of the ZeroTrust Table of the Trust DB. Note: We must protect the update routine
// here when the TTP calls this routine (Alice and Bob are single threaded). NOTE: duplicates are usually not possible because
// the IA marks the AT is used when it distributes them to customers/TTP so once an AT is transmitted, it is not sent again by
// the IA. Mark these new AT with status 0 ('NOT USED').
      int status = 0;
      if ( is_TTP == 1 )
         pthread_mutex_lock(Trust_DB_mutex_ptr);
      for ( customer_num = 0; customer_num < num_customers; customer_num++ )
         ZeroTrustAddCustomerATs(max_string_len, SHP_ptr->DB_Trust_AT, chip_num_arr[customer_num], chlng_num_arr[customer_num], 
            SHP_ptr->ZHK_A_num_bytes, ZHK_A_nonce_arr[customer_num], nonce_arr[customer_num], status);
      if ( is_TTP == 1 )
         pthread_mutex_unlock(Trust_DB_mutex_ptr);

// Try adding a duplicate to test the 'unique' feature. This will probably never occur -- see note above.
//ZeroTrustAddCustomerATs(max_string_len, SHP_ptr->DB_Trust_AT, chip_num_arr[0], chlng_num_arr[0], 
//   SHP_ptr->ZHK_A_num_bytes, ZHK_A_nonce_arr[0], nonce_arr[0], status);
      }

// Send ACK to the Bank to allow it to continue. 
   if ( SockSendB((unsigned char *)"ACK", strlen("ACK") + 1, Bank_socket_desc) < 0  )
      { printf("ERROR: ZeroTrust_GetATs(): Failed to send 'ACK' to Bank!\n"); exit(EXIT_FAILURE); }

// Wait for Bank to acknowledge
   if ( SockGetB((unsigned char *)request_str, max_string_len, Bank_socket_desc) != 4  )
      { printf("ERROR: ZeroTrust_GetATs(): Failed to get 'ACK' from Bank!\n"); exit(EXIT_FAILURE); }
   if ( strcmp(request_str, "ACK") != 0 )
      { printf("ERROR: ZeroTrust_GetATs(): Failed to match 'ACK' string from Bank!\n"); exit(EXIT_FAILURE); }

// Close the socket and free the session key, but ONLY IF this is NOT a TTP calling this function.
   if ( is_TTP == 0 )
      {
      close(Bank_socket_desc);
      if ( session_key != NULL )
         free(session_key); 
      }

   if ( chip_num_arr != NULL )
      free(chip_num_arr);
   if ( chlng_num_arr != NULL )
      free(chlng_num_arr);

   for ( customer_num = 0; customer_num < num_customers; customer_num++ )
      {
      if ( ZHK_A_nonce_arr[customer_num] != NULL )
         free(ZHK_A_nonce_arr[customer_num]);
      if ( nonce_arr[customer_num] != NULL )
         free(nonce_arr[customer_num]);
      }
   if ( ZHK_A_nonce_arr != NULL )
      free(ZHK_A_nonce_arr); 
   if ( nonce_arr != NULL )
      free(nonce_arr); 
  
   if ( AT_packet != NULL )
      free(AT_packet);
   if ( AT_packet_enc != NULL )
      free(AT_packet_enc);

// Can add this in later as needed
if ( 0 )
   {
   if ( LoadOrSaveDb(SHP_ptr->DB_Trust_AT, SHP_ptr->DB_name_Trust_AT, 1) != 0 )
      { 
      printf("Failed to store 'in memory' database to %s: %s\n", SHP_ptr->DB_name_Trust_AT, sqlite3_errmsg(SHP_ptr->DB_Trust_AT)); 
      sqlite3_close(SHP_ptr->DB_Trust_AT); exit(EXIT_FAILURE); 
      }
   }

#ifdef DEBUG
printf("ZeroTrust_GetATs(): DONE!\n"); fflush(stdout);
#endif

   return;
   }

