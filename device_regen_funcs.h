// ========================================================================================================
// ========================================================================================================
// ***************************************** device_regen_funcs.h *****************************************
// ========================================================================================================
// ========================================================================================================
//
//--------------------------------------------------------------------------------
// Company: IC-Safety, LLC and University of New Mexico
// Engineer: Professor Jim Plusquellic
// Exclusive License: IC-Safety, LLC
// Copyright: Univ. of New Mexico
//--------------------------------------------------------------------------------

void intHandler(int dummy);

void LoadUnloadBRAM(int max_string_len, int num_vals, volatile unsigned int *CtrlRegA, volatile unsigned int *DataRegA, 
   unsigned int ctrl_mask, unsigned char *ByteData, signed short *WordData, int load_or_unload, int byte_or_word_data, 
   int debug_flag);

int FetchTransSHD_SBS(int max_string_len, int target_bytes, volatile unsigned int *CtrlRegA, 
   volatile unsigned int *DataRegA, unsigned int ctrl_mask, int verifier_socket_desc, unsigned char *SHD_SBS, 
   int also_do_transfer, int SHD_or_SBS, int TA_or_KEK, int DUMP_BITSTRINGS, int DEBUG);

int CollectPNs(int max_string_len, int num_POs, int num_PIs, int vec_chunk_size, int max_generated_nonce_bytes, 
   volatile unsigned int *CtrlRegA, volatile unsigned int *DataRegA, unsigned int ctrl_mask, int num_vecs, 
   int num_rise_vecs, int has_masks, unsigned char **first_vecs_b, unsigned char **second_vecs_b, 
   unsigned char **masks_b, unsigned char *device_n1, int DUMP_BITSTRINGS, int DEBUG);

int KEK_DeviceAuthentication_SKE(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int verifier_socket_desc);

int KEK_Enroll(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int LL_or_session_or_cobra_PO_or_cobra_PCR, 
   int verifier_socket_desc);

int KEK_Regen(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int do_minority_bit_flip_analysis);

int KEK_ClientServerAuthen(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int verifier_socket_desc);

int TRNG(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int int_or_ext_mode, int load_seed,
   int store_nonce_num_bytes, unsigned char *nonce_arr);

int KEK_ClientServerAuthenKeyGen(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int verifier_socket_desc, 
   int gen_session_key);

// PUF-Cash V3.0
int GenLLK(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int open_socket, char *Bank_IP, int port_number,
   int Bank_socket_desc, int allow_multiple_LLK, int LLK_type, int LLK_num_bytes);

void ZeroTrust_Enroll(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, char *Bank_IP, int port_number,
   int zero_trust_LLK_index, int is_TTP, int Bank_socket_desc, unsigned char *session_key);

void ZeroTrust_GetATs(int max_string_len, SRFHardwareParamsStruct *SHP_ptr, int Bank_socket_desc, int is_TTP,
   unsigned char *session_key, pthread_mutex_t *Trust_DB_mutex_ptr, int chip_num);
