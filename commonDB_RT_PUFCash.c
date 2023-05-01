// ========================================================================================================
// ========================================================================================================
// ************************************* commonDB_RT_PUFCash.c ********************************************
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
#include "commonDB_RT_PUFCash.h"

#include "aes_128_ecb_openssl.h"
#include "aes_256_cbc_openssl.h"

// SQL commands depend on the structure of the tables in the database. Keeping these all in one place where possible.
const char *SQL_ListB_insert_into_cmd = "INSERT INTO ListB (n2) VALUES (?);";
const char *SQL_ListB_read_n2_cmd = "SELECT n2 FROM ListB WHERE ID = ?;";
const char *SQL_ListB_get_index_cmd = "SELECT ID FROM ListB WHERE n2 = ?;";

const char *SQL_PreAuthInfo_insert_into_cmd = "INSERT INTO PreAuthInfo (Acct, n3, NumVecs, NumRiseVecs, num_vec_bytes, num_mask_bytes, num_SpreadFactor_bytes, \
FirstVecs, SecondVecs, Masks, SpreadFactors) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
const char *SQL_PreAuthInfo_get_index_cmd = "SELECT ID FROM PreAuthInfo WHERE n3 = ?;";

const char *SQL_PreAuthInfo_read_FirstVecs_cmd = "SELECT FirstVecs FROM PreAuthInfo WHERE ID = ?;";
const char *SQL_PreAuthInfo_read_SecondVecs_cmd = "SELECT SecondVecs FROM PreAuthInfo WHERE ID = ?;";
const char *SQL_PreAuthInfo_read_Masks_cmd = "SELECT Masks FROM PreAuthInfo WHERE ID = ?;";
const char *SQL_PreAuthInfo_read_SpreadFactors_cmd = "SELECT SpreadFactors FROM PreAuthInfo WHERE ID = ?;";

// SKa/N1s table commands
const char *SQL_SKa_get_index_cmd = "SELECT ID FROM SKa WHERE SKa = ?;";
const char *SQL_SKa_insert_into_cmd = "INSERT INTO SKa (SKa) VALUES (?);";

const char *SQL_N1s_insert_into_cmd = "INSERT INTO N1s (n1, validated, SKa_id) VALUES (?, ?, ?);";

// NOT USED
const char *SQL_Bitstrings_one_chip = "SELECT PUFInstanceID, ChallengeSetName, CreationDate, SecurityFunction, FixParams, Bitstring) \
WHERE DesignIndex = %d AND InstanceName = %s AND Placement = %s;";


// ZeroTrust PROTOCOL
const char *SQL_ZeroTrustAuthenToken_insert_into_cmd = "INSERT INTO ZeroTrustAuthenToken (ChipNum, CH_LLK, n_x, Chlng_num, Status) VALUES (?, ?, ?, ?, ?);";
const char *SQL_ZeroTrustAuthenToken_get_index_cmd = "SELECT ID FROM ZeroTrustAuthenToken WHERE CH_LLK = ?;";


// PUFCash V3.0 PROTOCOL
const char *SQL_PUFCash_WRec_insert_into_cmd = "INSERT INTO PUFCash_WRec (AnonChipNum, LLK, eCt, heCt, num_eCt, Status) VALUES (?, ?, ?, ?, ?, ?);";
const char *SQL_PUFCash_WRec_get_index_cmd = "SELECT ID FROM PUFCash_WRec WHERE eCt = ?;";

const char *SQL_PUFCash_Account_insert_into_cmd = "INSERT INTO PUFCash_Account (ChipNum, TID, Amount) VALUES (?, ?, ?);";
const char *SQL_PUFCash_Account_get_index_cmd = "SELECT ID FROM PUFCash_Account WHERE (ChipNum = ?);";

const char *SQL_PUFCash_LLK_insert_into_cmd = "INSERT INTO PUFCash_LLK (ChipNum, AnonChipNum, mask, Chlng, Status) VALUES (?, ?, ?, ?, ?);";
const char *SQL_PUFCash_LLK_get_index_cmd = "SELECT ID FROM PUFCash_LLK WHERE Status = ?;";


// ========================================================================================================
// ========================================================================================================
// Search a table for a match to the input args. Return its index.

int GetIndexFromTable_RT(int max_string_len, sqlite3 *db, char *Table, const char *SQL_cmd, unsigned char *blob, 
   int blob_size_bytes, char *text1, char *text2, char *text3, char *text4, int int1, int int2, int int3)
   {
   sqlite3_stmt *pStmt;
   int rc, fc;
   int index;

#ifdef DEBUG
printf("GetIndexFromTable(): SQL cmd %s\n", SQL_cmd); fflush(stdout);
#endif

// Prepare 'pStmt' with SQL query.
   rc = sqlite3_prepare_v2(db, SQL_cmd, strlen(SQL_cmd) + 1, &pStmt, 0);
   if( rc != SQLITE_OK )
      { printf("ERROR: GetIndexFromTable(): 'sqlite3_prepare_v2' failed with %d\n", rc); exit(EXIT_FAILURE); }

// Bind the variables to '?' in 'SQL_cmd'.
   if ( strcmp(Table, "ListB") == 0 )
      {
      sqlite3_bind_blob(pStmt, 1, blob, blob_size_bytes, SQLITE_STATIC);
      }
   else if ( strcmp(Table, "PreAuthInfo") == 0 )
      {
      sqlite3_bind_blob(pStmt, 1, blob, blob_size_bytes, SQLITE_STATIC);
      }
   else if ( strcmp(Table, "SKa") == 0 )
      {
      sqlite3_bind_blob(pStmt, 1, blob, blob_size_bytes, SQLITE_STATIC);
      }
   else if ( strcmp(Table, "N1s") == 0 )
      {
      sqlite3_bind_blob(pStmt, 1, blob, blob_size_bytes, SQLITE_STATIC);
      }
   else if ( strcmp(Table, "ZeroTrustAuthenToken") == 0 )
      {
      sqlite3_bind_blob(pStmt, 1, blob, blob_size_bytes, SQLITE_STATIC);
      }
   else if ( strcmp(Table, "PUFCash_WRec") == 0 )
      {
      sqlite3_bind_blob(pStmt, 1, blob, blob_size_bytes, SQLITE_STATIC);
      }
   else if ( strcmp(Table, "PUFCash_Account") == 0 )
      {
      sqlite3_bind_int(pStmt, 1, int1);
      }
   else if ( strcmp(Table, "PUFCash_LLK") == 0 )
      {
      sqlite3_bind_int(pStmt, 1, int1);
      }
   else
      { printf("ERROR: GetIndexFromTable(): Unknown Table '%s'\n", Table); exit(EXIT_FAILURE); }

// Run the virtual machine. The SQL statement prepared MUST return at most 1 row of data since we call sqlite3_step() ONLY once
// here. Normally, we would keep calling sqlite3_step until it returned something other than SQLITE_ROW. Multiple kinds of errors 
// can occur as well -- see doc.
   rc = sqlite3_step(pStmt);

#ifdef DEBUG
printf("GetIndexFromTable(): Table '%s', Column cnt %d\n", Table, sqlite3_column_count(pStmt)); fflush(stdout);
printf("GetIndexFromTable(): Table '%s', Column type %d => Integer type %d\n", Table, sqlite3_column_type(pStmt, 0), SQLITE_INTEGER); fflush(stdout);
#endif

   index = sqlite3_column_int64(pStmt, 0);

   if ( (fc = sqlite3_finalize(pStmt)) != 0 )
      { printf("ERROR: GetIndexFromTable(): Finalize failed %d for Table '%s'\n", fc, Table); exit(EXIT_FAILURE); }

// Classify the return code. 'DONE' means search failed while 'ROW' means it found the item.
   if ( rc == SQLITE_DONE )
      { 
//      printf("WARNING: GetIndexFromTable(): Search string NOT FOUND in Table '%s': Return code %d\n", Table, rc); fflush(stdout); 
      index = -1;
      }
   else if ( rc != SQLITE_ROW )
      { printf("ERROR: GetIndexFromTable(): Return code for 'sqlite3_step' not SQLITE_DONE or SQLITE_ROW => %d for Table '%s'\n", rc, Table); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("GetIndexFromTable(): Index %d for Table '%s'\n", index, Table); fflush(stdout);
#endif

   return index;
   }


// ========================================================================================================
// ========================================================================================================
// Insert an element into a table given by the input arguments.

int InsertIntoTable_RT(int max_string_len, sqlite3 *db, char *Table, const char *SQL_cmd, unsigned char *blob1, 
   int blob1_size_bytes, unsigned char *blob2, int blob2_size_bytes, unsigned char *blob3, int blob3_size_bytes, 
   unsigned char *blob4, int blob4_size_bytes, unsigned char *blob5, int blob5_size_bytes, char *text1, 
   char *text2, char *text3, char *text4, char *text5, int int1, int int2, int int3, int int4, int int5, 
   int int6)
   {
   sqlite3_stmt *pStmt;
   int rc, fc;

#ifdef DEBUG
printf("InsertIntoTable_RT(): SQL cmd %s\n", SQL_cmd); fflush(stdout);
#endif

// Prepare 'pStmt' with SQL query.
   rc = sqlite3_prepare_v2(db, SQL_cmd, strlen(SQL_cmd) + 1, &pStmt, 0);
   if( rc != SQLITE_OK )
      { printf("ERROR: InsertIntoTable_RT(): 'sqlite3_prepare_v2' failed with %d\n", rc); exit(EXIT_FAILURE); }

// Insert the n2 block into ListB
   if ( strcmp(Table, "ListB") == 0 )
      {
      sqlite3_bind_blob(pStmt, 1, blob1, blob1_size_bytes, SQLITE_STATIC);
      }
   else if ( strcmp(Table, "PreAuthInfo") == 0 )
      {
      sqlite3_bind_int(pStmt, 1, int1);
      sqlite3_bind_blob(pStmt, 2, blob1, blob1_size_bytes, SQLITE_STATIC);
      sqlite3_bind_int(pStmt, 3, int2);
      sqlite3_bind_int(pStmt, 4, int3);
      sqlite3_bind_int(pStmt, 5, int4);
      sqlite3_bind_int(pStmt, 6, int5);
      sqlite3_bind_int(pStmt, 7, int6);
      sqlite3_bind_blob(pStmt, 8, blob2, blob2_size_bytes, SQLITE_STATIC);
      sqlite3_bind_blob(pStmt, 9, blob3, blob3_size_bytes, SQLITE_STATIC);
      sqlite3_bind_blob(pStmt, 10, blob4, blob4_size_bytes, SQLITE_STATIC);
      sqlite3_bind_blob(pStmt, 11, blob5, blob5_size_bytes, SQLITE_STATIC);
      }
   else if ( strcmp(Table, "SKa") == 0 )
      {
      sqlite3_bind_blob(pStmt, 1, blob1, blob1_size_bytes, SQLITE_STATIC);
      }
   else if ( strcmp(Table, "N1s") == 0 )
      {
      sqlite3_bind_blob(pStmt, 1, blob1, blob1_size_bytes, SQLITE_STATIC);
      sqlite3_bind_blob(pStmt, 2, blob2, blob2_size_bytes, SQLITE_STATIC);
      sqlite3_bind_int(pStmt, 3, int1);
      }
   else if ( strcmp(Table, "ZeroTrustAuthenToken") == 0 )
      {
      sqlite3_bind_int(pStmt, 1, int1);
      sqlite3_bind_blob(pStmt, 2, blob1, blob1_size_bytes, SQLITE_STATIC);
      sqlite3_bind_blob(pStmt, 3, blob2, blob2_size_bytes, SQLITE_STATIC);
      sqlite3_bind_int(pStmt, 4, int2);
      sqlite3_bind_int(pStmt, 5, int3);
      }
   else if ( strcmp(Table, "PUFCash_WRec") == 0 )
      {
      sqlite3_bind_int(pStmt, 1, int1);
      sqlite3_bind_blob(pStmt, 2, blob1, blob1_size_bytes, SQLITE_STATIC);
      sqlite3_bind_blob(pStmt, 3, blob2, blob2_size_bytes, SQLITE_STATIC);
      sqlite3_bind_blob(pStmt, 4, blob3, blob3_size_bytes, SQLITE_STATIC);
      sqlite3_bind_int(pStmt, 5, int2);
      sqlite3_bind_int(pStmt, 6, int3);
      }
   else if ( strcmp(Table, "PUFCash_Account") == 0 )
      {
      sqlite3_bind_int(pStmt, 1, int1);
      sqlite3_bind_int(pStmt, 2, int2);
      sqlite3_bind_int(pStmt, 3, int3);
      }
   else if ( strcmp(Table, "PUFCash_LLK") == 0 )
      {
      sqlite3_bind_int(pStmt, 1, int1);
      sqlite3_bind_int(pStmt, 2, int2);
      sqlite3_bind_int(pStmt, 3, int3);
      sqlite3_bind_blob(pStmt, 4, blob1, blob1_size_bytes, SQLITE_STATIC);
      sqlite3_bind_int(pStmt, 5, int4);
      }
   else
      { printf("ERROR: InsertIntoTable_RT(): Unknown Table '%s'\n", Table); exit(EXIT_FAILURE); }

   rc = sqlite3_step(pStmt);

   if ( (fc = sqlite3_finalize(pStmt)) != 0 && fc != SQLITE_CONSTRAINT )
      { printf("ERROR: InsertIntoTable_RT(): Finalize failed %d for Table '%s'\n", fc, Table); exit(EXIT_FAILURE); }

// 'DONE' means insertion succeeded while 'CONSTRAINT' means the element already exists (only occurs if UNIQUE 
// is set, I think).
   if ( rc == SQLITE_DONE )
      return 1;
   else if ( rc == SQLITE_CONSTRAINT )
      {
      printf("\t\tINFO: InsertIntoTable_RT(): Element already exists in Table '%s' -- NOT adding!\n", Table); fflush(stdout);
      return 0;
      }
   else 
      { printf("ERROR: InsertIntoTable_RT(): Return code => %d for Table '%s'\n", rc, Table); exit(EXIT_FAILURE); }

   return 1;
   }


// ********************************************************************************************************
// *************************************** ZeroTrust PROTOCOL *********************************************
// ********************************************************************************************************

// ========================================================================================================
// ZeroTrustAuthenToken
// ========================================================================================================
// IA adds ZeroTrustAuthenToken information into the PeeTrust table/database, which includes the chip_num
// a Chlng_num, the ZHK_A_nonce (keyed hashed LLK key bitstring) and corresponding nonce. Since this function
// is called by Alice from a menu option, it can be called more than once (and by the TTP before each 
// withdrawal operation), but we don't need to check that we are NOT adding duplicate AT entries because we
// always generate new ones on each call.

void ZeroTrustAddCustomerATs(int max_string_len, sqlite3 *DB_Trust_AT, int chip_num, 
   int Chlng_num, int ZHK_A_num_bytes, unsigned char *ZHK_A_nonce, unsigned char *nonce, int status)
   {
   int Alice_ZHK_A_index;

#ifdef DEBUG
printf("ZeroTrustAddCustomerATs(): CALLED!\n"); fflush(stdout);
#endif

// Sanity checks
   if ( chip_num == -1 )
      { printf("ERROR: ZeroTrustAddCustomerATs(): Expected chip_num >= 0 %d\n", chip_num); exit(EXIT_FAILURE); }
   if ( Chlng_num < 0 )
      { printf("ERROR: ZeroTrustAddCustomerATs(): Expected Chlng_num >= 0 %d\n", Chlng_num); exit(EXIT_FAILURE); }
   if ( ZHK_A_num_bytes <= 0  )
      { printf("ERROR: ZeroTrustAddCustomerATs(): Expected ZHK_A_num_bytes > 0 %d\n", ZHK_A_num_bytes); exit(EXIT_FAILURE); }
   if ( ZHK_A_nonce == NULL  )
      { printf("ERROR: ZeroTrustAddCustomerATs(): ZHK_A_nonce MUST BE NON-NULL\n"); exit(EXIT_FAILURE); }
   if ( nonce == NULL  )
      { printf("ERROR: ZeroTrustAddCustomerATs(): nonce MUST BE NON-NULL\n"); exit(EXIT_FAILURE); }

// The ZHK_A_nonce is set to 'unique' in the schema for this database. InsertIntoTable_RT will return 0 if this element is a duplicate.
   if ( InsertIntoTable_RT(max_string_len, DB_Trust_AT, "ZeroTrustAuthenToken", SQL_ZeroTrustAuthenToken_insert_into_cmd, 
      ZHK_A_nonce, ZHK_A_num_bytes, nonce, ZHK_A_num_bytes, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, chip_num, Chlng_num,
      status, 0, 0, 0) == 0 )
      return;

#ifdef DEBUG
printf("ZeroTrustAddCustomerATs(): Inserted ZHK_A_nonce info into ZeroTrustAuthenToken with chip_num %d\tChlng_num %d\tSTATUS %d!\n", 
   chip_num, Chlng_num, status); fflush(stdout);
#endif

#ifdef DEBUG
PrintHeaderAndHexVals("ZHK_A_nonce:\n", ZHK_A_num_bytes, ZHK_A_nonce, 32);
PrintHeaderAndHexVals("nonce:\n", ZHK_A_num_bytes, nonce, 32);
#endif

// Get the index of the element just inserted.
   Alice_ZHK_A_index = GetIndexFromTable_RT(max_string_len, DB_Trust_AT, "ZeroTrustAuthenToken", SQL_ZeroTrustAuthenToken_get_index_cmd, 
      ZHK_A_nonce, ZHK_A_num_bytes, NULL, NULL, NULL, NULL, 0, 0, 0);

// Sanity check
   if ( Alice_ZHK_A_index == -1 )
      { printf("ERROR: ZeroTrustAddCustomerATs(): Alice_ZHK_A_index NOT FOUND -- JUST ADDED IT -- IMPOSSIBLE!\n"); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("ZeroTrustAddCustomerATs(): DONE!\tAdded ZeroTrustAuthenToken record with DB index %d\n", Alice_ZHK_A_index); fflush(stdout);
#endif

   return;
   }


// ========================================================================================================
// ZeroTrustAuthenToken
// ========================================================================================================
// Called by IA and by Alice/Bob/Charlie/TTP to fetch ATs from the DB. When Alice contacts IA for other 
// customer ATs, IA calls this routine to fetch one AT for each customer, and marks it as NOT used and then 
// sends the set of ATs to Alice. The ATs are stored in the ZeroTrust table, which includes the chip_num, KEK 
// challenge information used to generate them (Chlng_num), the ZHK_A_nonce (keyed hashed LLK key bitstring) 
// and corresponding nonce. When Alice/TTP calls this routine, she uses it to get ATs for peers.

int ZeroTrustGetCustomerATs(int max_string_len, sqlite3 *DB_Trust_AT, int **chip_num_arr_ptr, 
   int **chlng_num_arr_ptr, int ZHK_A_num_bytes, unsigned char ***ZHK_A_nonce_arr_ptr, 
   unsigned char ***nonce_arr_ptr, int get_only_customer_AT, int customer_chip_num, 
   int return_customer_AT_info, int report_tot_num_ATs_only, int *num_one_customer_ATs_ptr)
   {
   int AT_num, AT_index, chip_num, chlng_num, status, num_customers, blob_num_bytes, success;
   SQLIntStruct AT_index_struct; 

   SQLRowStringsStruct row_strings_struct;
   char sql_command_str[max_string_len];
   char *col1_name = "ChipNum";
   char *col2_name = "Chlng_num";
   char *col3_name = "STATUS";

// STATUS of 0 means NOT USED.
   char *SQL_ATs_cmd = "SELECT ID FROM ZeroTrustAuthenToken WHERE STATUS = 0;";
   char *SQL_PT_read_ZHK_A_nonce_cmd = "SELECT CH_LLK FROM ZeroTrustAuthenToken WHERE ID = ?;";
   char *SQL_PT_read_nonce_cmd = "SELECT n_x FROM ZeroTrustAuthenToken WHERE ID = ?;";

#ifdef DEBUG
printf("\nZeroTrustGetCustomerATs(): BEGIN\n"); fflush(stdout);
#endif

#ifdef DEBUG
if ( get_only_customer_AT == 1 )
   { printf("ZeroTrustGetCustomerATs(): Fetching ONLY an AT for customer_chip_num %d!\n", customer_chip_num); fflush(stdout); }
#endif

// Set only when 'get_only_customer_AT' == 1 AND return_customer_AT_info == 0, otherwise it remains at 0 (INVALID).
   *num_one_customer_ATs_ptr = 0;

// Make sure these are NULL since we use realloc below to add to the array. I pass NULL in for these on some calls so don't
// try to write NULL to them in this case.
   if ( chip_num_arr_ptr != NULL )
      *chip_num_arr_ptr = NULL;
   if ( chlng_num_arr_ptr != NULL )
      *chlng_num_arr_ptr = NULL;
   if ( ZHK_A_nonce_arr_ptr != NULL )
      *ZHK_A_nonce_arr_ptr = NULL;
   if ( nonce_arr_ptr != NULL )
      *nonce_arr_ptr = NULL;

// ==============================================
// First thing to do is get a list of customer ID (chip_num_arr) that are currently in the ZeroTrust table.
   GetAllocateListOfInts(max_string_len, DB_Trust_AT, SQL_ATs_cmd, &AT_index_struct);

// Sanity check. We should always have at least one AT. 
   if ( AT_index_struct.num_ints == 0 || report_tot_num_ATs_only == 1 )
      { 
      if ( AT_index_struct.int_arr != NULL )
         free(AT_index_struct.int_arr);
      AT_index_struct.int_arr = NULL;

      if ( AT_index_struct.num_ints == 0 )
         { printf("ZeroTrustGetCustomerATs(): No IDs found in database!\n"); fflush(stdout); }
      return AT_index_struct.num_ints;
      }

// ==============================================
// Loop through the 'NOT USED' AT records. 
   num_customers = 0;
   success = 0;
   for ( AT_num = 0; AT_num < AT_index_struct.num_ints; AT_num++ )
      {

// Get the integer data associated with the AT table entry for the ID 
      AT_index = AT_index_struct.int_arr[AT_num];
      sprintf(sql_command_str, "SELECT %s, %s, %s FROM ZeroTrustAuthenToken WHERE ID = %d;", col1_name, col2_name, col3_name, AT_index);
      GetStringsDataForRow(max_string_len, DB_Trust_AT, sql_command_str, &row_strings_struct);
      GetRowResultInt(&row_strings_struct, "ZeroTrustGetCustomerATs()", 3, 0, col1_name, &chip_num);
      GetRowResultInt(&row_strings_struct, "ZeroTrustGetCustomerATs()", 3, 1, col2_name, &chlng_num);
      GetRowResultInt(&row_strings_struct, "ZeroTrustGetCustomerATs()", 3, 2, col3_name, &status);
      FreeStringsDataForRow(&row_strings_struct);

#ifdef DEBUG
printf("\tZeroTrustGetCustomerATs(): Fetched ZeroTrust AT with chip_num %d\tchlng_num %d\tstatus %d!\n", chip_num, chlng_num, status); fflush(stdout);
#endif

// If status is not 'NOT USED' (0), then this is an error since the query specifies 'NOT USED' only.
      if ( status != 0 )
         { printf("ERROR: ZeroTrustGetCustomerATs(): Query was ONLY supposed to fetch ATs that are 'NOT USED'!\n"); exit(EXIT_FAILURE); }

// If Alice calls this routine to get a customer AT given by customer_chip_num, and the current chip_num is for a different customer,
// skip this AT.
      if ( get_only_customer_AT == 1 && customer_chip_num != chip_num )
         continue;
 
// Check if we already have an AT for this customer. If so, skip it. NOTE: chip_num_arr_ptr MAY BE NULL on some calls. We ensure in this routine 
// that num_customers is ALWAYS 0 if get_only_customer_AT == 1 (b/c we only iterate once -- see below) but protecting this here just in case.
// ALSO, when we want the NUMBER of ATs for a customer (get_only_customer_AT == 1 && return_customer_AT_info == 0), we loop multiple times here
// BUT WE DO NOT increment num_customers, so we actually count the number of ATs available for ONE customer when these conditions are met.
      int i;
      for ( i = 0; i < num_customers; i++ )
         if ( chip_num_arr_ptr != NULL && chip_num == (*chip_num_arr_ptr)[i] )
            break;
      if ( i < num_customers )
         continue;

#ifdef DEBUG
printf("\t\tZeroTrustGetCustomerATs(): VALID AT with chip_num %d\tchlng_num %d\tstatus %d!\n", chip_num, chlng_num, status); fflush(stdout);
#endif

// Allocate storage for the AT and assign chip_num and chlng_num components of the AT if the calls requests it. NOTE: THESE ARRAY pointers
// may be NULL on some calls to this routine.
      if ( return_customer_AT_info == 1 )
         {
         if ( (*chip_num_arr_ptr = (int *)realloc(*chip_num_arr_ptr, (num_customers + 1)*sizeof(int))) == NULL )
            { printf("ERROR: ZeroTrustGetCustomerATs(): Failed to realloc *chip_num_arr_ptr!\n"); exit(EXIT_FAILURE); }
         (*chip_num_arr_ptr)[num_customers] = chip_num;
         if ( (*chlng_num_arr_ptr = (int *)realloc(*chlng_num_arr_ptr, (num_customers + 1)*sizeof(int))) == NULL )
            { printf("ERROR: ZeroTrustGetCustomerATs(): Failed to realloc *chlng_num_arr_ptr!\n"); exit(EXIT_FAILURE); }
         (*chlng_num_arr_ptr)[num_customers] = chlng_num;

// Get the ZHK_A_nonce and n_x components.

// ReadBinaryBlob will assign to pre-allocated space in the 4th arg, checking that the value read from the DB matches the number of
// bytes given by the 5th arg, if the 6th arg is 0. Otherwise if 6th arg is 1, it allocates space, fills it in with DB data and assigns 
// a pointer to that space to the last arg.
         if ( (*ZHK_A_nonce_arr_ptr = (unsigned char **)realloc(*ZHK_A_nonce_arr_ptr, (num_customers + 1)*sizeof(unsigned char *))) == NULL )
            { printf("ERROR: ZeroTrustGetCustomerATs(): Failed to realloc *ZHK_A_nonce_arr_ptr!\n"); exit(EXIT_FAILURE); }
         blob_num_bytes = ReadBinaryBlob(DB_Trust_AT, SQL_PT_read_ZHK_A_nonce_cmd, AT_index, NULL, 0, 1, &((*ZHK_A_nonce_arr_ptr)[num_customers]));

// Sanity check
         if ( ZHK_A_num_bytes != blob_num_bytes )
            { 
            printf("ERROR: ZeroTrustGetCustomerATs(): Number of bytes read from DB for ZHK_A_nonce_arr %d not equal to %d!\n", 
               ZHK_A_num_bytes, blob_num_bytes); exit(EXIT_FAILURE); 
            }

         if ( (*nonce_arr_ptr = (unsigned char **)realloc(*nonce_arr_ptr, (num_customers + 1)*sizeof(unsigned char *))) == NULL )
            { printf("ERROR: ZeroTrustGetCustomerATs(): Failed to realloc *nonce_arr_ptr!\n"); exit(EXIT_FAILURE); }
         blob_num_bytes = ReadBinaryBlob(DB_Trust_AT, SQL_PT_read_nonce_cmd, AT_index, NULL, 0, 1, &((*nonce_arr_ptr)[num_customers]));

// Sanity check (n_x MUST be the same size as CH_LLK).
         if ( ZHK_A_num_bytes != blob_num_bytes )
            { 
            printf("ERROR: ZeroTrustGetCustomerATs(): Number of bytes read from DB for nonce_arr %d not equal to %d!\n", 
               ZHK_A_num_bytes, blob_num_bytes); exit(EXIT_FAILURE); 
            }

// Mark the status of the AT as USED, but ONLY IF WE ACTUALLY FETCHED the data and returned it in this call.
         char *zErrMsg = 0;
         int fc;
         sprintf(sql_command_str, "UPDATE ZeroTrustAuthenToken SET status = 1 WHERE ID = %d;", AT_index);
         fc = sqlite3_exec(DB_Trust_AT, sql_command_str, NULL, 0, &zErrMsg);
         if ( fc != SQLITE_OK )
            { printf("SQL ERROR: %s\n", zErrMsg); sqlite3_free(zErrMsg); exit(EXIT_FAILURE); }
         }


// If Alice calls this routine to check or get a customer AT given by customer_chip_num, then break out of the loop because we found one if 
// we get here. But only break out if we are ALSO fetching an AT for this customer. If we are NOT fetching an AT, then keep counting
// the number of ATs associated with this customer. When we want the NUMBER of ATs for a customer (get_only_customer_AT == 1 && 
// return_customer_AT_info == 0), we loop multiple times here BUT WE DO NOT increment num_customers, so we actually count the number of 
// ATs available for ONE customer when these conditions are met.
      success = 1;
      if ( get_only_customer_AT == 1 )
         {
         if ( return_customer_AT_info == 1 )
            break;
         else
            (*num_one_customer_ATs_ptr)++;
         }

// If we are counting the number of valid ATs in the database for ALL customers, increment num_customers.
      else
         num_customers++;
      }

// See above, we do NOT increment num_customers in the above loop because we want to count ALL ATs available for ONE customer when
// get_only_customer_AT == 1 AND return_customer_AT_info == 0.
   if ( success == 1 && get_only_customer_AT == 1 )
      num_customers = 1;

   if ( AT_index_struct.int_arr != NULL )
      free(AT_index_struct.int_arr);
   AT_index_struct.int_arr = NULL;

#ifdef DEBUG
printf("\nZeroTrustGetCustomerATs(): DONE!\n"); fflush(stdout);
#endif

   return num_customers;
   }


// ********************************************************************************************************
// *************************************** PUF-Cash V3.0 PROTOCOL *****************************************
// ********************************************************************************************************

// ========================================================================================================
// PUFCash_WRec
// ========================================================================================================
// Alice/Bob: adds a withdrawal records that is uniquely identified using the id (or LLK). AnonChipNum is used
// by the server (TI) only, and is the anonymous ID assigned to Alice during provisioning, the index of her 
// anonymous timing data in the AT_DB. The LLK is used by the server (TI) only, and is the server generated 
// LLK (only used for malicious activity tracing). The eCt and heCt are blobs of one or more eCt/heCt 
// of total size eCt_tot_bytes. num_eCt are the number of eCt in the blobs.

void PUFCashAdd_WRec_Data(int max_string_len, sqlite3 *DB_PUFCash_V3, int AnonChipNum, unsigned char *LLK,
   int LLK_num_bytes, unsigned char *eCt_buffer, unsigned char *heCt_buffer, int eCt_tot_bytes, int num_eCt)
   {
   int WRec_id;

printf("PUFCashAdd_WRec_Data(): BEGIN!\n"); fflush(stdout);
#ifdef DEBUG
#endif

   if ( eCt_tot_bytes <= 0  )
      { printf("ERROR: PUFCashAdd_WRec_Data(): Expected eCt_tot_bytes > 0 \n"); exit(EXIT_FAILURE); }

// Set status to NOT used (0) 
   InsertIntoTable_RT(max_string_len, DB_PUFCash_V3, "PUFCash_WRec", SQL_PUFCash_WRec_insert_into_cmd, 
      LLK, LLK_num_bytes, eCt_buffer, eCt_tot_bytes, heCt_buffer, eCt_tot_bytes, NULL, 0, NULL, 0, 
      NULL, NULL, NULL, NULL, NULL, AnonChipNum, num_eCt, 0, -1, -1, -1);

// Get the index of the element just inserted.
   WRec_id = GetIndexFromTable_RT(max_string_len, DB_PUFCash_V3, "PUFCash_WRec", SQL_PUFCash_WRec_get_index_cmd, 
      eCt_buffer, eCt_tot_bytes, NULL, NULL, NULL, NULL, 0, 0, 0);

// Sanity check
   if ( WRec_id == -1 )
      { printf("ERROR: PUFCashAdd_WRec_Data(): Alice's eCt NOT FOUND -- JUST ADDED IT -- IMPOSSIBLE!\n"); exit(EXIT_FAILURE); }

printf("PUFCashAdd_WRec_Data(): DONE: Added WRec index %d\tnum_eCt %d\teCt_tot_bytes %d\n", 
   WRec_id, num_eCt, eCt_tot_bytes); fflush(stdout);
#ifdef DEBUG
#endif

   return;
   }


// ========================================================================================================
// PUFCash_WRec
// ========================================================================================================
// Alice, Bob and Bank: request a list of her withdrawal records (WRec_ids), which are just the unique id values 
// for the database records, or she gets the eCt, heCt blobs that are associated with a particular WRec. 
// NOTE: Updates to the withdrawal records are NOT done here -- see below.

int PUFCashGet_WRec_Data(int max_string_len, sqlite3 *DB_PUFCash_V3, int AnonChipNum, 
   int get_ids_or_eCt_blobs, int **WRec_ids_ptr, int WRec_id, unsigned char **eCt_buffer_ptr, 
   unsigned char **heCt_buffer_ptr, int *num_eCt_ptr)
   {
   SQLRowStringsStruct row_strings_struct;
   char sql_command_str[max_string_len];
   char *col1_name = "num_eCt";

   SQLIntStruct ID_index_struct; 

   int eCt_tot_bytes, heCt_tot_bytes;
   int withdraw_index;

printf("PUFCashGet_WRec_Data(): CALLED!\n"); fflush(stdout);
#ifdef DEBUG
#endif

// ===============================================
// Get a list of the database IDs of Alice withdrawals that are non-zero.
   if ( get_ids_or_eCt_blobs == 0 )
      {
      sprintf(sql_command_str, "SELECT ID FROM PUFCash_WRec WHERE (AnonChipNum = %d);", AnonChipNum);
      GetAllocateListOfInts(max_string_len, DB_PUFCash_V3, sql_command_str, &ID_index_struct);

      if ( ID_index_struct.num_ints == 0 )
         { 
         printf("WARNING: PUFCashGet_WRec_Data(): Did NOT find any eCt records in the PUFCash_WRec DB!\n"); 
         *WRec_ids_ptr = NULL; 
         return 0;
         }

// Note: Caller must free this list when done.
      *WRec_ids_ptr = ID_index_struct.int_arr;
      return ID_index_struct.num_ints;
      }

// ===============================================
// Else get num_eCt or the eCt/heCt blobs
   int ret_val = 0;

   sprintf(sql_command_str, "SELECT ID FROM PUFCash_WRec WHERE (id = %d);", WRec_id);
   GetAllocateListOfInts(max_string_len, DB_PUFCash_V3, sql_command_str, &ID_index_struct);

   if ( ID_index_struct.num_ints != 1 )
      { 
      printf("ERROR: PUFCashGet_WRec_Data(): WRec_id %d MUST have ONLY ONE DB record -- FOUND %d!\n", 
         WRec_id, ID_index_struct.num_ints); exit(EXIT_FAILURE); 
      }

// Get the index of Alice's withdrawal packet. 
   withdraw_index = ID_index_struct.int_arr[0];

   if ( ID_index_struct.int_arr != NULL )
      free(ID_index_struct.int_arr);
   ID_index_struct.int_arr = NULL;

// Get the num_eCt associated with one of the WRec ids returned above in the first call.
   sprintf(sql_command_str, "SELECT %s FROM PUFCash_WRec WHERE ID = %d;", col1_name, withdraw_index);
   GetStringsDataForRow(max_string_len, DB_PUFCash_V3, sql_command_str, &row_strings_struct);
   GetRowResultInt(&row_strings_struct, "PUFCashGet_WRec_Data()", 1, 0, col1_name, num_eCt_ptr);
   FreeStringsDataForRow(&row_strings_struct);
   ret_val = 1;

   ///////NEW//////////
   if(get_ids_or_eCt_blobs == 1 ) {
      return 1;
   }
   ////////////////////
   
// Also get the eCt and heCt blobs if requested.
   if ( get_ids_or_eCt_blobs == 2 )
      {

// Fetch eCt and heCt. Allocate storage. 
      char *SQL_get_Alice_eCt = "SELECT eCt FROM PUFCash_WRec WHERE ID = ?;";
      int allocate_storage = 1;
      eCt_tot_bytes = ReadBinaryBlob(DB_PUFCash_V3, SQL_get_Alice_eCt, withdraw_index, NULL, -1, allocate_storage, eCt_buffer_ptr);

      char *SQL_get_Alice_heCt = "SELECT heCt FROM PUFCash_WRec WHERE ID = ?;";
      heCt_tot_bytes = ReadBinaryBlob(DB_PUFCash_V3, SQL_get_Alice_heCt, withdraw_index, NULL, -1, allocate_storage, heCt_buffer_ptr);

      if ( eCt_tot_bytes != heCt_tot_bytes )
         { 
         printf("ERROR: PUFCashGet_WRec_Data(): WRec_id %d: number of bytes for eCt %d and heCt %d MUST BE the same!\n", 
            WRec_id, eCt_tot_bytes, heCt_tot_bytes); exit(EXIT_FAILURE); 
         }

printf("PUFCashGet_WRec_Data(): Got eCt and heCt for Alice of num_bytes %d!\n", eCt_tot_bytes); fflush(stdout);
#ifdef DEBUG
#endif

      ret_val = eCt_tot_bytes;
      }

printf("PUFCashGet_WRec_Data(): DONE\tNumber of eCt %d\n", *num_eCt_ptr); fflush(stdout);
#ifdef DEBUG
#endif

   return ret_val;
   }


// ========================================================================================================
// PUFCash_WRec
// ========================================================================================================
// Alice/Bob: updates a withdrawal record, identified as WRec. The update will be to delete the record WRec if 
// the eCt_tot_bytes is 0.

int PUFCashUpdate_WRec_Data(int max_string_len, sqlite3 *DB_PUFCash_V3, int WRec_id, unsigned char *eCt_buffer,
   unsigned char *heCt_buffer, int eCt_tot_bytes, int num_eCt)
   {
   char sql_command_str[max_string_len];
   SQLIntStruct ID_index_struct; 
   char *zErrMsg = 0;
   int fc;

   int WRec_num;

printf("PUFCashUpdate_WRec_Data(): CALLED!\n"); fflush(stdout);
#ifdef DEBUG
#endif

// Sanity check. Check for the existance of the record.
   sprintf(sql_command_str, "SELECT ID FROM PUFCash_WRec;");
   GetAllocateListOfInts(max_string_len, DB_PUFCash_V3, sql_command_str, &ID_index_struct);

   if ( ID_index_struct.num_ints == 0 )
      { printf("ERROR: PUFCashUpdate_WRec_Data(): Did NOT find any eCt records in the PUFCash_WRec DB!\n"); exit(EXIT_FAILURE); }

// Find the record specified as a parameter.
   for ( WRec_num = 0; WRec_num < ID_index_struct.num_ints; WRec_num++ )
      if ( ID_index_struct.int_arr[WRec_num] == WRec_id )
         break;

// ERROR if the WRec_id is NOT found.
   if ( WRec_num == ID_index_struct.num_ints )
      { printf("ERROR: PUFCashUpdate_WRec_Data(): Failed to find WRec_id %d in PUFCash_WRec DB!\n", WRec_id); exit(EXIT_FAILURE); }

// If no eCt remain, delete the WRec.
   if ( num_eCt == 0 )
      {
      sprintf(sql_command_str, "DELETE FROM PUFCash_WRec WHERE ID = %d;", WRec_id);
      fc = sqlite3_exec(DB_PUFCash_V3, sql_command_str, NULL, 0, &zErrMsg);
      if ( fc != SQLITE_OK )
         { printf("PUFCashUpdate_WRec_Data(): SQL ERROR: %s\n", zErrMsg); sqlite3_free(zErrMsg); exit(EXIT_FAILURE); }
      }
   else
      {
      char *eCt_hex = NULL, *heCt_hex = NULL, hex_byte[3];
      char *long_command_str = NULL;

#ifdef DEBUG
printf("PUFCashUpdate_WRec_Data(): Allocating 2X storage + 1 bytes %d for HEX strings\n", 2*eCt_tot_bytes+1); fflush(stdout);
#endif

      Allocate1DString((char **)(&eCt_hex), 2*eCt_tot_bytes+1);
      Allocate1DString((char **)(&heCt_hex), 2*eCt_tot_bytes+1);
      Allocate1DString((char **)(&long_command_str), 4*eCt_tot_bytes+200);

#ifdef DEBUG
printf("PUFCashUpdate_WRec_Data(): Converting eCt/heCt buffers to HEX strings\n"); fflush(stdout);
#endif

// Make it a zero-length string so we can use strcat below.
      eCt_hex[0] = '\0';
      heCt_hex[0] = '\0';
      hex_byte[2] = '\0';
      int i;
      for ( i = 0; i < eCt_tot_bytes; i++ )
         {

// Print each byte as a 2 hex char string.
         sprintf(hex_byte, "%02X", eCt_buffer[i]);
         strcat(eCt_hex, hex_byte);
         sprintf(hex_byte, "%02X", heCt_buffer[i]);
         strcat(heCt_hex, hex_byte);
         }

// NULL terminate so we can treat this as a NULL-terminated string below.
      eCt_hex[2*eCt_tot_bytes] = '\0';
      heCt_hex[2*eCt_tot_bytes] = '\0';

#ifdef DEBUG
printf("PUFCashUpdate_WRec_Data(): eCt_buffer as hex string '%s'\n", eCt_hex); fflush(stdout);
printf("PUFCashUpdate_WRec_Data(): heCt_buffer as hex string '%s'\n", heCt_hex); fflush(stdout);
#endif

      sprintf(long_command_str, "UPDATE PUFCash_WRec SET num_eCt = %d, eCt = X'%s', heCt = X'%s' WHERE ID = %d;", 
         num_eCt, eCt_hex, heCt_hex, WRec_id);

      fc = sqlite3_exec(DB_PUFCash_V3, long_command_str, NULL, 0, &zErrMsg);
      if ( fc != SQLITE_OK )
         { printf("SQL ERROR: %s\n", zErrMsg); sqlite3_free(zErrMsg); exit(EXIT_FAILURE); }

      if ( eCt_hex != NULL )
         free(eCt_hex); 
      if ( heCt_hex != NULL )
         free(heCt_hex); 
      if ( long_command_str != NULL )
         free(long_command_str); 
      }

printf("PUFCashUpdate_WRec_Data(): DONE!\n"); fflush(stdout);
#ifdef DEBUG
#endif

   return 1;
   }


// ========================================================================================================
// PUFCash_Account
// ========================================================================================================
// TTP: Add a account record to the PUFCash_Account Table for Alice, which represents a transaction ID
// (TID) and an amount.

int PUFCashAddAcctRec(int max_string_len, sqlite3 *DB_PUFCash_V3, int Alice_chip_num, int TID, 
   int num_eCt, int min_withdraw_increment)
   {
   SQLIntStruct ID_index_struct; 
   char sql_command_str[max_string_len];

   int acct_ID;

#ifdef DEBUG
printf("PUFCashAddAcctRec(): CALLED!\n"); fflush(stdout);
#endif

// Sanity checks
   if ( TID < 0 )
      { printf("ERROR: PUFCashAddAcctRec(): Expected TID > 0 %d\n", TID); exit(EXIT_FAILURE); }

   if ( num_eCt <= 0 || (num_eCt % min_withdraw_increment) != 0 )
      { 
      printf("ERROR: PUFCashAddAcctRec(): Expected num_eCt %d > 0 and divisible by %d\n", 
         num_eCt, min_withdraw_increment); exit(EXIT_FAILURE); 
      }

// Get the index of the relevant element. Right now, we assume Alice has only one entry.
   sprintf(sql_command_str, "SELECT ID FROM PUFCash_Account WHERE (ChipNum = %d AND TID = %d);", Alice_chip_num, TID);
   GetAllocateListOfInts(max_string_len, DB_PUFCash_V3, sql_command_str, &ID_index_struct);

   if ( ID_index_struct.int_arr != NULL )
      free(ID_index_struct.int_arr);
   ID_index_struct.int_arr = NULL;

   if ( ID_index_struct.num_ints != 0 )
      { 
      printf("ERROR: PUFCashAddAcctRec(): Only ONE Account record allowed (right now) for Alice_chip_num %d and TID %d -- FOUND %d!\n", 
         Alice_chip_num, TID, ID_index_struct.num_ints); 
      return 0;
      }

#ifdef DEBUG
printf("\tPUFCashAddAcctRec(): Inserting Alice_chip_num %d\tTID %d\tnum_eCt %d into PUFCash_Account Table!\n",
   Alice_chip_num, TID, num_eCt); fflush(stdout);
#endif

   InsertIntoTable_RT(max_string_len, DB_PUFCash_V3, "PUFCash_Account", SQL_PUFCash_Account_insert_into_cmd, 
      NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, 
      Alice_chip_num, TID, num_eCt, 0, 0, 0);

// Get the index of the element just inserted.
   acct_ID = GetIndexFromTable_RT(max_string_len, DB_PUFCash_V3, "PUFCash_Account", SQL_PUFCash_Account_get_index_cmd, 
      NULL, 0, NULL, NULL, NULL, NULL, Alice_chip_num, 0, 0);

// Sanity check
   if ( acct_ID == -1 )
      { printf("ERROR: PUFCashAddAcctRec(): Alice's acct_ID NOT FOUND -- JUST ADDED IT -- IMPOSSIBLE!\n"); exit(EXIT_FAILURE); }

#ifdef DEBUG
printf("PUFCashAddAcctRec(): DONE: Added Alice's Account record with Alice_chip_num %d\tTID %d\tnum_eCt %d -- Index %d\n", 
   Alice_chip_num, TID, num_eCt, acct_ID); fflush(stdout);
#endif

   return 1;
   }


// ========================================================================================================
// PUFCash_Account
// ========================================================================================================
// TTP: Get and/or update an account record from the PUFCash_V3 Account Table for Alice, using her Alice_chip_num.
// Assume there is only one transaction ID (TID) record in the DB at this point.

int PUFCashGetAcctRec(int max_string_len, sqlite3 *DB_PUFCash_V3, int Alice_chip_num, int *TID_ptr, 
   int *num_eCt_ptr, int do_update, int update_amt)
   {
   SQLIntStruct ID_index_struct; 

   SQLRowStringsStruct row_strings_struct;
   char sql_command_str[max_string_len];
   char *col1_name = "TID";
   char *col2_name = "Amount";

   char *zErrMsg = 0;
   int fc;

   int Acct_index;

printf("PUFCashGetAcctRec(): BEGIN for Alice_chip_num %d\n", Alice_chip_num); fflush(stdout);
#ifdef DEBUG
#endif

// Get the index of the relevant element. Right now, we assume Alice has only one entry.
//   sprintf(sql_command_str, "SELECT ID FROM PUFCash_Account WHERE (DeviceID = %d AND TID = %d);", Alice_chip_num, *TID_ptr);
   sprintf(sql_command_str, "SELECT ID FROM PUFCash_Account WHERE ChipNum = %d;", Alice_chip_num);
   GetAllocateListOfInts(max_string_len, DB_PUFCash_V3, sql_command_str, &ID_index_struct);

   if ( ID_index_struct.num_ints != 1 )
      { printf("ERROR: PUFCashGetAcctRec(): Only 1 entry is allowed for Alice -- FOUND %d!\n", ID_index_struct.num_ints); exit(EXIT_FAILURE); }

// Get the index of Alice's withdrawal packet. 
   Acct_index = ID_index_struct.int_arr[0];

   if ( ID_index_struct.int_arr != NULL )
      free(ID_index_struct.int_arr);
   ID_index_struct.int_arr = NULL;

// Now get the TID and num_eCt (Amount).
   sprintf(sql_command_str, "SELECT %s, %s FROM PUFCash_Account WHERE ID = %d;", col1_name, col2_name, Acct_index);
   GetStringsDataForRow(max_string_len, DB_PUFCash_V3, sql_command_str, &row_strings_struct);
   GetRowResultInt(&row_strings_struct, "PUFCashGetAcctRec()", 2, 0, col1_name, TID_ptr);
   GetRowResultInt(&row_strings_struct, "PUFCashGetAcctRec()", 2, 1, col2_name, num_eCt_ptr);
   FreeStringsDataForRow(&row_strings_struct);

printf("PUFCashGetAcctRec(): Alice_chip_num %d\tGot TID %d and num_eCt %d for ID %d in PUFCash_Account Table!\n", 
   Alice_chip_num, *TID_ptr, *num_eCt_ptr, Acct_index); fflush(stdout);
#ifdef DEBUG
#endif

// Update the amount.
   if ( do_update == 1 )
      {

// Sanity check
      if ( update_amt < 0 )
         { 
         printf("ERROR: PUFCashAddAcctRec(): Update amount %d is NEGATIVE!\n", update_amt); 
         return 0;
         }

printf("PUFCashAddAcctRec(): Updating Amount from %d to %d\n", *num_eCt_ptr, update_amt); fflush(stdout);
#ifdef DEBUG
#endif

      sprintf(sql_command_str, "UPDATE PUFCash_Account SET Amount = %d WHERE ID = %d;", update_amt, Acct_index);
      fc = sqlite3_exec(DB_PUFCash_V3, sql_command_str, NULL, 0, &zErrMsg);
      if ( fc != SQLITE_OK )
         { printf("SQL ERROR: %s\n", zErrMsg); sqlite3_free(zErrMsg); exit(EXIT_FAILURE); }
      }

printf("PUFCashAddAcctRec(): DONE\n"); fflush(stdout);
#ifdef DEBUG
#endif

   return 1;
   }


// ========================================================================================================
// PUFCash_LLK
// ========================================================================================================
// Bank, Alice/Bob: Add LLK information into the PUFCash_LLK table, which includes Alice's non-anonyous chip 
// number, anonymous chip number, mask, Chlng_blob and status. The LLK_type is used to distinguish between 
// the LLK_blob/LLK Challenges type.

int PUFCashAddLLKChlngInfo(int max_string_len, sqlite3 *DB_PUFCash_V3, int chip_num, int anon_chip_num, 
   unsigned char *Chlng_blob, int Chlng_blob_num_bytes, unsigned char mask[2], int LLK_type, int allow_only_one)
   {
   char sql_command_str[max_string_len];
   SQLIntStruct ID_index_struct;
   char *zErrMsg = 0;
   int fc;

   int LLK_index;

printf("PUFCashAddLLKChlngInfo(): CALLED!\n"); fflush(stdout);
#ifdef DEBUG
#endif

// Sanity checks. NOTE: Valid data (checks for NULL) are done in AssembleChlngPacket
   if ( chip_num < 0 )
      { 
      printf("ERROR: PUFCashAddLLKChlngInfo(): Expected chip_num >= 0 %d\n", chip_num); exit(EXIT_FAILURE); 
      }

   if ( mask == NULL )
      { printf("ERROR: PUFCashAddLLKChlngInfo(): mask is NULL\n"); exit(EXIT_FAILURE); }

   if ( Chlng_blob_num_bytes <= 0 )
      { printf("ERROR: PUFCashAddLLKChlngInfo(): Expected Chlng_blob_num_bytes >= 0 %d\n", Chlng_blob_num_bytes); exit(EXIT_FAILURE); }

// 7_2_2022: If we find more than one element of the given LLK_type, delete them. 
   if ( allow_only_one == 1 )
      {
      sprintf(sql_command_str, "SELECT ID FROM PUFCash_LLK WHERE status = %d;", LLK_type);
      GetAllocateListOfInts(max_string_len, DB_PUFCash_V3, sql_command_str, &ID_index_struct);

      if ( ID_index_struct.num_ints > 0 )
         { 
         printf("PUFCashAddLLKChlngInfo(): Found %d existing DB elements -- deleting them!\n", ID_index_struct.num_ints); fflush(stdout);

         sprintf(sql_command_str, "DELETE FROM PUFCash_LLK WHERE status = %d;", LLK_type);
         fc = sqlite3_exec(DB_PUFCash_V3, sql_command_str, NULL, 0, &zErrMsg);
         if ( fc != SQLITE_OK )
            { printf("PUFCashAddLLKChlngInfo(): SQL ERROR: %s\n", zErrMsg); sqlite3_free(zErrMsg); exit(EXIT_FAILURE); }
         }
      if ( ID_index_struct.int_arr != NULL )
         free(ID_index_struct.int_arr);
      ID_index_struct.int_arr = NULL;
      }

#ifdef DEBUG
printf("PUFCashAddLLKChlngInfo(): Inserting CH_LLK info into PUFCash_LLK with STATUS %d!\n", LLK_type); fflush(stdout);
#endif
   int mask_int;
   mask_int = ((int)mask[1] << 8) + (int)mask[0];

   InsertIntoTable_RT(max_string_len, DB_PUFCash_V3, "PUFCash_LLK", SQL_PUFCash_LLK_insert_into_cmd, 
      Chlng_blob, Chlng_blob_num_bytes, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, 
      chip_num, anon_chip_num, mask_int, LLK_type, 0, 0);

// Get the index of the element just inserted.
   LLK_index = GetIndexFromTable_RT(max_string_len, DB_PUFCash_V3, "PUFCash_LLK", SQL_PUFCash_LLK_get_index_cmd, 
      NULL, 0, NULL, NULL, NULL, NULL, LLK_type, 0, 0);

// Sanity check
   if ( LLK_index == -1 )
      { printf("ERROR: PUFCashAddLLKChlngInfo(): LLK_index NOT FOUND -- JUST ADDED IT -- IMPOSSIBLE!\n"); exit(EXIT_FAILURE); }

printf("PUFCashAddLLKChlngInfo(): DONE!\n"); fflush(stdout);
#ifdef DEBUG
#endif

   return LLK_index;
   }


// ========================================================================================================
// PUFCash_LLK
// ========================================================================================================
// Get an LLK or challenge from the PUFCash_LLK table, which is basically all the information needed by the 
// KEK FSB algorithm to regenerate the LLK. Note that this routine supports fetching of the LLK or Chlng 
// information needed to generate the LLK (which is NOT stored). Alice and Bob use the latter functionality.

int PUFCashGetLLKChlngInfo(int max_string_len, sqlite3 *DB_PUFCash_V3, int *chip_num_ptr,
   int *anon_chip_num_ptr, unsigned char **Chlng_blob_ptr, int *Chlng_blob_num_bytes_ptr,
   int allow_multiple_LLK, int *Chlng_index_ptr, int status, int check_exists_only, unsigned char mask[2])
   {
   SQLIntStruct Chlng_ID_index_struct; 
   int Chlng_index;

   SQLRowStringsStruct row_strings_struct;
   char sql_command_str[max_string_len];
   char *col1_name = "ChipNum";
   char *col2_name = "AnonChipNum";
   char *col3_name = "mask";

   char *SQL_read_Chlng_cmd = "SELECT Chlng FROM PUFCash_LLK WHERE ID = ?;";

   int mask_int = 0;
   int index_to_use = 0;

#ifdef DEBUG
printf("\nPUFCashGetLLKChlngInfo(): CALLED!\n"); fflush(stdout);
#endif

// If enrollment has been done, then we will succeed in finding a DB record. Note that Status here is really LLK_type.
   sprintf(sql_command_str, "SELECT ID FROM PUFCash_LLK WHERE Status = %d;", status);
   GetAllocateListOfInts(max_string_len, DB_PUFCash_V3, sql_command_str, &Chlng_ID_index_struct);

// If no records exist, return 0
   if ( Chlng_ID_index_struct.num_ints == 0 )
      { 
      printf("WARNING: PUFCashGetLLKChlngInfo(): No Chlng's of LLK_type %d found in DB!\n", status); 
      if ( Chlng_ID_index_struct.int_arr != NULL )
         free(Chlng_ID_index_struct.int_arr);
      Chlng_ID_index_struct.int_arr = NULL;
      return 0;
      }

// If we are only checking for the existance of an LLK in the database, then return 1 that we found a record.
   if ( check_exists_only == 1 )
      return 1;

// Sanity check. Should be only one ZeroTrust_LLK in the DB.
   if ( allow_multiple_LLK == 0 && Chlng_ID_index_struct.num_ints != 1 )
      { 
      printf("ERROR: PUFCashGetLLKChlngInfo(): More than one LLK_type (status) = %d element exist in PUFCash_LLK Table!\n", status); 
      exit(EXIT_FAILURE); 
      }
   if ( Chlng_ID_index_struct.num_ints != 1 )
      { 
      printf("WARNING: PUFCashGetLLKChlngInfo(): Found more than one LLK_type = %d in PUFCash_LLK Table -- using element %d!\n", 
         status, index_to_use); fflush(stdout); 
      }

// Get the first one.
   Chlng_index = Chlng_ID_index_struct.int_arr[index_to_use];

#ifdef DEBUG
printf("PUFCashGetLLKChlngInfo(): Found %d Chlngs with LLK_type (status) field set to %d!\n", 
   Chlng_ID_index_struct.num_ints, status); fflush(stdout);
#endif

// Get the integer data associated with a particular DB record. 
   sprintf(sql_command_str, "SELECT %s, %s, %s FROM PUFCash_LLK WHERE ID = %d;", col1_name, col2_name, col3_name, Chlng_index);
   GetStringsDataForRow(max_string_len, DB_PUFCash_V3, sql_command_str, &row_strings_struct);
   GetRowResultInt(&row_strings_struct, "PUFCashGetLLKChlngInfo()", 3, 0, col1_name, chip_num_ptr);
   GetRowResultInt(&row_strings_struct, "PUFCashGetLLKChlngInfo()", 3, 1, col2_name, anon_chip_num_ptr);
   GetRowResultInt(&row_strings_struct, "PUFCashGetLLKChlngInfo()", 3, 2, col3_name, &mask_int);
   FreeStringsDataForRow(&row_strings_struct);

#ifdef DEBUG
printf("PUFCashGetLLKChlngInfo(): Mask [%02X][%02X]\t chip_num %d\tanon_chip_num %d\tfor LLK index %d\n", 
   (int)mask[1], (int)mask[2], *chip_num_ptr, *anon_chip_num_ptr, Chlng_index); fflush(stdout);
#endif

// Fetch the Chlng_blob. 
   int mask_expected;

// Sanity check. Compare the expected mask with the mask stored in the DB.
   mask_expected = ((int)mask[1] << 8) + (int)mask[0];
   if ( mask_int != mask_expected )
      { printf("ERROR: PUFCashGetLLKChlngInfo(): DB mask_int %d != to expected mask %d!\n", mask_int, mask_expected); exit(EXIT_FAILURE); }

// Read the Chlng_blob from the DB
   *Chlng_blob_num_bytes_ptr = ReadBinaryBlob(DB_PUFCash_V3, SQL_read_Chlng_cmd, Chlng_index, NULL, 0, 1, Chlng_blob_ptr);

#ifdef DEBUG
if ( *XOR_nonce_ptr != NULL )
   PrintHeaderAndHexVals("XOR_nonce:\n", XOR_nonce_num_bytes, *XOR_nonce_ptr, 32);
if ( *XHD_ptr != NULL )
   PrintHeaderAndHexVals("XHD:\n", XHD_num_bytes, *XHD_ptr, 32);
#endif

   if ( Chlng_ID_index_struct.int_arr != NULL )
      free(Chlng_ID_index_struct.int_arr);
   Chlng_ID_index_struct.int_arr = NULL;
   Chlng_ID_index_struct.num_ints = 0;

// Return the index in case it is needed to relocate this record.
   *Chlng_index_ptr = Chlng_index;

#ifdef DEBUG
printf("PUFCashGetLLKChlngInfo(): DONE!\n"); fflush(stdout);
#endif

   return 1;
   }
