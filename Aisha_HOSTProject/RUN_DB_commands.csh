
# Create RunTime.db (if it doesn't exist) and these tables
sqlite3 RunTime.db < SQLSchemaScripts/SQL_Bitstrings_create_table.sql

# ZeroTrust
sqlite3 AuthenticationToken.db < SQLSchemaScripts/SQL_ZeroTrustAuthenToken_create_table.sql


# LLK stores chip numbers, challenge fields OR LLKs for Alice and TI, respectively, and type and status.
# WRec stores anonymous chip numbers LLK_id link to LLK table, eCt, heCt, the number of eCt and status
# Account used by TTP (commercial Bank) to store Account information for Alice/Bob.
sqlite3 PUFCash_V3.db < SQLSchemaScripts/SQL_PUFCash_LLK_create_table.sql
sqlite3 PUFCash_V3.db < SQLSchemaScripts/SQL_PUFCash_WRec_create_table.sql
sqlite3 PUFCash_V3.db < SQLSchemaScripts/SQL_PUFCash_Account_create_table.sql



sqlite3 PUFCash_V3_empty.db < SQLSchemaScripts/SQL_PUFCash_LLK_create_table.sql
sqlite3 PUFCash_V3_empty.db < SQLSchemaScripts/SQL_PUFCash_WRec_create_table.sql
sqlite3 PUFCash_V3_empty.db < SQLSchemaScripts/SQL_PUFCash_Account_create_table.sql
