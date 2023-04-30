PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS PUFCash_LLK ( 
   id INTEGER PRIMARY KEY,
   ChipNum INTEGER NOT NULL,
   AnonChipNum INTEGER NOT NULL,
   mask INTEGER NOT NULL,
   Chlng BLOB NOT NULL,
   Status INTEGER NOT NULL
   );

CREATE UNIQUE INDEX LLK_ID_index ON PUFCash_LLK (id);