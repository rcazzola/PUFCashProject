PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS Bitstrings ( 
   id INTEGER PRIMARY KEY,
   DesignIndex INTEGER NOT NULL,
   NetlistName TEXT NOT NULL, 
   SynthesisName TEXT NOT NULL,
   InstanceName TEXT NOT NULL,
   Dev TEXT NOT NULL,
   Placement TEXT NOT NULL,
   PUFInstanceID INTEGER NOT NULL,
   ChallengeSetName TEXT NOT NULL, 
   CreationDate TEXT NOT NULL,
   SecurityFunction TEXT NOT NULL,
   FixParams TEXT NOT NULL,
   LFSRSeedLow INTEGER NOT NULL,
   LFSRSeedHigh INTEGER NOT NULL,
   RangeConstant REAL NOT NULL,
   SpreadConstant INTEGER NOT NULL,
   Threshold INTEGER NOT NULL,
   Bitstring TEXT NOT NULL 
   );

