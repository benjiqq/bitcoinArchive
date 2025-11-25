================================================================================
BITCOIN SOURCE CODE COMMENT EXTRACTION
================================================================================

BITCOIN 0.1 SOURCE FILES
================================================================================

File: /home/user/bitcoinArchive/bitcoin0.1/src/db.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 12] Single-line comment:
  //
[Line 13] Single-line comment:
  // CDB
[Line 14] Single-line comment:
  //
[Line 68] Single-line comment:
  /// debug
[Line 69] Single-line comment:
  ///dbenv.log_set_config(DB_LOG_AUTO_REMOVE, 1); /// causes corruption
[Line 91] Single-line comment:
  // Txn pointer
[Line 92] Single-line comment:
  // Filename
[Line 93] Single-line comment:
  // Logical db name
[Line 94] Single-line comment:
  // Database type
[Line 95] Single-line comment:
  // Flags
[Line 134] Single-line comment:
  // Flush log data to the actual data file
[Line 135] Single-line comment:
  //  on all files that are not in use
[Line 169] Single-line comment:
  //
[Line 170] Single-line comment:
  // CTxDB
[Line 171] Single-line comment:
  //
[Line 190] Single-line comment:
  // Add to tx index
[Line 215] Single-line comment:
  // Get cursor
[Line 223] Single-line comment:
  // Read next record
[Line 235] Single-line comment:
  // Unserialize
[Line 243] Single-line comment:
  // Read transaction
[Line 307] Single-line comment:
  // Return existing
[Line 312] Single-line comment:
  // Create new
[Line 324] Single-line comment:
  // Get cursor
[Line 332] Single-line comment:
  // Read next record
[Line 344] Single-line comment:
  // Unserialize
[Line 352] Single-line comment:
  // Construct block index object
[Line 365] Single-line comment:
  // Watch for genesis block and best block
[Line 395] Single-line comment:
  //
[Line 396] Single-line comment:
  // CAddrDB
[Line 397] Single-line comment:
  //
[Line 408] Single-line comment:
  // Load user provided addresses
[Line 425] Single-line comment:
  // Get cursor
[Line 432] Single-line comment:
  // Read next record
[Line 441] Single-line comment:
  // Unserialize
[Line 452] Single-line comment:
  //// debug print
[Line 470] Single-line comment:
  //
[Line 471] Single-line comment:
  // CReviewDB
[Line 472] Single-line comment:
  //
[Line 476] Single-line comment:
  // msvc workaround, just need to do anything with vReviews
[Line 491] Single-line comment:
  //
[Line 492] Single-line comment:
  // CWalletDB
[Line 493] Single-line comment:
  //
[Line 499] Single-line comment:
  //// todo: shouldn't we catch exceptions and try to recover and continue?
[Line 503] Single-line comment:
  // Get cursor
[Line 510] Single-line comment:
  // Read next record
[Line 519] Single-line comment:
  // Unserialize
[Line 520] Single-line comment:
  // Taking advantage of the fact that pair serialization
[Line 521] Single-line comment:
  // is just the two items serialized one after the other
[Line 540] Single-line comment:
  //// debug print
[Line 541] Single-line comment:
  //printf("LoadWallet  %s\n", wtx.GetHash().ToString().c_str());
[Line 542] Single-line comment:
  //printf(" %12I64d  %s  %s  %s\n",
[Line 543] Single-line comment:
  //    wtx.vout[0].nValue,
[Line 544] Single-line comment:
  //    DateTimeStr(wtx.nTime).c_str(),
[Line 545] Single-line comment:
  //    wtx.hashBlock.ToString().substr(0,14).c_str(),
[Line 546] Single-line comment:
  //    wtx.mapValue["message"].c_str());
[Line 562] Single-line comment:
  /// or settings or option or options or config?
[Line 588] Single-line comment:
  // Set keyUser
[Line 594] Single-line comment:
  // Create new keyUser and set as default key

File: /home/user/bitcoinArchive/bitcoin0.1/src/headers.h
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.

File: /home/user/bitcoinArchive/bitcoin0.1/src/irc.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 82] Single-line comment:
  // socket closed
[Line 88] Single-line comment:
  // socket error
[Line 204] Single-line comment:
  // index 7 is limited to 16 characters
[Line 205] Single-line comment:
  // could get full length name at index 10, but would be different from join messages
[Line 212] Single-line comment:
  // :username!username@50000007.F000000B.90000002.IP JOIN :#channelname

File: /home/user/bitcoinArchive/bitcoin0.1/src/main.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 12] Single-line comment:
  //
[Line 13] Single-line comment:
  // Global state
[Line 14] Single-line comment:
  //
[Line 48] Single-line comment:
  // Settings
[Line 60] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 61] Single-line comment:
  //
[Line 62] Single-line comment:
  // mapKeys
[Line 63] Single-line comment:
  //
[Line 87] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 88] Single-line comment:
  //
[Line 89] Single-line comment:
  // mapWallet
[Line 90] Single-line comment:
  //
[Line 97] Single-line comment:
  // Inserts only if not already there, returns tx inserted or tx found
[Line 104] Single-line comment:
  //// debug print
[Line 109] Single-line comment:
  // Merge
[Line 136] Single-line comment:
  // Write to disk
[Line 140] Single-line comment:
  // Notify UI
[Line 144] Single-line comment:
  // Refresh UI
[Line 154] Single-line comment:
  // Get merkle branch if transaction was found in a block
[Line 180] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 181] Single-line comment:
  //
[Line 182] Single-line comment:
  // mapOrphanTransactions
[Line 183] Single-line comment:
  //
[Line 226] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 227] Single-line comment:
  //
[Line 228] Single-line comment:
  // CTransaction
[Line 229] Single-line comment:
  //
[Line 267] Single-line comment:
  // If we did not receive the transaction directly, we rely on the block's
[Line 268] Single-line comment:
  // time to figure out when it happened.  We use the median over a range
[Line 269] Single-line comment:
  // of blocks to try to filter out inaccurate block times.
[Line 298] Single-line comment:
  // Load the block this tx is in
[Line 307] Single-line comment:
  // Update the tx's hashBlock
[Line 310] Single-line comment:
  // Locate the transaction
[Line 322] Single-line comment:
  // Fill in merkle branch
[Line 326] Single-line comment:
  // Is the tx in a block that's in the main chain
[Line 350] Single-line comment:
  // This critsect is OK because txdb is already open
[Line 411] Single-line comment:
  // Coinbase is only valid in a block, not as a loose transaction
[Line 418] Single-line comment:
  // Do we already have it?
[Line 427] Single-line comment:
  // Check for conflicts with in-memory transactions
[Line 434] Single-line comment:
  // Allow replacing with a newer version of the same transaction
[Line 450] Single-line comment:
  // Check against previous transactions
[Line 460] Single-line comment:
  // Store transaction in memory
[Line 471] Single-line comment:
  ///// are we sure this is ok when loading transactions or restoring block txes
[Line 472] Single-line comment:
  // If updated, erase old tx from wallet
[Line 483] Single-line comment:
  // Add to memory pool without checking anything.  Don't call this directly,
[Line 484] Single-line comment:
  // call AcceptTransaction to properly check the transaction first.
[Line 499] Single-line comment:
  // Remove transaction from memory pool
[Line 520] Single-line comment:
  // Find the block it claims to be in
[Line 528] Single-line comment:
  // Make sure the merkle branch connects to this block
[Line 585] Single-line comment:
  // Reaccept any txes of ours that aren't already in a block
[Line 628] Single-line comment:
  // Rebroadcast any of our txes that aren't in a block yet
[Line 633] Single-line comment:
  // Sort them in chronological order
[Line 657] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 658] Single-line comment:
  //
[Line 659] Single-line comment:
  // CBlock and CBlockIndex
[Line 660] Single-line comment:
  //
[Line 669] Single-line comment:
  // Work back to the first block in the orphan chain
[Line 679] Single-line comment:
  // Subsidy is cut in half every 4 years
[Line 687] Single-line comment:
  // two weeks
[Line 691] Single-line comment:
  // Genesis block
[Line 695] Single-line comment:
  // Only change once per interval
[Line 699] Single-line comment:
  // Go back by what we want to be 14 days worth of blocks
[Line 705] Single-line comment:
  // Limit adjustment step
[Line 713] Single-line comment:
  // Retarget
[Line 722] Single-line comment:
  /// debug print
[Line 741] Single-line comment:
  // Relinquish previous transactions' spent pointers
[Line 748] Single-line comment:
  // Get prev txindex from disk
[Line 756] Single-line comment:
  // Mark outpoint as not spent
[Line 759] Single-line comment:
  // Write back
[Line 764] Single-line comment:
  // Remove transaction from index
[Line 774] Single-line comment:
  // Take over previous transactions' spent pointers
[Line 782] Single-line comment:
  // Read txindex
[Line 787] Single-line comment:
  // Get txindex from current proposed changes
[Line 792] Single-line comment:
  // Read txindex from txdb
[Line 798] Single-line comment:
  // Read txPrev
[Line 802] Single-line comment:
  // Get prev tx from single transactions in memory
[Line 814] Single-line comment:
  // Get prev tx from disk
[Line 822] Single-line comment:
  // If prev is coinbase, check that it's matured
[Line 828] Single-line comment:
  // Verify signature
[Line 832] Single-line comment:
  // Check for conflicts
[Line 836] Single-line comment:
  // Mark outpoints as spent
[Line 839] Single-line comment:
  // Write back
[Line 848] Single-line comment:
  // Tally transaction fees
[Line 859] Single-line comment:
  // Add transaction to disk index
[Line 865] Single-line comment:
  // Add transaction to test pool
[Line 878] Single-line comment:
  // Take over previous transactions' spent pointers
[Line 884] Single-line comment:
  // Get prev tx from single transactions in memory
[Line 893] Single-line comment:
  // Verify signature
[Line 897] Single-line comment:
  ///// this is redundant with the mapNextTx stuff, not sure which I want to get rid of
[Line 898] Single-line comment:
  ///// this has to go away now that posNext is gone
[Line 899] Single-line comment:
  // // Check for conflicts
[Line 900] Single-line comment:
  // if (!txPrev.vout[prevout.n].posNext.IsNull())
[Line 901] Single-line comment:
  //     return error("ConnectInputs() : prev tx already used");
[Line 902] Single-line comment:
  //
[Line 903] Single-line comment:
  // // Flag outpoints as used
[Line 904] Single-line comment:
  // txPrev.vout[prevout.n].posNext = posThisTx;
[Line 920] Single-line comment:
  // Disconnect in reverse order
[Line 925] Single-line comment:
  // Update block index on disk without changing it in memory.
[Line 926] Single-line comment:
  // The memory index structure will be changed after the db commits.
[Line 939] Single-line comment:
  //// issue here: it doesn't know the version
[Line 956] Single-line comment:
  // Update block index on disk without changing it in memory.
[Line 957] Single-line comment:
  // The memory index structure will be changed after the db commits.
[Line 965] Single-line comment:
  // Watch for transactions paying to me
[Line 978] Single-line comment:
  // Find the fork
[Line 990] Single-line comment:
  // List of what to disconnect
[Line 995] Single-line comment:
  // List of what to connect
[Line 1001] Single-line comment:
  // Disconnect shorter branch
[Line 1011] Single-line comment:
  // Queue memory transactions to resurrect
[Line 1017] Single-line comment:
  // Connect longer branch
[Line 1027] Single-line comment:
  // Invalid block, delete the rest of this branch
[Line 1040] Single-line comment:
  // Queue memory transactions to delete
[Line 1047] Single-line comment:
  // Commit now because resurrecting could take some time
[Line 1050] Single-line comment:
  // Disconnect shorter branch
[Line 1055] Single-line comment:
  // Connect longer branch
[Line 1060] Single-line comment:
  // Resurrect memory transactions that were in the disconnected branch
[Line 1064] Single-line comment:
  // Delete redundant memory transactions that are in the connected branch
[Line 1074] Single-line comment:
  // Check for duplicate
[Line 1079] Single-line comment:
  // Construct new block index object
[Line 1096] Single-line comment:
  // New best
[Line 1106] Single-line comment:
  // Adding to current best branch
[Line 1118] Single-line comment:
  // Delete redundant memory transactions
[Line 1124] Single-line comment:
  // New best branch
[Line 1132] Single-line comment:
  // New best link
[Line 1143] Single-line comment:
  // Relay wallet transactions that haven't gotten in yet
[Line 1156] Single-line comment:
  // These are checks that are independent of context
[Line 1157] Single-line comment:
  // that can be verified before saving an orphan block.
[Line 1159] Single-line comment:
  // Size limits
[Line 1163] Single-line comment:
  // Check timestamp
[Line 1167] Single-line comment:
  // First transaction must be coinbase, the rest must not be
[Line 1174] Single-line comment:
  // Check transactions
[Line 1179] Single-line comment:
  // Check proof of work matches claimed amount
[Line 1185] Single-line comment:
  // Check merkleroot
[Line 1194] Single-line comment:
  // Check for duplicate
[Line 1199] Single-line comment:
  // Get prev block index
[Line 1205] Single-line comment:
  // Check timestamp against prev
[Line 1209] Single-line comment:
  // Check proof of work
[Line 1213] Single-line comment:
  // Write block to history file
[Line 1224] Single-line comment:
  // // Add atoms to user reviews for coins created
[Line 1225] Single-line comment:
  // vector<unsigned char> vchPubKey;
[Line 1226] Single-line comment:
  // if (ExtractPubKey(vtx[0].vout[0].scriptPubKey, false, vchPubKey))
[Line 1227] Single-line comment:
  // {
[Line 1228] Single-line comment:
  //     unsigned short nAtom = GetRand(USHRT_MAX - 100) + 100;
[Line 1229] Single-line comment:
  //     vector<unsigned short> vAtoms(1, nAtom);
[Line 1230] Single-line comment:
  //     AddAtomsAndPropagate(Hash(vchPubKey.begin(), vchPubKey.end()), vAtoms, true);
[Line 1231] Single-line comment:
  // }
[Line 1238] Single-line comment:
  // Check for duplicate
[Line 1245] Single-line comment:
  // Preliminary checks
[Line 1252] Single-line comment:
  // If don't already have its previous block, shunt it off to holding area until we get it
[Line 1259] Single-line comment:
  // Ask this guy to fill in what we're missing
[Line 1265] Single-line comment:
  // Store to disk
[Line 1273] Single-line comment:
  // Recursively process any orphan blocks that depended on this one
[Line 1306] Single-line comment:
  // Scan ahead to the next pchMessageStart, which should normally be immediately
[Line 1307] Single-line comment:
  // at the file pointer.  Leaves file pointer at end of pchMessageStart.
[Line 1409] Single-line comment:
  // FAT32 filesize max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
[Line 1422] Single-line comment:
  //
[Line 1423] Single-line comment:
  // Load block index
[Line 1424] Single-line comment:
  //
[Line 1430] Single-line comment:
  //
[Line 1431] Single-line comment:
  // Init with genesis block
[Line 1432] Single-line comment:
  //
[Line 1439] Single-line comment:
  // Genesis Block:
[Line 1440] Single-line comment:
  // GetHash()      = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
[Line 1441] Single-line comment:
  // hashMerkleRoot = 0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
[Line 1442] Single-line comment:
  // txNew.vin[0].scriptSig     = 486604799 4 0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854
[Line 1443] Single-line comment:
  // txNew.vout[0].nValue       = 5000000000
[Line 1444] Single-line comment:
  // txNew.vout[0].scriptPubKey = 0x5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704 OP_CHECKSIG
[Line 1445] Single-line comment:
  // block.nVersion = 1
[Line 1446] Single-line comment:
  // block.nTime    = 1231006505
[Line 1447] Single-line comment:
  // block.nBits    = 0x1d00ffff
[Line 1448] Single-line comment:
  // block.nNonce   = 2083236893
[Line 1449] Single-line comment:
  // CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
[Line 1450] Single-line comment:
  //   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
[Line 1451] Single-line comment:
  //     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
[Line 1452] Single-line comment:
  //     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
[Line 1453] Single-line comment:
  //   vMerkleTree: 4a5e1e
[Line 1455] Single-line comment:
  // Genesis block
[Line 1472] Single-line comment:
  //// debug print, delete this later
[Line 1482] Single-line comment:
  // Start new block file
[Line 1498] Single-line comment:
  // precompute tree structure
[Line 1504] Single-line comment:
  // test
[Line 1505] Single-line comment:
  //while (rand() % 3 == 0)
[Line 1506] Single-line comment:
  //    mapNext[pindex->pprev].push_back(pindex);
[Line 1519] Single-line comment:
  // print split or gap
[Line 1534] Single-line comment:
  // print columns
[Line 1538] Single-line comment:
  // print item
[Line 1560] Single-line comment:
  // put the main timechain first
[Line 1571] Single-line comment:
  // iterate children
[Line 1586] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 1587] Single-line comment:
  //
[Line 1588] Single-line comment:
  // Messages
[Line 1589] Single-line comment:
  //
[Line 1601] Single-line comment:
  // Don't know what it is, just say we already got one
[Line 1618] Single-line comment:
  //
[Line 1619] Single-line comment:
  // Message format
[Line 1620] Single-line comment:
  //  (4) message start
[Line 1621] Single-line comment:
  //  (12) command
[Line 1622] Single-line comment:
  //  (4) size
[Line 1623] Single-line comment:
  //  (x) data
[Line 1624] Single-line comment:
  //
[Line 1628] Single-line comment:
  // Scan for message start
[Line 1643] Single-line comment:
  // Read header
[Line 1653] Single-line comment:
  // Message size
[Line 1657] Single-line comment:
  // Rewind and wait for rest of message
[Line 1658] Single-line comment:
  ///// need a mechanism to give up waiting for overlong message size error
[Line 1665] Single-line comment:
  // Copy message to its own buffer
[Line 1669] Single-line comment:
  // Process message
[Line 1707] Single-line comment:
  // Can only do this once
[Line 1729] Single-line comment:
  // Ask the first connected node for block updates
[Line 1743] Single-line comment:
  // Must have a version message before anything else
[Line 1753] Single-line comment:
  // Store the new addresses
[Line 1761] Single-line comment:
  // Put on lists to send to other nodes
[Line 1808] Single-line comment:
  // Send block from disk
[Line 1812] Single-line comment:
  //// could optimize this to send header straight from blockindex for client
[Line 1820] Single-line comment:
  // Send stream from relay memory
[Line 1838] Single-line comment:
  // Find the first block the caller has in the main chain
[Line 1841] Single-line comment:
  // Send the rest of the chain
[Line 1853] Single-line comment:
  // Bypass setInventoryKnown in case an inventory message got lost
[Line 1857] Single-line comment:
  // returns true if wasn't already contained in the set
[Line 1886] Single-line comment:
  // Recursively process any orphan transactions that depended on this one
[Line 1932] Single-line comment:
  // Relay the original message as-is in case it's a higher version than we know how to parse
[Line 1944] Single-line comment:
  //// debug print
[Line 1958] Single-line comment:
  //// need to expand the time range if not enough found
[Line 1959] Single-line comment:
  // in the last hour
[Line 1980] Single-line comment:
  /// we have a chance to check the order here
[Line 1982] Single-line comment:
  // Keep giving the same key to the same ip until they use it
[Line 1986] Single-line comment:
  // Send back approval of order and pubkey to use
[Line 1999] Single-line comment:
  // Broadcast
[Line 2010] Single-line comment:
  // Send back confirmation
[Line 2037] Single-line comment:
  // Ignore unknown commands for extensibility
[Line 2061] Single-line comment:
  // Don't send anything until we get their version message
[Line 2066] Single-line comment:
  //
[Line 2067] Single-line comment:
  // Message: addr
[Line 2068] Single-line comment:
  //
[Line 2079] Single-line comment:
  //
[Line 2080] Single-line comment:
  // Message: inventory
[Line 2081] Single-line comment:
  //
[Line 2088] Single-line comment:
  // returns true if wasn't already contained in the set
[Line 2099] Single-line comment:
  //
[Line 2100] Single-line comment:
  // Message: getdata
[Line 2101] Single-line comment:
  //
[Line 2133] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 2134] Single-line comment:
  //
[Line 2135] Single-line comment:
  // BitcoinMiner
[Line 2136] Single-line comment:
  //
[Line 2206] Single-line comment:
  //
[Line 2207] Single-line comment:
  // Create coinbase tx
[Line 2208] Single-line comment:
  //
[Line 2217] Single-line comment:
  //
[Line 2218] Single-line comment:
  // Create new block
[Line 2219] Single-line comment:
  //
[Line 2224] Single-line comment:
  // Add our coinbase tx as first transaction
[Line 2227] Single-line comment:
  // Collect the latest transactions into the block
[Line 2249] Single-line comment:
  // Transaction fee requirements, mainly only needed for flood control
[Line 2250] Single-line comment:
  // Under 10K (about 80 inputs) is free for first 100 transactions
[Line 2251] Single-line comment:
  // Base rate is 0.01 per KB
[Line 2271] Single-line comment:
  //
[Line 2272] Single-line comment:
  // Prebuild hash buffer
[Line 2273] Single-line comment:
  //
[Line 2303] Single-line comment:
  //
[Line 2304] Single-line comment:
  // Search
[Line 2305] Single-line comment:
  //
[Line 2320] Single-line comment:
  //// debug print
[Line 2328] Single-line comment:
  // Save key
[Line 2333] Single-line comment:
  // Process this block the same as if we had received it from another node
[Line 2343] Single-line comment:
  // Update nTime every few seconds
[Line 2380] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 2381] Single-line comment:
  //
[Line 2382] Single-line comment:
  // Actions
[Line 2383] Single-line comment:
  //
[Line 2404] Single-line comment:
  ///printf(" GetBalance() time = %16I64d\n", nEnd - nStart);
[Line 2414] Single-line comment:
  // List of values less than target
[Line 2456] Single-line comment:
  // Solve subset sum by stochastic approximation
[Line 2491] Single-line comment:
  // If the next larger is still closer, return it
[Line 2500] Single-line comment:
  //// debug print
[Line 2519] Single-line comment:
  // txdb must be opened before the mapWallet lock
[Line 2533] Single-line comment:
  // Choose coins to use
[Line 2541] Single-line comment:
  // Fill vout[0] to the payee
[Line 2544] Single-line comment:
  // Fill vout[1] back to self with any change
[Line 2547] Single-line comment:
  // Use the same key as one of the coins
[Line 2557] Single-line comment:
  // Fill vout[1] to ourself
[Line 2563] Single-line comment:
  // Fill vin
[Line 2569] Single-line comment:
  // Sign
[Line 2576] Single-line comment:
  // Check that enough fee is included
[Line 2583] Single-line comment:
  // Fill vtxPrev by copying from previous transactions vtxPrev
[Line 2594] Single-line comment:
  // Call after CreateTransaction unless you want to abort
[Line 2600] Single-line comment:
  //// todo: make this transactional, never want to add a transaction
[Line 2601] Single-line comment:
  ////  without marking spent transactions
[Line 2603] Single-line comment:
  // Add tx to wallet, because if it has change it's also ours,
[Line 2604] Single-line comment:
  // otherwise just for transaction history.
[Line 2607] Single-line comment:
  // Mark old coins as spent
[Line 2648] Single-line comment:
  // Broadcast
[Line 2651] Single-line comment:
  // This must not fail. The transaction has already been signed and recorded.

File: /home/user/bitcoinArchive/bitcoin0.1/src/main.h
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 40] Single-line comment:
  // Settings
[Line 188] Single-line comment:
  //
[Line 189] Single-line comment:
  // An input of a transaction.  It contains the location of the previous
[Line 190] Single-line comment:
  // transaction's output that it claims and a signature that matches the
[Line 191] Single-line comment:
  // output's public key.
[Line 192] Single-line comment:
  //
[Line 270] Single-line comment:
  //
[Line 271] Single-line comment:
  // An output of a transaction.  It contains the public key that the next input
[Line 272] Single-line comment:
  // must be able to sign with to claim it.
[Line 273] Single-line comment:
  //
[Line 353] Single-line comment:
  //
[Line 354] Single-line comment:
  // The basic transaction that is broadcasted on the network and contained in
[Line 355] Single-line comment:
  // blocks.  A transaction can contain multiple inputs and outputs.
[Line 356] Single-line comment:
  //
[Line 444] Single-line comment:
  // Basic checks that don't depend on any context
[Line 448] Single-line comment:
  // Check for negative values
[Line 520] Single-line comment:
  // Read transaction
[Line 525] Single-line comment:
  // Return file pointer
[Line 595] Single-line comment:
  //
[Line 596] Single-line comment:
  // A transaction with a merkle branch linking it to the block chain
[Line 597] Single-line comment:
  //
[Line 605] Single-line comment:
  // memory only
[Line 628] Single-line comment:
  // Must wait until coinbase is safely deep enough in the chain before valuing it
[Line 655] Single-line comment:
  //
[Line 656] Single-line comment:
  // A transaction with a bunch of additional info that only the owner cares
[Line 657] Single-line comment:
  // about.  It includes any unrecorded transactions needed to link it back
[Line 658] Single-line comment:
  // to the block chain.
[Line 659] Single-line comment:
  //
[Line 667] Single-line comment:
  // time received by this node
[Line 670] Single-line comment:
  //// probably need to sign the order info so know it came from payer
[Line 672] Single-line comment:
  // memory only
[Line 733] Single-line comment:
  //
[Line 734] Single-line comment:
  // A txdb record that contains the disk location of a transaction and the
[Line 735] Single-line comment:
  // locations of transactions that spend its outputs.  vSpent is really only
[Line 736] Single-line comment:
  // used as a flag, but having the location is very helpful for debugging.
[Line 737] Single-line comment:
  //
[Line 794] Single-line comment:
  //
[Line 795] Single-line comment:
  // Nodes collect new transactions into a block, hash them into a hash tree,
[Line 796] Single-line comment:
  // and scan through nonce values to make the block's hash satisfy proof-of-work
[Line 797] Single-line comment:
  // requirements.  When they solve the proof-of-work, they broadcast the block
[Line 798] Single-line comment:
  // to everyone and the block is added to the block chain.  The first transaction
[Line 799] Single-line comment:
  // in the block is a special one that creates a new coin owned by the creator
[Line 800] Single-line comment:
  // of the block.
[Line 801] Single-line comment:
  //
[Line 802] Single-line comment:
  // Blocks are appended to blk0001.dat files on disk.  Their location on disk
[Line 803] Single-line comment:
  // is indexed by CBlockIndex objects in memory.
[Line 804] Single-line comment:
  //
[Line 808] Single-line comment:
  // header
[Line 816] Single-line comment:
  // network and disk
[Line 819] Single-line comment:
  // memory only
[Line 838] Single-line comment:
  // ConnectBlock depends on vtx being last so it can calculate offset
[Line 921] Single-line comment:
  // Open history file to append
[Line 928] Single-line comment:
  // Write index header
[Line 932] Single-line comment:
  // Write block
[Line 945] Single-line comment:
  // Open history file to read
[Line 952] Single-line comment:
  // Read block
[Line 955] Single-line comment:
  // Check the header
[Line 1001] Single-line comment:
  //
[Line 1002] Single-line comment:
  // The block chain is a tree shaped structure starting with the
[Line 1003] Single-line comment:
  // genesis block at the root, with each block potentially having multiple
[Line 1004] Single-line comment:
  // candidates to be the next block.  pprev and pnext link a path through the
[Line 1005] Single-line comment:
  // main/longest chain.  A blockindex may have multiple pprev pointing back
[Line 1006] Single-line comment:
  // to it, but pnext will only point forward to the longest branch, or will
[Line 1007] Single-line comment:
  // be null if the block is not part of the longest chain.
[Line 1008] Single-line comment:
  //
[Line 1019] Single-line comment:
  // block header
[Line 1071] Single-line comment:
  // Open history file
[Line 1076] Single-line comment:
  // Overwrite with empty null block
[Line 1130] Single-line comment:
  //
[Line 1131] Single-line comment:
  // Used to marshal pointers into hashes for db storage.
[Line 1132] Single-line comment:
  //
[Line 1161] Single-line comment:
  // block header
[Line 1207] Single-line comment:
  //
[Line 1208] Single-line comment:
  // Describes a place in the block chain to another node such that if the
[Line 1209] Single-line comment:
  // other node doesn't have the same branch, it can find a recent common trunk.
[Line 1210] Single-line comment:
  // The further back it is, the further before the fork it may be.
[Line 1211] Single-line comment:
  //
[Line 1249] Single-line comment:
  // Exponentially larger steps back
[Line 1260] Single-line comment:
  // Find the first block the caller has in the main chain
[Line 1276] Single-line comment:
  // Find the first block the caller has in the main chain

File: /home/user/bitcoinArchive/bitcoin0.1/src/market.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 16] Single-line comment:
  //
[Line 17] Single-line comment:
  // Global state variables
[Line 18] Single-line comment:
  //
[Line 20] Single-line comment:
  //// later figure out how these are persisted
[Line 37] Single-line comment:
  // Insert or find existing product
[Line 42] Single-line comment:
  // Update if newer
[Line 50] Single-line comment:
  //if (fNew)
[Line 51] Single-line comment:
  //    NotifyProductAdded(hash);
[Line 52] Single-line comment:
  //else if (fUpdated)
[Line 53] Single-line comment:
  //    NotifyProductUpdated(hash);
[Line 63] Single-line comment:
  //NotifyProductDeleted(hash);
[Line 87] Single-line comment:
  // v1 = v1 union v2
[Line 88] Single-line comment:
  // v1 and v2 must be sorted
[Line 89] Single-line comment:
  // returns the number of elements added to v1
[Line 91] Single-line comment:
  ///// need to check that this is equivalent, then delete this comment
[Line 92] Single-line comment:
  //vector<unsigned short> vUnion(v1.size() + v2.size());
[Line 93] Single-line comment:
  //vUnion.erase(set_union(v1.begin(), v1.end(),
[Line 94] Single-line comment:
  //                       v2.begin(), v2.end(),
[Line 95] Single-line comment:
  //                       vUnion.begin()),
[Line 96] Single-line comment:
  //             vUnion.end());
[Line 111] Single-line comment:
  // Ignore duplicates
[Line 116] Single-line comment:
  //// instead of zero atom, should change to free atom that propagates,
[Line 117] Single-line comment:
  //// limited to lower than a certain value like 5 so conflicts quickly
[Line 118] Single-line comment:
  // The zero atom never propagates,
[Line 119] Single-line comment:
  // new atoms always propagate through the user that created them
[Line 133] Single-line comment:
  // Select atom to flow through to vAtomsOut
[Line 136] Single-line comment:
  // Merge vAtomsNew into vAtomsIn
[Line 159] Single-line comment:
  ///// this would be a lot easier on the database if it put the new atom at the beginning of the list,
[Line 160] Single-line comment:
  ///// so the change would be right next to the vector size.
[Line 162] Single-line comment:
  // Read user
[Line 169] Single-line comment:
  // Add atoms received
[Line 174] Single-line comment:
  // Don't bother writing to disk if no changes
[Line 178] Single-line comment:
  // Propagate
[Line 183] Single-line comment:
  // Write back
[Line 199] Single-line comment:
  // Timestamp
[Line 202] Single-line comment:
  // Check signature
[Line 208] Single-line comment:
  // Add review text to recipient
[Line 215] Single-line comment:
  // Add link from sender
[Line 225] Single-line comment:
  // Propagate atoms to recipient
[Line 247] Single-line comment:
  // Make sure it's a summary product
[Line 251] Single-line comment:
  // Look up seller's atom count
[Line 258] Single-line comment:
  ////// delme, this is now done by AdvertInsert
[Line 259] Single-line comment:
  //// Store to memory
[Line 260] Single-line comment:
  //CRITICAL_BLOCK(cs_mapProducts)
[Line 261] Single-line comment:
  //    mapProducts[GetHash()] = *this;

File: /home/user/bitcoinArchive/bitcoin0.1/src/market.h
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 81] Single-line comment:
  // memory only
[Line 132] Single-line comment:
  // disk only
[Line 135] Single-line comment:
  // memory only

File: /home/user/bitcoinArchive/bitcoin0.1/src/net.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 17] Single-line comment:
  //
[Line 18] Single-line comment:
  // Global state variables
[Line 19] Single-line comment:
  //
[Line 94] Single-line comment:
  // whatismyip.com 198-200
[Line 147] Single-line comment:
  // New address
[Line 157] Single-line comment:
  // Services have been added
[Line 173] Single-line comment:
  // If the dialog might get closed before the reply comes back,
[Line 174] Single-line comment:
  // call this in the destructor so it doesn't get called after it's deleted.
[Line 200] Single-line comment:
  //
[Line 201] Single-line comment:
  // Subscription methods for the broadcast and subscription system.
[Line 202] Single-line comment:
  // Channel numbers are message numbers, i.e. MSG_TABLE and MSG_PRODUCT.
[Line 203] Single-line comment:
  //
[Line 204] Single-line comment:
  // The subscription system uses a meet-in-the-middle strategy.
[Line 205] Single-line comment:
  // With 100,000 nodes, if senders broadcast to 1000 random nodes and receivers
[Line 206] Single-line comment:
  // subscribe to 1000 random nodes, 99.995% (1 - 0.99^1000) of messages will get through.
[Line 207] Single-line comment:
  //
[Line 234] Single-line comment:
  // Relay subscribe
[Line 249] Single-line comment:
  // Prevent from relaying cancel if wasn't subscribed
[Line 256] Single-line comment:
  // Relay subscription cancel
[Line 262] Single-line comment:
  // Clear memory, no longer subscribed
[Line 304] Single-line comment:
  // Look for an existing connection
[Line 315] Single-line comment:
  /// debug print
[Line 318] Single-line comment:
  // Connect
[Line 322] Single-line comment:
  /// debug print
[Line 325] Single-line comment:
  // Add node
[Line 352] Single-line comment:
  // All of a nodes broadcasts and subscriptions are automatically torn down
[Line 353] Single-line comment:
  // when it goes down, so a node has to stay up to keep its broadcast going.
[Line 359] Single-line comment:
  // Cancel subscriptions
[Line 404] Single-line comment:
  //
[Line 405] Single-line comment:
  // Disconnect nodes
[Line 406] Single-line comment:
  //
[Line 409] Single-line comment:
  // Disconnect duplicate connections
[Line 418] Single-line comment:
  // In case two nodes connect to each other at once,
[Line 419] Single-line comment:
  // the lower ip disconnects its outbound connection
[Line 440] Single-line comment:
  // Disconnect unused nodes
[Line 446] Single-line comment:
  // remove from vNodes
[Line 450] Single-line comment:
  // hold in disconnected pool until all refs are released
[Line 458] Single-line comment:
  // Delete disconnected nodes
[Line 462] Single-line comment:
  // wait until threads are done using it
[Line 486] Single-line comment:
  //
[Line 487] Single-line comment:
  // Find which sockets have data to receive
[Line 488] Single-line comment:
  //
[Line 491] Single-line comment:
  // frequency to poll pnode->vSend
[Line 529] Single-line comment:
  //// debug print
[Line 530] Single-line comment:
  //foreach(CNode* pnode, vNodes)
[Line 531] Single-line comment:
  //{
[Line 532] Single-line comment:
  //    printf("vRecv = %-5d ", pnode->vRecv.size());
[Line 533] Single-line comment:
  //    printf("vSend = %-5d    ", pnode->vSend.size());
[Line 534] Single-line comment:
  //}
[Line 535] Single-line comment:
  //printf("\n");
[Line 538] Single-line comment:
  //
[Line 539] Single-line comment:
  // Accept new connections
[Line 540] Single-line comment:
  //
[Line 563] Single-line comment:
  //
[Line 564] Single-line comment:
  // Service each socket
[Line 565] Single-line comment:
  //
[Line 574] Single-line comment:
  //
[Line 575] Single-line comment:
  // Receive
[Line 576] Single-line comment:
  //
[Line 584] Single-line comment:
  // typical socket buffer is 8K-64K
[Line 591] Single-line comment:
  // socket closed gracefully
[Line 598] Single-line comment:
  // socket error
[Line 610] Single-line comment:
  //
[Line 611] Single-line comment:
  // Send
[Line 612] Single-line comment:
  //
[Line 677] Single-line comment:
  // Initiate network connections
[Line 681] Single-line comment:
  // Wait
[Line 693] Single-line comment:
  // Make a list of unique class C's
[Line 707] Single-line comment:
  // Taking advantage of mapAddresses being in sorted order,
[Line 708] Single-line comment:
  // with IPs of the same class C grouped together.
[Line 715] Single-line comment:
  //
[Line 716] Single-line comment:
  // The IP selection process is designed to limit vulnerability to address flooding.
[Line 717] Single-line comment:
  // Any class C (a.b.c.?) has an equal chance of being chosen, then an IP is
[Line 718] Single-line comment:
  // chosen within the class C.  An attacker may be able to allocate many IPs, but
[Line 719] Single-line comment:
  // they would normally be concentrated in blocks of class C's.  They can hog the
[Line 720] Single-line comment:
  // attention within their class C, but not the whole IP address space overall.
[Line 721] Single-line comment:
  // A lone node in a class C will get as much attention as someone holding all 255
[Line 722] Single-line comment:
  // IPs in another class C.
[Line 723] Single-line comment:
  //
[Line 728] Single-line comment:
  // Choose a random class C
[Line 731] Single-line comment:
  // Organize all addresses in the class C by IP
[Line 751] Single-line comment:
  // Choose a random IP in the class C
[Line 755] Single-line comment:
  // Once we've chosen an IP, we'll try every given port before moving on
[Line 768] Single-line comment:
  // Advertise our address
[Line 774] Single-line comment:
  // Get as many addresses as we can
[Line 777] Single-line comment:
  ////// should the one on the receiving end do this too?
[Line 778] Single-line comment:
  // Subscribe our local subscription list
[Line 822] Single-line comment:
  // Poll the connected nodes for messages
[Line 830] Single-line comment:
  // Receive messages
[Line 834] Single-line comment:
  // Send messages
[Line 841] Single-line comment:
  // Wait and allow messages to bunch up
[Line 857] Single-line comment:
  //// todo: start one thread per processor, use getenv("NUMBER_OF_PROCESSORS")
[Line 885] Single-line comment:
  // Sockets startup
[Line 895] Single-line comment:
  // Get local host ip
[Line 915] Single-line comment:
  // Create socket for listening for incoming connections
[Line 924] Single-line comment:
  // Set to nonblocking, incoming connections will also inherit this
[Line 933] Single-line comment:
  // The sockaddr_in structure specifies the address family,
[Line 934] Single-line comment:
  // IP address, and port for the socket that is being bound
[Line 949] Single-line comment:
  // Listen for incoming connections
[Line 957] Single-line comment:
  // Get our external IP address for incoming connections
[Line 967] Single-line comment:
  // Get addresses from IRC and advertise ours
[Line 971] Single-line comment:
  //
[Line 972] Single-line comment:
  // Start threads
[Line 973] Single-line comment:
  //
[Line 1007] Single-line comment:
  // Sockets shutdown

File: /home/user/bitcoinArchive/bitcoin0.1/src/net.h
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 45] Single-line comment:
  //
[Line 46] Single-line comment:
  // Message header
[Line 47] Single-line comment:
  //  (4) message start
[Line 48] Single-line comment:
  //  (12) command
[Line 49] Single-line comment:
  //  (4) size
[Line 51] Single-line comment:
  // The message start string is designed to be unlikely to occur in normal data.
[Line 52] Single-line comment:
  // The characters are rarely used upper ascii, not valid as UTF-8, and produce
[Line 53] Single-line comment:
  // a large 4-byte int at any alignment.
[Line 96] Single-line comment:
  // Check start string
[Line 100] Single-line comment:
  // Check the command string for errors
[Line 105] Single-line comment:
  // Must be all zeros after the first zero
[Line 114] Single-line comment:
  // Message size
[Line 140] Single-line comment:
  // disk only
[Line 143] Single-line comment:
  // memory only
[Line 286] Single-line comment:
  //return strprintf("%u.%u.%u.%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0));
[Line 437] Single-line comment:
  // socket
[Line 458] Single-line comment:
  // flood
[Line 462] Single-line comment:
  // inventory based relay
[Line 469] Single-line comment:
  // publish and subscription
[Line 482] Single-line comment:
  // set by version message
[Line 490] Single-line comment:
  // Push a version message
[Line 491] Single-line comment:
  /// when NTP implemented, change to just nTime = GetAdjustedTime()
[Line 548] Single-line comment:
  // We're using mapAskFor as a priority queue,
[Line 549] Single-line comment:
  // the key is the earliest time the request can be sent
[Line 553] Single-line comment:
  // Make sure not to reuse time indexes to keep things in the same order
[Line 558] Single-line comment:
  // Each retry is 2 minutes after the last
[Line 598] Single-line comment:
  // Patch in the size
[Line 603] Single-line comment:
  //for (int i = nPushPos+sizeof(CMessageHeader); i < min(vSend.size(), nPushPos+sizeof(CMessageHeader)+20U); i++)
[Line 604] Single-line comment:
  //    printf("%02x ", vSend[i] & 0xff);
[Line 768] Single-line comment:
  // Put on lists to offer to the other nodes
[Line 788] Single-line comment:
  // Expire old relay messages
[Line 795] Single-line comment:
  // Save original serialized message so newer versions are preserved
[Line 810] Single-line comment:
  //
[Line 811] Single-line comment:
  // Templates for the publish and subscription system.
[Line 812] Single-line comment:
  // The object being published as T& obj needs to have:
[Line 813] Single-line comment:
  //   a set<unsigned int> setSources member
[Line 814] Single-line comment:
  //   specializations of AdvertInsert and AdvertErase
[Line 815] Single-line comment:
  // Currently implemented for CTable and CProduct.
[Line 816] Single-line comment:
  //
[Line 821] Single-line comment:
  // Add to sources
[Line 827] Single-line comment:
  // Relay
[Line 850] Single-line comment:
  // Remove a source
[Line 853] Single-line comment:
  // If no longer supported by any sources, cancel it

File: /home/user/bitcoinArchive/bitcoin0.1/src/script.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 28] Single-line comment:
  // Lengthen the shorter one
[Line 37] Single-line comment:
  //
[Line 38] Single-line comment:
  // Script is a stack machine (like Forth) that evaluates a predicate
[Line 39] Single-line comment:
  // returning a bool indicating valid or not.  There are no loops.
[Line 40] Single-line comment:
  //
[Line 62] Single-line comment:
  //
[Line 63] Single-line comment:
  // Read instruction
[Line 64] Single-line comment:
  //
[Line 75] Single-line comment:
  //
[Line 76] Single-line comment:
  // Push value
[Line 77] Single-line comment:
  //
[Line 96] Single-line comment:
  // ( -- value)
[Line 103] Single-line comment:
  //
[Line 104] Single-line comment:
  // Control
[Line 105] Single-line comment:
  //
[Line 121] Single-line comment:
  // <expression> if [statements] [else [statements]] endif
[Line 158] Single-line comment:
  // (true -- ) or
[Line 159] Single-line comment:
  // (false -- false) and return
[Line 177] Single-line comment:
  //
[Line 178] Single-line comment:
  // Stack ops
[Line 179] Single-line comment:
  //
[Line 200] Single-line comment:
  // (x1 x2 -- )
[Line 208] Single-line comment:
  // (x1 x2 -- x1 x2 x1 x2)
[Line 220] Single-line comment:
  // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
[Line 234] Single-line comment:
  // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
[Line 246] Single-line comment:
  // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
[Line 259] Single-line comment:
  // (x1 x2 x3 x4 -- x3 x4 x1 x2)
[Line 269] Single-line comment:
  // (x - 0 | x x)
[Line 280] Single-line comment:
  // -- stacksize
[Line 288] Single-line comment:
  // (x -- )
[Line 297] Single-line comment:
  // (x -- x x)
[Line 307] Single-line comment:
  // (x1 x2 -- x2)
[Line 316] Single-line comment:
  // (x1 x2 -- x1 x2 x1)
[Line 327] Single-line comment:
  // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
[Line 328] Single-line comment:
  // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
[Line 344] Single-line comment:
  // (x1 x2 x3 -- x2 x3 x1)
[Line 345] Single-line comment:
  //  x2 x1 x3  after first swap
[Line 346] Single-line comment:
  //  x2 x3 x1  after second swap
[Line 356] Single-line comment:
  // (x1 x2 -- x2 x1)
[Line 365] Single-line comment:
  // (x1 x2 -- x2 x1 x2)
[Line 374] Single-line comment:
  //
[Line 375] Single-line comment:
  // Splice ops
[Line 376] Single-line comment:
  //
[Line 379] Single-line comment:
  // (x1 x2 -- out)
[Line 391] Single-line comment:
  // (in begin size -- out)
[Line 413] Single-line comment:
  // (in size -- out)
[Line 432] Single-line comment:
  // (in -- in size)
[Line 441] Single-line comment:
  //
[Line 442] Single-line comment:
  // Bitwise logic
[Line 443] Single-line comment:
  //
[Line 446] Single-line comment:
  // (in - out)
[Line 459] Single-line comment:
  // (x1 x2 - out)
[Line 486] Single-line comment:
  //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
[Line 488] Single-line comment:
  // (x1 x2 - bool)
[Line 494] Single-line comment:
  // OP_NOTEQUAL is disabled because it would be too easy to say
[Line 495] Single-line comment:
  // something like n != 1 and have some wiseguy pass in 1 with extra
[Line 496] Single-line comment:
  // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
[Line 497] Single-line comment:
  //if (opcode == OP_NOTEQUAL)
[Line 498] Single-line comment:
  //    fEqual = !fEqual;
[Line 513] Single-line comment:
  //
[Line 514] Single-line comment:
  // Numeric
[Line 515] Single-line comment:
  //
[Line 525] Single-line comment:
  // (in -- out)
[Line 564] Single-line comment:
  // (x1 x2 -- out)
[Line 635] Single-line comment:
  // (x min max -- out)
[Line 650] Single-line comment:
  //
[Line 651] Single-line comment:
  // Crypto
[Line 652] Single-line comment:
  //
[Line 659] Single-line comment:
  // (in -- hash)
[Line 687] Single-line comment:
  // Hash starts after the code separator
[Line 695] Single-line comment:
  // (sig pubkey -- bool)
[Line 702] Single-line comment:
  ////// debug print
[Line 703] Single-line comment:
  //PrintHex(vchSig.begin(), vchSig.end(), "sig: %s\n");
[Line 704] Single-line comment:
  //PrintHex(vchPubKey.begin(), vchPubKey.end(), "pubkey: %s\n");
[Line 706] Single-line comment:
  // Subset of script starting at the most recent codeseparator
[Line 709] Single-line comment:
  // Drop the signature, since there's no way for a signature to sign itself
[Line 730] Single-line comment:
  // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)
[Line 752] Single-line comment:
  // Subset of script starting at the most recent codeseparator
[Line 755] Single-line comment:
  // Drop the signatures, since there's no way for a signature to sign itself
[Line 768] Single-line comment:
  // Check signature
[Line 777] Single-line comment:
  // If there are more signatures left than keys left,
[Line 778] Single-line comment:
  // then too many signatures have failed
[Line 827] Single-line comment:
  // In case concatenating two scripts ends up with two codeseparators,
[Line 828] Single-line comment:
  // or an extra one at the end, this prevents all those possible incompatibilities.
[Line 831] Single-line comment:
  // Blank out other inputs' signatures
[Line 836] Single-line comment:
  // Blank out some of the outputs
[Line 839] Single-line comment:
  // Wildcard payee
[Line 842] Single-line comment:
  // Let the others update at will
[Line 849] Single-line comment:
  // Only lockin the txout payee at same index as txin
[Line 860] Single-line comment:
  // Let the others update at will
[Line 866] Single-line comment:
  // Blank out other inputs completely, not recommended for open transactions
[Line 873] Single-line comment:
  // Serialize and hash
[Line 888] Single-line comment:
  // Hash type is one byte tacked on to the end of the signature
[Line 915] Single-line comment:
  // Templates
[Line 919] Single-line comment:
  // Standard tx, sender provides pubkey, receiver adds signature
[Line 922] Single-line comment:
  // Short account number tx, sender provides hash of pubkey, receiver provides signature and pubkey
[Line 926] Single-line comment:
  // Scan templates
[Line 934] Single-line comment:
  // Compare
[Line 943] Single-line comment:
  // Success
[Line 983] Single-line comment:
  // Compile solution
[Line 990] Single-line comment:
  // Sign
[Line 1005] Single-line comment:
  // Sign and give pubkey
[Line 1097] Single-line comment:
  // Leave out the signature from the hash, since a signature can't sign itself.
[Line 1098] Single-line comment:
  // The checksig op will also drop the signatures from its hash.
[Line 1106] Single-line comment:
  // Test solution

File: /home/user/bitcoinArchive/bitcoin0.1/src/script.h
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 19] Single-line comment:
  // push value
[Line 45] Single-line comment:
  // control
[Line 57] Single-line comment:
  // stack ops
[Line 78] Single-line comment:
  // splice ops
[Line 85] Single-line comment:
  // bit logic
[Line 95] Single-line comment:
  // numeric
[Line 127] Single-line comment:
  // crypto
[Line 140] Single-line comment:
  // multi-byte opcodes
[Line 144] Single-line comment:
  // template matching params
[Line 164] Single-line comment:
  // push value
[Line 188] Single-line comment:
  // control
[Line 200] Single-line comment:
  // stack ops
[Line 221] Single-line comment:
  // splice ops
[Line 228] Single-line comment:
  // bit logic
[Line 238] Single-line comment:
  // numeric
[Line 267] Single-line comment:
  // crypto
[Line 281] Single-line comment:
  // multi-byte opcodes
[Line 304] Single-line comment:
  //return string("(") + HexStr(vch.begin(), vch.end()) + string(")");
[Line 466] Single-line comment:
  // I'm not sure if this should push the script or concatenate scripts.
[Line 467] Single-line comment:
  // If there's ever a use for pushing a script onto a script, delete this member fn
[Line 475] Single-line comment:
  // This is why people hate C++
[Line 489] Single-line comment:
  // Read instruction
[Line 499] Single-line comment:
  // Immediate operand
[Line 550] Single-line comment:
  //printf("FindAndDeleted deleted %d items\n", count); /// debug

File: /home/user/bitcoinArchive/bitcoin0.1/src/serialize.h
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 28] Single-line comment:
  /////////////////////////////////////////////////////////////////
[Line 29] Single-line comment:
  //
[Line 30] Single-line comment:
  // Templates for serializing to anything that looks like a stream,
[Line 31] Single-line comment:
  // i.e. anything that supports .read(char*, int) and .write(char*, int)
[Line 32] Single-line comment:
  //
[Line 36] Single-line comment:
  // primary actions
[Line 41] Single-line comment:
  // modifiers
[Line 88] Single-line comment:
  //
[Line 89] Single-line comment:
  // Basic types
[Line 90] Single-line comment:
  //
[Line 145] Single-line comment:
  //
[Line 146] Single-line comment:
  // Compact size
[Line 147] Single-line comment:
  //  size <  253        -- 1 byte
[Line 148] Single-line comment:
  //  size <= USHRT_MAX  -- 3 bytes  (253 + 2 bytes)
[Line 149] Single-line comment:
  //  size <= UINT_MAX   -- 5 bytes  (254 + 4 bytes)
[Line 150] Single-line comment:
  //  size >  UINT_MAX   -- 9 bytes  (255 + 8 bytes)
[Line 151] Single-line comment:
  //
[Line 222] Single-line comment:
  //
[Line 223] Single-line comment:
  // Wrapper for serializing arrays and POD
[Line 224] Single-line comment:
  // There's a clever template way to make arrays serialize normally, but MSVC6 doesn't support it
[Line 225] Single-line comment:
  //
[Line 259] Single-line comment:
  //
[Line 260] Single-line comment:
  // string stored as a fixed length field
[Line 261] Single-line comment:
  //
[Line 301] Single-line comment:
  //
[Line 302] Single-line comment:
  // Forward declarations
[Line 303] Single-line comment:
  //
[Line 305] Single-line comment:
  // string
[Line 310] Single-line comment:
  // vector
[Line 321] Single-line comment:
  // others derived from vector
[Line 326] Single-line comment:
  // pair
[Line 331] Single-line comment:
  // map
[Line 336] Single-line comment:
  // set
[Line 345] Single-line comment:
  //
[Line 346] Single-line comment:
  // If none of the specialized versions above matched, default to calling member function.
[Line 347] Single-line comment:
  // "int nType" is changed to "long nType" to keep from getting an ambiguous overload error.
[Line 348] Single-line comment:
  // The compiler will only cast int to long if none of the other templates matched.
[Line 349] Single-line comment:
  // Thanks to Boost serialization for this idea.
[Line 350] Single-line comment:
  //
[Line 373] Single-line comment:
  //
[Line 374] Single-line comment:
  // string
[Line 375] Single-line comment:
  //
[Line 401] Single-line comment:
  //
[Line 402] Single-line comment:
  // vector
[Line 403] Single-line comment:
  //
[Line 452] Single-line comment:
  //unsigned int nSize = ReadCompactSize(is);
[Line 453] Single-line comment:
  //v.resize(nSize);
[Line 454] Single-line comment:
  //is.read((char*)&v[0], nSize * sizeof(T));
[Line 456] Single-line comment:
  // Limit size per read so bogus size value won't cause out of memory
[Line 472] Single-line comment:
  //unsigned int nSize = ReadCompactSize(is);
[Line 473] Single-line comment:
  //v.resize(nSize);
[Line 474] Single-line comment:
  //for (std::vector<T, A>::iterator vi = v.begin(); vi != v.end(); ++vi)
[Line 475] Single-line comment:
  //    Unserialize(is, (*vi), nType, nVersion);
[Line 500] Single-line comment:
  //
[Line 501] Single-line comment:
  // others derived from vector
[Line 502] Single-line comment:
  //
[Line 522] Single-line comment:
  //
[Line 523] Single-line comment:
  // pair
[Line 524] Single-line comment:
  //
[Line 547] Single-line comment:
  //
[Line 548] Single-line comment:
  // map
[Line 549] Single-line comment:
  //
[Line 583] Single-line comment:
  //
[Line 584] Single-line comment:
  // set
[Line 585] Single-line comment:
  //
[Line 619] Single-line comment:
  //
[Line 620] Single-line comment:
  // Support for IMPLEMENT_SERIALIZE and READWRITE macro
[Line 621] Single-line comment:
  //
[Line 660] Single-line comment:
  //
[Line 661] Single-line comment:
  // Allocator that clears its contents before deletion
[Line 662] Single-line comment:
  //
[Line 666] Single-line comment:
  // MSVC8 default copy constructor is broken
[Line 691] Single-line comment:
  //
[Line 692] Single-line comment:
  // Double ended buffer combining vector and stream-like interfaces.
[Line 693] Single-line comment:
  // >> and << read and write unformatted data using the above serialization templates.
[Line 694] Single-line comment:
  // Fills with data in linear time; some stringstream implementations take N^2 time.
[Line 695] Single-line comment:
  //
[Line 778] Single-line comment:
  //
[Line 779] Single-line comment:
  // Vector subset
[Line 780] Single-line comment:
  //
[Line 799] Single-line comment:
  // special case for inserting at the front when there's room
[Line 818] Single-line comment:
  // special case for erasing from the front
[Line 821] Single-line comment:
  // whenever we reach the end, we take the opportunity to clear the buffer
[Line 835] Single-line comment:
  // special case for erasing from the front
[Line 859] Single-line comment:
  // Rewind by n characters if the buffer hasn't been compacted yet
[Line 867] Single-line comment:
  //
[Line 868] Single-line comment:
  // Stream subset
[Line 869] Single-line comment:
  //
[Line 880] Single-line comment:
  // name conflict with vector clear()
[Line 895] Single-line comment:
  // Read from the beginning of the buffer
[Line 918] Single-line comment:
  // Ignore from the beginning of the buffer
[Line 938] Single-line comment:
  // Write to the end of the buffer
[Line 947] Single-line comment:
  // Special case: stream << stream concatenates like stream += stream
[Line 955] Single-line comment:
  // Tells the size of the object if serialized to this stream
[Line 962] Single-line comment:
  // Serialize to this stream
[Line 970] Single-line comment:
  // Unserialize from this stream
[Line 977] Single-line comment:
  // VC6sp6
[Line 978] Single-line comment:
  // CDataStream:
[Line 979] Single-line comment:
  // n=1000       0 seconds
[Line 980] Single-line comment:
  // n=2000       0 seconds
[Line 981] Single-line comment:
  // n=4000       0 seconds
[Line 982] Single-line comment:
  // n=8000       0 seconds
[Line 983] Single-line comment:
  // n=16000      0 seconds
[Line 984] Single-line comment:
  // n=32000      0 seconds
[Line 985] Single-line comment:
  // n=64000      1 seconds
[Line 986] Single-line comment:
  // n=128000     1 seconds
[Line 987] Single-line comment:
  // n=256000     2 seconds
[Line 988] Single-line comment:
  // n=512000     4 seconds
[Line 989] Single-line comment:
  // n=1024000    8 seconds
[Line 990] Single-line comment:
  // n=2048000    16 seconds
[Line 991] Single-line comment:
  // n=4096000    32 seconds
[Line 992] Single-line comment:
  // stringstream:
[Line 993] Single-line comment:
  // n=1000       1 seconds
[Line 994] Single-line comment:
  // n=2000       1 seconds
[Line 995] Single-line comment:
  // n=4000       13 seconds
[Line 996] Single-line comment:
  // n=8000       87 seconds
[Line 997] Single-line comment:
  // n=16000      400 seconds
[Line 998] Single-line comment:
  // n=32000      1660 seconds
[Line 999] Single-line comment:
  // n=64000      6749 seconds
[Line 1000] Single-line comment:
  // n=128000     27241 seconds
[Line 1001] Single-line comment:
  // n=256000     109804 seconds
[Line 1036] Single-line comment:
  //
[Line 1037] Single-line comment:
  // Automatic closing wrapper for FILE*
[Line 1038] Single-line comment:
  //  - Will automatically close the file when it goes out of scope if not null.
[Line 1039] Single-line comment:
  //  - If you're returning the file pointer, return file.release().
[Line 1040] Single-line comment:
  //  - If you need to close the file early, use file.fclose() instead of fclose(file).
[Line 1041] Single-line comment:
  //
[Line 1084] Single-line comment:
  //
[Line 1085] Single-line comment:
  // Stream subset
[Line 1086] Single-line comment:
  //
[Line 1128] Single-line comment:
  // Tells the size of the object if serialized to this stream
[Line 1135] Single-line comment:
  // Serialize to this stream
[Line 1145] Single-line comment:
  // Unserialize from this stream

File: /home/user/bitcoinArchive/bitcoin0.1/src/sha.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // This file is public domain
[Line 2] Single-line comment:
  // SHA routines extracted as a standalone file from:
[Line 3] Single-line comment:
  // Crypto++: a C++ Class Library of Cryptographic Schemes
[Line 4] Single-line comment:
  // Version 5.5.2 (9/24/2007)
[Line 5] Single-line comment:
  // http://www.cryptopp.com
[Line 7] Single-line comment:
  // sha.cpp - modified by Wei Dai from Steve Reid's public domain sha1.c
[Line 9] Single-line comment:
  // Steve Reid implemented SHA-1. Wei Dai implemented SHA-2.
[Line 10] Single-line comment:
  // Both are in the public domain.
[Line 19] Single-line comment:
  // start of Steve Reid's code
[Lines 38-38] Multi-line comment:
  /* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
[Lines 48-48] Multi-line comment:
      /* Copy context->state[] to working vars */
[Lines 54-54] Multi-line comment:
      /* 4 rounds of 20 operations each. Loop unrolled. */
[Lines 75-75] Multi-line comment:
      /* Add the working vars back into context.state[] */
[Line 83] Single-line comment:
  // end of Steve Reid's code
[Line 85] Single-line comment:
  // *************************************************************
[Line 135] Single-line comment:
  // for SHA256
[Lines 145-145] Multi-line comment:
      /* Copy context->state[] to working vars */
[Lines 147-147] Multi-line comment:
      /* 64 operations, partially loop unrolled */
[Lines 155-155] Multi-line comment:
      /* Add the working vars back into context.state[] */
[Lines 166-239] Multi-line comment:
  /*
  // smaller but slower
  void SHA256_Transform(word32 *state, const word32 *data)
  {
      word32 T[20];
      word32 W[32];
      unsigned int i = 0, j = 0;
      word32 *t = T+8;
  
      memcpy(t, state, 8*4);
      word32 e = t[4], a = t[0];
  
      do
      {
          word32 w = data[j];
          W[j] = w;
          w += K[j];
          w += t[7];
          w += S1(e);
          w += Ch(e, t[5], t[6]);
          e = t[3] + w;
          t[3] = t[3+8] = e;
          w += S0(t[0]);
          a = w + Maj(a, t[1], t[2]);
          t[-1] = t[7] = a;
          --t;
          ++j;
          if (j%8 == 0)
              t += 8;
      } while (j<16);
  
      do
      {
          i = j&0xf;
          word32 w = s1(W[i+16-2]) + s0(W[i+16-15]) + W[i] + W[i+16-7];
          W[i+16] = W[i] = w;
          w += K[j];
          w += t[7];
          w += S1(e);
          w += Ch(e, t[5], t[6]);
          e = t[3] + w;
          t[3] = t[3+8] = e;
          w += S0(t[0]);
          a = w + Maj(a, t[1], t[2]);
          t[-1] = t[7] = a;
  
          w = s1(W[(i+1)+16-2]) + s0(W[(i+1)+16-15]) + W[(i+1)] + W[(i+1)+16-7];
          W[(i+1)+16] = W[(i+1)] = w;
          w += K[j+1];
          w += (t-1)[7];
          w += S1(e);
          w += Ch(e, (t-1)[5], (t-1)[6]);
          e = (t-1)[3] + w;
          (t-1)[3] = (t-1)[3+8] = e;
          w += S0((t-1)[0]);
          a = w + Maj(a, (t-1)[1], (t-1)[2]);
          (t-1)[-1] = (t-1)[7] = a;
  
          t-=2;
          j+=2;
          if (j%8 == 0)
              t += 8;
      } while (j<64);
  
      state[0] += a;
      state[1] += t[1];
      state[2] += t[2];
      state[3] += t[3];
      state[4] += e;
      state[5] += t[5];
      state[6] += t[6];
      state[7] += t[7];
  }
  */
[Line 247] Single-line comment:
  // *************************************************************
[Line 315] Single-line comment:
  // put assembly version in separate function, otherwise MSVC 2005 SP1 doesn't generate correct code for the non-assembly version
[Line 333] Single-line comment:
  // 17*16 for expanded data, 20*8 for state
[Line 336] Single-line comment:
  // start at middle of state buffer. will decrement pointer each round to avoid copying
[Line 337] Single-line comment:
  // 16-byte alignment, then add 8
[Line 399] Single-line comment:
  // k + w is in mm0, a is in mm4, e is in mm5
[Line 400] Single-line comment:
  // h
[Line 401] Single-line comment:
  // f
[Line 402] Single-line comment:
  // g
[Line 407] Single-line comment:
  // h += Ch(e,f,g)
[Line 408] Single-line comment:
  // h += S1(e)
[Line 409] Single-line comment:
  // b
[Line 412] Single-line comment:
  // c
[Line 415] Single-line comment:
  // temp = h + Maj(a,b,c)
[Line 416] Single-line comment:
  // e = d + h
[Line 419] Single-line comment:
  // S0(a)
[Line 420] Single-line comment:
  // a = temp + S0(a)
[Line 425] Single-line comment:
  // first 16 rounds
[Line 440] Single-line comment:
  // rest of the rounds
[Line 443] Single-line comment:
  // data expansion, W[i-2] already in xmm0
[Line 458] Single-line comment:
  // 2 rounds
[Line 464] Single-line comment:
  // update indices and loop
[Line 470] Single-line comment:
  // do housekeeping every 8 rounds
[Line 509] Single-line comment:
  // #if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
[Lines 531-531] Multi-line comment:
      /* Copy context->state[] to working vars */
[Lines 533-533] Multi-line comment:
      /* 80 operations, partially loop unrolled */
[Lines 541-541] Multi-line comment:
      /* Add the working vars back into context.state[] */

File: /home/user/bitcoinArchive/bitcoin0.1/src/sha.h
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // This file is public domain
[Line 2] Single-line comment:
  // SHA routines extracted as a standalone file from:
[Line 3] Single-line comment:
  // Crypto++: a C++ Class Library of Cryptographic Schemes
[Line 4] Single-line comment:
  // Version 5.5.2 (9/24/2007)
[Line 5] Single-line comment:
  // http://www.cryptopp.com
[Line 13] Single-line comment:
  //
[Line 14] Single-line comment:
  // Dependencies
[Line 15] Single-line comment:
  //
[Line 38] Single-line comment:
  // ************** endian reversal ***************
[Line 51] Single-line comment:
  // depend on GCC's peephole optimization to generate rotate instructions
[Line 85] Single-line comment:
  // 5 instructions with rotate instruction, 9 without
[Line 88] Single-line comment:
  // 6 instructions with rotate instruction, 8 without
[Line 115] Single-line comment:
  //
[Line 116] Single-line comment:
  // SHA
[Line 117] Single-line comment:
  //
[Line 119] Single-line comment:
  // http://www.weidai.com/scan-mirror/md.html#SHA-1
[Line 129] Single-line comment:
  // for backwards compatibility
[Line 131] Single-line comment:
  // implements the SHA-256 standard
[Line 141] Single-line comment:
  // implements the SHA-224 standard
[Line 153] Single-line comment:
  // implements the SHA-512 standard
[Line 163] Single-line comment:
  // implements the SHA-384 standard

File: /home/user/bitcoinArchive/bitcoin0.1/src/ui.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 34] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 35] Single-line comment:
  //
[Line 36] Single-line comment:
  // Util
[Line 37] Single-line comment:
  //
[Line 41] Single-line comment:
  // Ctrl-a select all
[Line 50] Single-line comment:
  //char pszHourFormat[256];
[Line 51] Single-line comment:
  //pszHourFormat[0] = '\0';
[Line 52] Single-line comment:
  //GetLocaleInfo(LOCALE_USER_DEFAULT, LOCALE_ITIME, pszHourFormat, 256);
[Line 53] Single-line comment:
  //return (pszHourFormat[0] != '0');
[Line 73] Single-line comment:
  // Helper to simplify access to listctrl
[Line 181] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 182] Single-line comment:
  //
[Line 183] Single-line comment:
  // Custom events
[Line 184] Single-line comment:
  //
[Line 263] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 264] Single-line comment:
  //
[Line 265] Single-line comment:
  // CMainFrame
[Line 266] Single-line comment:
  //
[Line 272] Single-line comment:
  // Init
[Line 283] Single-line comment:
  // Init toolbar with transparency masked bitmaps
[Line 286] Single-line comment:
  //// shouldn't have to do mask separately anymore, bitmap alpha support added in wx 2.8.9,
[Line 297] Single-line comment:
  // Init column headers
[Line 307] Single-line comment:
  //m_listCtrlProductsSent->InsertColumn(0, "Category",      wxLIST_FORMAT_LEFT,  100);
[Line 308] Single-line comment:
  //m_listCtrlProductsSent->InsertColumn(1, "Title",         wxLIST_FORMAT_LEFT,  100);
[Line 309] Single-line comment:
  //m_listCtrlProductsSent->InsertColumn(2, "Description",   wxLIST_FORMAT_LEFT,  100);
[Line 310] Single-line comment:
  //m_listCtrlProductsSent->InsertColumn(3, "Price",         wxLIST_FORMAT_LEFT,  100);
[Line 311] Single-line comment:
  //m_listCtrlProductsSent->InsertColumn(4, "",              wxLIST_FORMAT_LEFT,  100);
[Line 313] Single-line comment:
  //m_listCtrlOrdersSent->InsertColumn(0, "Time",          wxLIST_FORMAT_LEFT,  100);
[Line 314] Single-line comment:
  //m_listCtrlOrdersSent->InsertColumn(1, "Price",         wxLIST_FORMAT_LEFT,  100);
[Line 315] Single-line comment:
  //m_listCtrlOrdersSent->InsertColumn(2, "",              wxLIST_FORMAT_LEFT,  100);
[Line 316] Single-line comment:
  //m_listCtrlOrdersSent->InsertColumn(3, "",              wxLIST_FORMAT_LEFT,  100);
[Line 317] Single-line comment:
  //m_listCtrlOrdersSent->InsertColumn(4, "",              wxLIST_FORMAT_LEFT,  100);
[Line 319] Single-line comment:
  //m_listCtrlOrdersReceived->InsertColumn(0, "Time",            wxLIST_FORMAT_LEFT,  100);
[Line 320] Single-line comment:
  //m_listCtrlOrdersReceived->InsertColumn(1, "Price",           wxLIST_FORMAT_LEFT,  100);
[Line 321] Single-line comment:
  //m_listCtrlOrdersReceived->InsertColumn(2, "Payment Status",  wxLIST_FORMAT_LEFT,  100);
[Line 322] Single-line comment:
  //m_listCtrlOrdersReceived->InsertColumn(3, "",                wxLIST_FORMAT_LEFT,  100);
[Line 323] Single-line comment:
  //m_listCtrlOrdersReceived->InsertColumn(4, "",                wxLIST_FORMAT_LEFT,  100);
[Line 325] Single-line comment:
  // Init status bar
[Line 329] Single-line comment:
  // Fill your address text box
[Line 334] Single-line comment:
  // Fill listctrl with wallet transactions
[Line 374] Single-line comment:
  // Hidden columns not resizeable
[Line 392] Single-line comment:
  // Find item
[Line 403] Single-line comment:
  // If sort key changed, must delete and reinsert to make it relocate
[Line 422] Single-line comment:
  // Status
[Line 442] Single-line comment:
  // Find the block the tx is in
[Line 448] Single-line comment:
  // Sort order, unrecorded transactions sort to the top
[Line 454] Single-line comment:
  // Insert line
[Line 457] Single-line comment:
  //
[Line 458] Single-line comment:
  // Credit
[Line 459] Single-line comment:
  //
[Line 464] Single-line comment:
  // Coinbase
[Line 479] Single-line comment:
  // Online transaction
[Line 491] Single-line comment:
  // Offline transaction
[Line 537] Single-line comment:
  // Payment to self
[Line 548] Single-line comment:
  //
[Line 549] Single-line comment:
  // Debit
[Line 550] Single-line comment:
  //
[Line 561] Single-line comment:
  // Online transaction
[Line 566] Single-line comment:
  // Offline transaction
[Line 602] Single-line comment:
  //
[Line 603] Single-line comment:
  // Mixed debit transaction, can't break down payees
[Line 604] Single-line comment:
  //
[Line 670] Single-line comment:
  // Collect list of wallet transactions and sort newest first
[Line 680] Single-line comment:
  // Do the newest transactions first
[Line 695] Single-line comment:
  // Fill list control
[Line 717] Single-line comment:
  // Check for time updates
[Line 742] Single-line comment:
  // Update listctrl contents
[Line 763] Single-line comment:
  // Update status column of visible items only
[Line 766] Single-line comment:
  // Update status bar
[Line 777] Single-line comment:
  // Balance total
[Line 850] Single-line comment:
  /// debug test
[Line 857] Single-line comment:
  // Toolbar: Send
[Line 864] Single-line comment:
  // Toolbar: Address Book
[Line 868] Single-line comment:
  // Send
[Line 876] Single-line comment:
  // Automatically select-all when entering window
[Line 892] Single-line comment:
  // Copy address box to clipboard
[Line 934] Single-line comment:
  //CTxDetailsDialog* pdialog = new CTxDetailsDialog(this, wtx);
[Line 935] Single-line comment:
  //pdialog->Show();
[Line 966] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 967] Single-line comment:
  //
[Line 968] Single-line comment:
  // CTxDetailsDialog
[Line 969] Single-line comment:
  //
[Line 988] Single-line comment:
  //
[Line 989] Single-line comment:
  // From
[Line 990] Single-line comment:
  //
[Line 997] Single-line comment:
  // Online transaction
[Line 1003] Single-line comment:
  // Offline transaction
[Line 1027] Single-line comment:
  //
[Line 1028] Single-line comment:
  // To
[Line 1029] Single-line comment:
  //
[Line 1033] Single-line comment:
  // Online transaction
[Line 1042] Single-line comment:
  //
[Line 1043] Single-line comment:
  // Amount
[Line 1044] Single-line comment:
  //
[Line 1047] Single-line comment:
  //
[Line 1048] Single-line comment:
  // Coinbase
[Line 1049] Single-line comment:
  //
[Line 1060] Single-line comment:
  //
[Line 1061] Single-line comment:
  // Credit
[Line 1062] Single-line comment:
  //
[Line 1077] Single-line comment:
  //
[Line 1078] Single-line comment:
  // Debit
[Line 1079] Single-line comment:
  //
[Line 1088] Single-line comment:
  // Online transaction
[Line 1093] Single-line comment:
  // Offline transaction
[Line 1109] Single-line comment:
  // Payment to self
[Line 1121] Single-line comment:
  //
[Line 1122] Single-line comment:
  // Mixed debit transaction
[Line 1123] Single-line comment:
  //
[Line 1136] Single-line comment:
  //
[Line 1137] Single-line comment:
  // Message
[Line 1138] Single-line comment:
  //
[Line 1143] Single-line comment:
  //
[Line 1144] Single-line comment:
  // Debug view
[Line 1145] Single-line comment:
  //
[Line 1189] Single-line comment:
  //Destroy();
[Line 1196] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 1197] Single-line comment:
  //
[Line 1198] Single-line comment:
  // COptionsDialog
[Line 1199] Single-line comment:
  //
[Line 1216] Single-line comment:
  // nTransactionFee
[Line 1234] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 1235] Single-line comment:
  //
[Line 1236] Single-line comment:
  // CAboutDialog
[Line 1237] Single-line comment:
  //
[Line 1243] Single-line comment:
  // Workaround until upgrade to wxWidgets supporting UTF-8
[Line 1260] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 1261] Single-line comment:
  //
[Line 1262] Single-line comment:
  // CSendDialog
[Line 1263] Single-line comment:
  //
[Line 1267] Single-line comment:
  // Init
[Line 1271] Single-line comment:
  //// todo: should add a display of your balance for convenience
[Line 1273] Single-line comment:
  // Set Icon
[Line 1283] Single-line comment:
  // Fixup the tab order
[Line 1291] Single-line comment:
  // Check mark
[Line 1295] Single-line comment:
  // Grey out message if bitcoin address
[Line 1306] Single-line comment:
  // Reformat the amount
[Line 1316] Single-line comment:
  // Open address book
[Line 1324] Single-line comment:
  // Copy clipboard to address box
[Line 1342] Single-line comment:
  // Parse amount
[Line 1360] Single-line comment:
  // Parse bitcoin address
[Line 1366] Single-line comment:
  // Send to bitcoin address
[Line 1377] Single-line comment:
  // Parse IP address
[Line 1385] Single-line comment:
  // Message
[Line 1390] Single-line comment:
  // Send to IP address
[Line 1404] Single-line comment:
  // Cancel
[Line 1413] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 1414] Single-line comment:
  //
[Line 1415] Single-line comment:
  // CSendingDialog
[Line 1416] Single-line comment:
  //
[Line 1418] Single-line comment:
  // we have to give null so parent can't destroy us
[Line 1444] Single-line comment:
  // Last one out turn out the lights.
[Line 1445] Single-line comment:
  // fWorkDone signals that work side is done and UI thread should call destroy.
[Line 1446] Single-line comment:
  // fUIDone signals that UI window has closed and work thread should call destroy.
[Line 1447] Single-line comment:
  // This allows the window to disappear and end modality when cancelled
[Line 1448] Single-line comment:
  // without making the user wait for ConnectNode to return.  The dialog object
[Line 1449] Single-line comment:
  // hangs around in the background until the work thread exits.
[Line 1513] Single-line comment:
  /// debug test
[Line 1523] Single-line comment:
  //
[Line 1524] Single-line comment:
  // Everything from here on is not in the UI thread and must only communicate
[Line 1525] Single-line comment:
  // with the rest of the dialog through variables and calling repaint.
[Line 1526] Single-line comment:
  //
[Line 1576] Single-line comment:
  // Make sure we have enough money
[Line 1583] Single-line comment:
  // We may have connected already for product details
[Line 1593] Single-line comment:
  // Send order to seller, with response going to OnReply2 via event handler
[Line 1619] Single-line comment:
  //// todo: enlarge the window and enable a hidden white box to put seller's message
[Line 1626] Single-line comment:
  //// what do we want to do about this?
[Line 1631] Single-line comment:
  // Should already be connected
[Line 1639] Single-line comment:
  // Pause to give the user a chance to cancel
[Line 1649] Single-line comment:
  // Pay
[Line 1667] Single-line comment:
  // Last chance to cancel
[Line 1682] Single-line comment:
  // Commit
[Line 1689] Single-line comment:
  // Send payment tx to seller, with response going to OnReply3 via event handler
[Line 1692] Single-line comment:
  // Accept and broadcast transaction
[Line 1723] Single-line comment:
  //// what do we want to do about this?
[Line 1738] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 1739] Single-line comment:
  //
[Line 1740] Single-line comment:
  // CYourAddressDialog
[Line 1741] Single-line comment:
  //
[Line 1745] Single-line comment:
  // Init column headers
[Line 1750] Single-line comment:
  // Fill listctrl with address book data
[Line 1779] Single-line comment:
  // Update address book with edited name
[Line 1793] Single-line comment:
  // Doubleclick returns selection
[Line 1799] Single-line comment:
  // Ask new name
[Line 1810] Single-line comment:
  // Change name
[Line 1818] Single-line comment:
  // Ask name
[Line 1824] Single-line comment:
  // Generate new key
[Line 1828] Single-line comment:
  // Add to list and select it
[Line 1836] Single-line comment:
  // Copy address box to clipboard
[Line 1846] Single-line comment:
  // OK
[Line 1852] Single-line comment:
  // Cancel
[Line 1858] Single-line comment:
  // Close
[Line 1867] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 1868] Single-line comment:
  //
[Line 1869] Single-line comment:
  // CAddressBookDialog
[Line 1870] Single-line comment:
  //
[Line 1878] Single-line comment:
  // Init column headers
[Line 1883] Single-line comment:
  // Set Icon
[Line 1890] Single-line comment:
  // Fill listctrl with address book data
[Line 1919] Single-line comment:
  // Update address book with edited name
[Line 1935] Single-line comment:
  // Doubleclick returns selection
[Line 1940] Single-line comment:
  // Doubleclick edits item
[Line 1948] Single-line comment:
  // Ask new name
[Line 1961] Single-line comment:
  // Change name
[Line 1972] Single-line comment:
  // Ask name
[Line 1979] Single-line comment:
  // Add to list and select it
[Line 2002] Single-line comment:
  // Copy address box to clipboard
[Line 2012] Single-line comment:
  // OK
[Line 2018] Single-line comment:
  // Cancel
[Line 2024] Single-line comment:
  // Close
[Line 2033] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 2034] Single-line comment:
  //
[Line 2035] Single-line comment:
  // CProductsDialog
[Line 2036] Single-line comment:
  //
[Line 2045] Single-line comment:
  // Init column headers
[Line 2052] Single-line comment:
  // Tally top categories
[Line 2058] Single-line comment:
  // Sort top categories
[Line 2064] Single-line comment:
  // Fill categories combo box
[Line 2069] Single-line comment:
  // Fill window with initial search
[Line 2070] Single-line comment:
  //wxCommandEvent event;
[Line 2071] Single-line comment:
  //OnButtonSearch(event);
[Line 2089] Single-line comment:
  // Search products
[Line 2108] Single-line comment:
  // Sort
[Line 2111] Single-line comment:
  // Display
[Line 2125] Single-line comment:
  // Doubleclick opens product
[Line 2136] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 2137] Single-line comment:
  //
[Line 2138] Single-line comment:
  // CEditProductDialog
[Line 2139] Single-line comment:
  //
[Line 2292] Single-line comment:
  // Sign the detailed product
[Line 2300] Single-line comment:
  // Save detailed product
[Line 2303] Single-line comment:
  // Strip down to summary product
[Line 2307] Single-line comment:
  // Sign the summary product
[Line 2314] Single-line comment:
  // Verify
[Line 2321] Single-line comment:
  // Broadcast
[Line 2372] Single-line comment:
  // map<string, string> mapValue;
[Line 2373] Single-line comment:
  // vector<pair<string, string> > vOrderForm;
[Line 2402] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 2403] Single-line comment:
  //
[Line 2404] Single-line comment:
  // CViewProductDialog
[Line 2405] Single-line comment:
  //
[Line 2412] Single-line comment:
  // Fill display with product summary while waiting for details
[Line 2422] Single-line comment:
  // Request details from seller
[Line 2433] Single-line comment:
  // Extract parameters
[Line 2439] Single-line comment:
  // Connect to seller
[Line 2448] Single-line comment:
  // Request detailed product, with response going to OnReply1 via dialog's event handler
[Line 2493] Single-line comment:
  // Product and reviews
[Line 2516] Single-line comment:
  // Get reviews
[Line 2520] Single-line comment:
  // Get reviewer's number of atoms
[Line 2534] Single-line comment:
  // Sort
[Line 2537] Single-line comment:
  // Format reviews
[Line 2555] Single-line comment:
  // Shrink capacity to fit
[Line 2560] Single-line comment:
  ///// need to find some other indicator to use so can allow empty order form
[Line 2564] Single-line comment:
  // Order form
[Line 2573] Single-line comment:
  // Construct flexgridsizer
[Line 2581] Single-line comment:
  // Construct order form fields
[Line 2623] Single-line comment:
  // Insert after instructions and before submit/cancel buttons
[Line 2629] Single-line comment:
  // Fixup the tab order
[Line 2632] Single-line comment:
  //m_buttonBack->MoveAfterInTabOrder(m_buttonCancelForm);
[Line 2633] Single-line comment:
  //m_buttonNext->MoveAfterInTabOrder(m_buttonBack);
[Line 2634] Single-line comment:
  //m_buttonCancel->MoveAfterInTabOrder(m_buttonNext);
[Line 2710] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 2711] Single-line comment:
  //
[Line 2712] Single-line comment:
  // CViewOrderDialog
[Line 2713] Single-line comment:
  //
[Line 2740] Single-line comment:
  // Shrink capacity to fit
[Line 2741] Single-line comment:
  // (strings are ref counted, so it may live on in SetPage)
[Line 2758] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 2759] Single-line comment:
  //
[Line 2760] Single-line comment:
  // CEditReviewDialog
[Line 2761] Single-line comment:
  //
[Line 2778] Single-line comment:
  // Sign the review
[Line 2786] Single-line comment:
  // Broadcast
[Line 2820] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 2821] Single-line comment:
  //
[Line 2822] Single-line comment:
  // CMyApp
[Line 2823] Single-line comment:
  //
[Line 2825] Single-line comment:
  // Define a new application
[Line 2835] Single-line comment:
  // 2nd-level exception handling: we get all the exceptions occurring in any
[Line 2836] Single-line comment:
  // event handler here
[Line 2839] Single-line comment:
  // 3rd, and final, level exception handling: whenever an unhandled
[Line 2840] Single-line comment:
  // exception is caught, this function is called
[Line 2843] Single-line comment:
  // and now for something different: this function is called in case of a
[Line 2844] Single-line comment:
  // crash (e.g. dereferencing null pointer, division by 0, ...)
[Line 2888] Single-line comment:
  // Turn off microsoft heap dump noise for now
[Line 2893] Single-line comment:
  //// debug print
[Line 2897] Single-line comment:
  //
[Line 2898] Single-line comment:
  // Limit to single instance per user
[Line 2899] Single-line comment:
  // Required to protect the database files if we're going to keep deleting log.*
[Line 2900] Single-line comment:
  //
[Line 2912] Single-line comment:
  // Show the previous instance and exit
[Line 2925] Single-line comment:
  // Resume this instance if the other exits
[Line 2934] Single-line comment:
  //
[Line 2935] Single-line comment:
  // Parameters
[Line 2936] Single-line comment:
  //
[Line 2964] Single-line comment:
  //
[Line 2965] Single-line comment:
  // Load data files
[Line 2966] Single-line comment:
  //
[Line 2993] Single-line comment:
  //// debug print
[Line 3008] Single-line comment:
  // Add wallet transactions that aren't already in a block to mapTransactions
[Line 3011] Single-line comment:
  //
[Line 3012] Single-line comment:
  // Parameters
[Line 3013] Single-line comment:
  //
[Line 3029] Single-line comment:
  //
[Line 3030] Single-line comment:
  // Create the main frame window
[Line 3031] Single-line comment:
  //
[Line 3043] Single-line comment:
  //
[Line 3044] Single-line comment:
  // Tests
[Line 3045] Single-line comment:
  //
[Line 3062] Single-line comment:
  // Send to IP address
[Line 3113] Single-line comment:
  // this shows how we may let some exception propagate uncaught
[Line 3158] Single-line comment:
  // randsendtest to bitcoin address
[Line 3173] Single-line comment:
  // Message
[Line 3180] Single-line comment:
  // Value
[Line 3189] Single-line comment:
  // Send to bitcoin address
[Line 3199] Single-line comment:
  // randsendtest to any connected node
[Line 3210] Single-line comment:
  // Message
[Line 3216] Single-line comment:
  // Value
[Line 3224] Single-line comment:
  // Send to IP address

File: /home/user/bitcoinArchive/bitcoin0.1/src/ui.h
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 38] Single-line comment:
  // Event handlers
[Lines 62-62] Multi-line comment:
      /** Constructor */
[Line 66] Single-line comment:
  // Custom
[Line 86] Single-line comment:
  // Event handlers
[Lines 90-90] Multi-line comment:
      /** Constructor */
[Line 93] Single-line comment:
  // State
[Line 102] Single-line comment:
  // Event handlers
[Lines 108-108] Multi-line comment:
      /** Constructor */
[Line 117] Single-line comment:
  // Event handlers
[Lines 121-121] Multi-line comment:
      /** Constructor */
[Line 130] Single-line comment:
  // Event handlers
[Lines 140-140] Multi-line comment:
      /** Constructor */
[Line 149] Single-line comment:
  // Event handlers
[Lines 156-156] Multi-line comment:
      /** Constructor */
[Line 160] Single-line comment:
  // State
[Line 191] Single-line comment:
  // Event handlers
[Lines 203-203] Multi-line comment:
      /** Constructor */
[Line 207] Single-line comment:
  // Custom
[Line 216] Single-line comment:
  // Event handlers
[Lines 229-229] Multi-line comment:
      /** Constructor */
[Line 232] Single-line comment:
  // Custom
[Line 242] Single-line comment:
  // Event handlers
[Lines 249-249] Multi-line comment:
      /** Constructor */
[Line 252] Single-line comment:
  // Custom
[Line 261] Single-line comment:
  // Event handlers
[Lines 289-289] Multi-line comment:
      /** Constructor */
[Line 292] Single-line comment:
  // Custom
[Line 311] Single-line comment:
  // Event handlers
[Lines 319-319] Multi-line comment:
      /** Constructor */
[Line 323] Single-line comment:
  // Custom
[Line 340] Single-line comment:
  // Event handlers
[Lines 344-344] Multi-line comment:
      /** Constructor */
[Line 347] Single-line comment:
  // Custom
[Line 356] Single-line comment:
  // Event handlers
[Lines 362-362] Multi-line comment:
      /** Constructor */
[Line 365] Single-line comment:
  // Custom
[Line 374] Single-line comment:
  // Event handlers
[Lines 388-388] Multi-line comment:
      /** Constructor */
[Line 408] Single-line comment:
  // Custom

File: /home/user/bitcoinArchive/bitcoin0.1/src/uibase.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 5] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////
[Line 6] Single-line comment:
  // C++ code generated with wxFormBuilder (version Apr 16 2008)
[Line 7] Single-line comment:
  // http://www.wxformbuilder.org/
[Line 8] Single-line comment:
  //
[Line 9] Single-line comment:
  // PLEASE DO "NOT" EDIT THIS FILE!
[Line 10] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////
[Line 14] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////
[Line 207] Single-line comment:
  // Connect Events
[Line 257] Single-line comment:
  // Disconnect Events
[Line 331] Single-line comment:
  // Connect Events
[Line 337] Single-line comment:
  // Disconnect Events
[Line 388] Single-line comment:
  // Connect Events
[Line 396] Single-line comment:
  // Disconnect Events
[Line 441] Single-line comment:
  //www.opensource.org/licenses/mit-license.php.\n\nThis product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/) and cryptographic software written by Eric Young (eay@cryptsoft.com)."), wxDefaultPosition, wxDefaultSize, 0);
[Line 466] Single-line comment:
  // Connect Events
[Line 472] Single-line comment:
  // Disconnect Events
[Line 607] Single-line comment:
  // Connect Events
[Line 622] Single-line comment:
  // Disconnect Events
[Line 673] Single-line comment:
  // Connect Events
[Line 682] Single-line comment:
  // Disconnect Events
[Line 742] Single-line comment:
  // Connect Events
[Line 756] Single-line comment:
  // Disconnect Events
[Line 823] Single-line comment:
  // Connect Events
[Line 837] Single-line comment:
  // Disconnect Events
[Line 877] Single-line comment:
  // Connect Events
[Line 886] Single-line comment:
  // Disconnect Events
[Line 1233] Single-line comment:
  // Connect Events
[Line 1306] Single-line comment:
  // Disconnect Events
[Line 1449] Single-line comment:
  // Connect Events
[Line 1459] Single-line comment:
  // Disconnect Events
[Line 1496] Single-line comment:
  // Connect Events
[Line 1502] Single-line comment:
  // Disconnect Events
[Line 1559] Single-line comment:
  // Connect Events
[Line 1567] Single-line comment:
  // Disconnect Events
[Line 1600] Single-line comment:
  // Connect Events
[Line 1609] Single-line comment:
  // Disconnect Events
[Line 1669] Single-line comment:
  // Connect Events
[Line 1702] Single-line comment:
  // Disconnect Events
[Line 1790] Single-line comment:
  // Connect Events
[Line 1800] Single-line comment:
  // Disconnect Events

File: /home/user/bitcoinArchive/bitcoin0.1/src/uibase.h
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 5] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////
[Line 6] Single-line comment:
  // C++ code generated with wxFormBuilder (version Apr 16 2008)
[Line 7] Single-line comment:
  // http://www.wxformbuilder.org/
[Line 8] Single-line comment:
  //
[Line 9] Single-line comment:
  // PLEASE DO "NOT" EDIT THIS FILE!
[Line 10] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////
[Line 44] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////
[Line 99] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 100] Single-line comment:
  /// Class CMainFrameBase
[Line 101] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 130] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 166] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 167] Single-line comment:
  /// Class CTxDetailsDialogBase
[Line 168] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 177] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 187] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 188] Single-line comment:
  /// Class COptionsDialogBase
[Line 189] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 202] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 214] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 215] Single-line comment:
  /// Class CAboutDialogBase
[Line 216] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 231] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 242] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 243] Single-line comment:
  /// Class CSendDialogBase
[Line 244] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 271] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 287] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 288] Single-line comment:
  /// Class CSendingDialogBase
[Line 289] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 301] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 314] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 315] Single-line comment:
  /// Class CYourAddressDialogBase
[Line 316] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 332] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 350] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 351] Single-line comment:
  /// Class CAddressBookDialogBase
[Line 352] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 367] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 386] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 387] Single-line comment:
  /// Class CProductsDialogBase
[Line 388] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 399] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 412] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 413] Single-line comment:
  /// Class CEditProductDialogBase
[Line 414] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 499] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 534] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 535] Single-line comment:
  /// Class CViewProductDialogBase
[Line 536] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 552] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 566] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 567] Single-line comment:
  /// Class CViewOrderDialogBase
[Line 568] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 577] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 587] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 588] Single-line comment:
  /// Class CEditReviewDialogBase
[Line 589] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 605] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 617] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 618] Single-line comment:
  /// Class CPokerLobbyDialogBase
[Line 619] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 629] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 642] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 643] Single-line comment:
  /// Class CPokerDialogBase
[Line 644] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 657] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 689] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 690] Single-line comment:
  /// Class CGetTextFromUserDialogBase
[Line 691] Single-line comment:
  ///////////////////////////////////////////////////////////////////////////////
[Line 707] Single-line comment:
  // Virtual event handlers, overide them in your derived class
[Line 720] Single-line comment:
  //__uibase__

File: /home/user/bitcoinArchive/bitcoin0.1/src/uint256.h
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 23] Single-line comment:
  // We have to keep a separate base class without constructors
[Line 24] Single-line comment:
  // so the compiler will let us use it in a union
[Line 181] Single-line comment:
  // prefix operator
[Line 190] Single-line comment:
  // postfix operator
[Line 198] Single-line comment:
  // prefix operator
[Line 207] Single-line comment:
  // postfix operator
[Line 307] Single-line comment:
  // skip 0x
[Line 316] Single-line comment:
  // hex string to uint
[Line 384] Single-line comment:
  //
[Line 385] Single-line comment:
  // uint160 and uint256 could be implemented as templates, but to keep
[Line 386] Single-line comment:
  // compile errors and debugging cleaner, they're copy and pasted.
[Line 387] Single-line comment:
  // It's safe to search and replace 160 with 256 and vice versa.
[Line 388] Single-line comment:
  //
[Line 392] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 393] Single-line comment:
  //
[Line 394] Single-line comment:
  // uint160
[Line 395] Single-line comment:
  //
[Line 504] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 505] Single-line comment:
  //
[Line 506] Single-line comment:
  // uint256
[Line 507] Single-line comment:
  //

File: /home/user/bitcoinArchive/bitcoin0.1/src/util.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 14] Single-line comment:
  // Init openssl library multithreading support
[Line 25] Single-line comment:
  // Init
[Line 31] Single-line comment:
  // Init openssl library multithreading support
[Line 37] Single-line comment:
  // Seed random number generator with screen scrape and other hardware sources
[Line 40] Single-line comment:
  // Seed random number generator with perfmon data
[Line 45] Single-line comment:
  // Shutdown openssl library multithreading support
[Line 59] Single-line comment:
  // Seed with CPU performance counter
[Line 70] Single-line comment:
  // Seed with the entire set of perfmon data
[Line 97] Single-line comment:
  // Safer snprintf
[Line 98] Single-line comment:
  //  - prints up to limit-1 characters
[Line 99] Single-line comment:
  //  - output string is always null terminated even if limit reached
[Line 100] Single-line comment:
  //  - return value is the number of characters actually printed
[Line 140] Single-line comment:
  // msvc optimisation
[Line 186] Single-line comment:
  //DebugBreak();
[Line 300] Single-line comment:
  // The range of the random source must be a multiple of the modulus
[Line 301] Single-line comment:
  // to give every possible output value an equal possibility
[Line 319] Single-line comment:
  //
[Line 320] Single-line comment:
  // "Never go to sea with two chronometers; take one or three."
[Line 321] Single-line comment:
  // Our three chronometers are:
[Line 322] Single-line comment:
  //  - System clock
[Line 323] Single-line comment:
  //  - Median of other server's clocks
[Line 324] Single-line comment:
  //  - NTP servers
[Line 325] Single-line comment:
  //
[Line 326] Single-line comment:
  // note: NTP isn't implemented yet, so until then we just use the median
[Line 327] Single-line comment:
  //  of other nodes clocks to correct ours.
[Line 328] Single-line comment:
  //
[Line 346] Single-line comment:
  // Ignore duplicates
[Line 351] Single-line comment:
  // Add data
[Line 364] Single-line comment:
  // Only let other nodes change our clock so far before we
[Line 365] Single-line comment:
  // go to the NTP servers
[Line 366] Single-line comment:
  /// todo: Get time from NTP servers, then set a flag
[Line 367] Single-line comment:
  ///    to make sure it doesn't get changed again

File: /home/user/bitcoinArchive/bitcoin0.1/src/util.h
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 50] Single-line comment:
  // This is needed because the foreach macro can't get over the comma in pair<t1, t2>
[Line 53] Single-line comment:
  // Used to bypass the rule against non-const reference to temporary
[Line 54] Single-line comment:
  // where it makes sense with wrappers such as CFlatData or CTxDB
[Line 97] Single-line comment:
  // Wrapper to automatically initialize critical section
[Line 98] Single-line comment:
  // Could use wxCriticalSection for portability, but it doesn't support TryEnterCriticalSection
[Line 114] Single-line comment:
  // Automatically leave critical section when leaving block, needed for exception safety
[Line 125] Single-line comment:
  // WARNING: This will catch continue and break!
[Line 126] Single-line comment:
  // break is caught with an assertion, but there's no way to detect continue.
[Line 127] Single-line comment:
  // I'd rather be careful than suffer the other more error prone syntax.
[Line 128] Single-line comment:
  // The compiler will optimise away all this loop junk.
[Line 235] Single-line comment:
  // log file
[Line 246] Single-line comment:
  // accumulate a line at a time
[Line 287] Single-line comment:
  // print to console
[Line 310] Single-line comment:
  // Randomize the stack to help protect against buffer overrun exploits
[Line 383] Single-line comment:
  // Most of the time is spent allocating and deallocating CDataStream's
[Line 384] Single-line comment:
  // buffer.  If this ever needs to be optimized further, make a CStaticStream
[Line 385] Single-line comment:
  // class with its buffer on the stack.

File: /home/user/bitcoinArchive/bitcoin0.1/src/base58.h
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 6] Single-line comment:
  //
[Line 7] Single-line comment:
  // Why base-58 instead of standard base-64 encoding?
[Line 8] Single-line comment:
  // - Don't want 0OIl characters that look the same in some fonts and
[Line 9] Single-line comment:
  //      could be used to create visually identical looking account numbers.
[Line 10] Single-line comment:
  // - A string with non-alphanumeric characters is not as easily accepted as an account number.
[Line 11] Single-line comment:
  // - E-mail usually won't line-break if there's no punctuation to break at.
[Line 12] Single-line comment:
  // - Doubleclicking selects the whole number as one word if it's all alphanumeric.
[Line 13] Single-line comment:
  //
[Line 25] Single-line comment:
  // Convert big endian data to little endian
[Line 26] Single-line comment:
  // Extra zero at the end make sure bignum will interpret as a positive number
[Line 30] Single-line comment:
  // Convert little endian data to bignum
[Line 34] Single-line comment:
  // Convert bignum to string
[Line 48] Single-line comment:
  // Leading zeroes encoded as base58 zeros
[Line 52] Single-line comment:
  // Convert little endian string to big endian
[Line 72] Single-line comment:
  // Convert big endian string to bignum
[Line 90] Single-line comment:
  // Get bignum as little endian data
[Line 93] Single-line comment:
  // Trim off sign byte if present
[Line 97] Single-line comment:
  // Restore leading zeros
[Line 103] Single-line comment:
  // Convert little endian data to big endian
[Line 119] Single-line comment:
  // add 4-byte hash check to the end
[Line 159] Single-line comment:
  // add 1-byte version number to the front

File: /home/user/bitcoinArchive/bitcoin0.1/src/bignum.h
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 284] Single-line comment:
  // skip 0x
[Line 299] Single-line comment:
  // hex string to bignum
[Line 387] Single-line comment:
  // prefix operator
[Line 395] Single-line comment:
  // postfix operator
[Line 403] Single-line comment:
  // prefix operator
[Line 413] Single-line comment:
  // postfix operator

File: /home/user/bitcoinArchive/bitcoin0.1/src/key.h
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 6] Single-line comment:
  // secp160k1
[Line 7] Single-line comment:
  // const unsigned int PRIVATE_KEY_SIZE = 192;
[Line 8] Single-line comment:
  // const unsigned int PUBLIC_KEY_SIZE  = 41;
[Line 9] Single-line comment:
  // const unsigned int SIGNATURE_SIZE   = 48;
[Line 10] Single-line comment:
  //
[Line 11] Single-line comment:
  // secp192k1
[Line 12] Single-line comment:
  // const unsigned int PRIVATE_KEY_SIZE = 222;
[Line 13] Single-line comment:
  // const unsigned int PUBLIC_KEY_SIZE  = 49;
[Line 14] Single-line comment:
  // const unsigned int SIGNATURE_SIZE   = 57;
[Line 15] Single-line comment:
  //
[Line 16] Single-line comment:
  // secp224k1
[Line 17] Single-line comment:
  // const unsigned int PRIVATE_KEY_SIZE = 250;
[Line 18] Single-line comment:
  // const unsigned int PUBLIC_KEY_SIZE  = 57;
[Line 19] Single-line comment:
  // const unsigned int SIGNATURE_SIZE   = 66;
[Line 20] Single-line comment:
  //
[Line 21] Single-line comment:
  // secp256k1:
[Line 22] Single-line comment:
  // const unsigned int PRIVATE_KEY_SIZE = 279;
[Line 23] Single-line comment:
  // const unsigned int PUBLIC_KEY_SIZE  = 65;
[Line 24] Single-line comment:
  // const unsigned int SIGNATURE_SIZE   = 72;
[Line 25] Single-line comment:
  //
[Line 26] Single-line comment:
  // see www.keylength.com
[Line 27] Single-line comment:
  // script supports up to 75 for single byte push
[Line 38] Single-line comment:
  // secure_allocator is defined is serialize.h
[Line 135] Single-line comment:
  // -1 = error, 0 = bad sig, 1 = good


================================================================================
NOV08 FILES
================================================================================

File: /home/user/bitcoinArchive/nov08/main.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2008 Satoshi Nakamoto
[Line 2] Single-line comment:
  //
[Line 3] Single-line comment:
  // Permission is hereby granted, free of charge, to any person obtaining a copy
[Line 4] Single-line comment:
  // of this software and associated documentation files (the "Software"), to deal
[Line 5] Single-line comment:
  // in the Software without restriction, including without limitation the rights
[Line 6] Single-line comment:
  // to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
[Line 7] Single-line comment:
  // copies of the Software, and to permit persons to whom the Software is
[Line 8] Single-line comment:
  // furnished to do so, subject to the following conditions:
[Line 9] Single-line comment:
  //
[Line 10] Single-line comment:
  // The above copyright notice and this permission notice shall be included in
[Line 11] Single-line comment:
  // all copies or substantial portions of the Software.
[Line 12] Single-line comment:
  //
[Line 13] Single-line comment:
  // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
[Line 14] Single-line comment:
  // IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
[Line 15] Single-line comment:
  // FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
[Line 16] Single-line comment:
  // SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
[Line 17] Single-line comment:
  // OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
[Line 18] Single-line comment:
  // FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
[Line 19] Single-line comment:
  // IN THE SOFTWARE.
[Line 28] Single-line comment:
  //
[Line 29] Single-line comment:
  // Global state
[Line 30] Single-line comment:
  //
[Line 35] Single-line comment:
  /// mapNextTx is only used anymore to track disk tx outpoints used by memory txes
[Line 70] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 71] Single-line comment:
  //
[Line 72] Single-line comment:
  // mapKeys
[Line 73] Single-line comment:
  //
[Line 97] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 98] Single-line comment:
  //
[Line 99] Single-line comment:
  // mapWallet
[Line 100] Single-line comment:
  //
[Line 107] Single-line comment:
  // Inserts only if not already there, returns tx inserted or tx found
[Line 112] Single-line comment:
  //// debug print
[Line 117] Single-line comment:
  // Merge
[Line 138] Single-line comment:
  // Write to disk
[Line 142] Single-line comment:
  // Notify UI
[Line 146] Single-line comment:
  // Refresh UI
[Line 172] Single-line comment:
  // Reaccept any txes of ours that aren't already in a block
[Line 192] Single-line comment:
  // Rebroadcast any of our txes that aren't in a block yet
[Line 211] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 212] Single-line comment:
  //
[Line 213] Single-line comment:
  // CTransaction
[Line 214] Single-line comment:
  //
[Line 254] Single-line comment:
  // Load the block this tx is in
[Line 262] Single-line comment:
  // Update the tx's hashBlock
[Line 265] Single-line comment:
  // Locate the transaction
[Line 277] Single-line comment:
  // Fill in merkle branch
[Line 281] Single-line comment:
  // Is the tx in a block that's in the main chain
[Line 356] Single-line comment:
  // Relinquish previous transactions' posNext pointers
[Line 368] Single-line comment:
  // Get prev tx from disk
[Line 369] Single-line comment:
  // Version -1 tells unserialize to set version so we write back same version
[Line 378] Single-line comment:
  // Relinquish posNext pointer
[Line 381] Single-line comment:
  // Write back
[Line 389] Single-line comment:
  // Put a blocked-off copy of this transaction in the test pool
[Line 397] Single-line comment:
  // Remove transaction from index
[Line 401] Single-line comment:
  // Resurect single transaction objects
[Line 413] Single-line comment:
  // Take over previous transactions' posNext pointers
[Line 426] Single-line comment:
  // Get prev tx from single transactions in memory
[Line 431] Single-line comment:
  // Get prev tx from disk
[Line 432] Single-line comment:
  // Version -1 tells unserialize to set version so we write back same version
[Line 437] Single-line comment:
  // If tx will only be connected in a reorg,
[Line 438] Single-line comment:
  // then these outpoints will be checked at that time
[Line 447] Single-line comment:
  // Verify signature
[Line 451] Single-line comment:
  // Check for conflicts
[Line 455] Single-line comment:
  // Flag outpoints as used
[Line 458] Single-line comment:
  // Write back
[Line 465] Single-line comment:
  // Tally transaction fees
[Line 474] Single-line comment:
  // Add transaction to test pool
[Line 479] Single-line comment:
  // Add transaction to disk index
[Line 483] Single-line comment:
  // Delete redundant single transaction objects
[Line 500] Single-line comment:
  // Coinbase is only valid in a block, not as a loose transaction
[Line 511] Single-line comment:
  // Check for conflicts with in-memory transactions
[Line 512] Single-line comment:
  // and allow replacing with a newer version of the same transaction
[Line 530] Single-line comment:
  // Check against previous transactions
[Line 537] Single-line comment:
  // Store transaction in memory
[Line 545] Single-line comment:
  //printf("mapTransaction.insert(%s)\n  ", hash.ToString().c_str());
[Line 546] Single-line comment:
  //print();
[Line 552] Single-line comment:
  // If updated, erase old tx from wallet
[Line 570] Single-line comment:
  // Find the block it claims to be in
[Line 578] Single-line comment:
  // Get merkle root
[Line 583] Single-line comment:
  // Make sure the merkle branch connects to this block
[Line 642] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 643] Single-line comment:
  //
[Line 644] Single-line comment:
  // CBlock and CBlockIndex
[Line 645] Single-line comment:
  //
[Line 666] Single-line comment:
  // Cache
[Line 674] Single-line comment:
  // Go back 30 days
[Line 681] Single-line comment:
  // Load first and last block
[Line 689] Single-line comment:
  // Limit one change per timespan
[Line 710] Single-line comment:
  // Work back to the first block in the orphan chain
[Line 755] Single-line comment:
  //// issue here: it doesn't know the version
[Line 769] Single-line comment:
  // Watch for transactions paying to me
[Line 780] Single-line comment:
  // Find the fork
[Line 792] Single-line comment:
  // List of what to disconnect
[Line 797] Single-line comment:
  // List of what to connect
[Line 803] Single-line comment:
  // Pretest the reorg
[Line 819] Single-line comment:
  // Invalid block, delete the rest of this branch
[Line 831] Single-line comment:
  // Disconnect shorter branch
[Line 840] Single-line comment:
  // Connect longer branch
[Line 857] Single-line comment:
  // Add to block index
[Line 869] Single-line comment:
  // New best
[Line 878] Single-line comment:
  // Adding to current best branch
[Line 886] Single-line comment:
  // New best branch
[Line 891] Single-line comment:
  // New best link
[Line 897] Single-line comment:
  // Relay wallet transactions that haven't gotten in yet
[Line 913] Single-line comment:
  // Scan ahead to the next pchMessageStart, which should normally be immediately
[Line 914] Single-line comment:
  // at the file pointer.  Leaves file pointer at end of pchMessageStart.
[Line 981] Single-line comment:
  // FAT32 filesize max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
[Line 994] Single-line comment:
  //
[Line 995] Single-line comment:
  // Load from disk
[Line 996] Single-line comment:
  //
[Line 1010] Single-line comment:
  //// debug
[Line 1011] Single-line comment:
  // Genesis Block:
[Line 1012] Single-line comment:
  // GetHash()      = 0x000006b15d1327d67e971d1de9116bd60a3a01556c91b6ebaa416ebc0cfaa646
[Line 1013] Single-line comment:
  // hashPrevBlock  = 0x0000000000000000000000000000000000000000000000000000000000000000
[Line 1014] Single-line comment:
  // hashMerkleRoot = 0x769a5e93fac273fd825da42d39ead975b5d712b2d50953f35a4fdebdec8083e3
[Line 1015] Single-line comment:
  // txNew.vin[0].scriptSig      = 247422313
[Line 1016] Single-line comment:
  // txNew.vout[0].nValue        = 10000
[Line 1017] Single-line comment:
  // txNew.vout[0].scriptPubKey  = OP_CODESEPARATOR 0x31D18A083F381B4BDE37B649AACF8CD0AFD88C53A3587ECDB7FAF23D449C800AF1CE516199390BFE42991F10E7F5340F2A63449F0B639A7115C667E5D7B051D404 OP_CHECKSIG
[Line 1018] Single-line comment:
  // nTime          = 1221069728
[Line 1019] Single-line comment:
  // nBits          = 20
[Line 1020] Single-line comment:
  // nNonce         = 141755
[Line 1021] Single-line comment:
  // CBlock(hashPrevBlock=000000, hashMerkleRoot=769a5e, nTime=1221069728, nBits=20, nNonce=141755, vtx=1)
[Line 1022] Single-line comment:
  //   CTransaction(vin.size=1, vout.size=1, nLockTime=0)
[Line 1023] Single-line comment:
  //     CTxIn(COutPoint(000000, -1), coinbase 04695dbf0e)
[Line 1024] Single-line comment:
  //     CTxOut(nValue=10000, nSequence=4294967295, scriptPubKey=51b0, posNext=null)
[Line 1025] Single-line comment:
  //   vMerkleTree: 769a5e
[Line 1027] Single-line comment:
  // Genesis block
[Line 1042] Single-line comment:
  //// debug print
[Line 1052] Single-line comment:
  // Start new block file
[Line 1069] Single-line comment:
  // Read index header
[Line 1075] Single-line comment:
  // Read block header
[Line 1080] Single-line comment:
  // Skip transactions
[Line 1082] Single-line comment:
  //// is this all we want to do if there's a file error like this?
[Line 1084] Single-line comment:
  // Add to block index without updating disk
[Line 1096] Single-line comment:
  // precompute tree structure
[Line 1102] Single-line comment:
  // test
[Line 1103] Single-line comment:
  //while (rand() % 3 == 0)
[Line 1104] Single-line comment:
  //    mapNext[pindex->pprev].push_back(pindex);
[Line 1117] Single-line comment:
  // print split or gap
[Line 1132] Single-line comment:
  // print columns
[Line 1136] Single-line comment:
  // print item
[Line 1139] Single-line comment:
  // put the main timechain first
[Line 1150] Single-line comment:
  // iterate children
[Line 1163] Single-line comment:
  // Size limits
[Line 1167] Single-line comment:
  // Check timestamp
[Line 1171] Single-line comment:
  // Check proof of work matches claimed amount
[Line 1177] Single-line comment:
  // First transaction must be coinbase, the rest must not be
[Line 1184] Single-line comment:
  // Check transactions
[Line 1189] Single-line comment:
  // Check merkleroot
[Line 1198] Single-line comment:
  // Check for duplicate
[Line 1203] Single-line comment:
  // Get prev block index
[Line 1209] Single-line comment:
  // Check timestamp against prev
[Line 1216] Single-line comment:
  // Check proof of work
[Line 1220] Single-line comment:
  // Check transaction inputs and verify signatures
[Line 1233] Single-line comment:
  // Write block to history file
[Line 1244] Single-line comment:
  // Add atoms to user reviews for coins created
[Line 1260] Single-line comment:
  // Check for duplicate
[Line 1265] Single-line comment:
  // Preliminary checks
[Line 1273] Single-line comment:
  // If don't already have its previous block, shunt it off to holding area until we get it
[Line 1279] Single-line comment:
  // Ask this guy to fill in what we're missing
[Line 1285] Single-line comment:
  // Store to disk
[Line 1294] Single-line comment:
  // Now process any orphan blocks that depended on this one

File: /home/user/bitcoinArchive/nov08/main.h
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2008 Satoshi Nakamoto
[Line 2] Single-line comment:
  //
[Line 3] Single-line comment:
  // Permission is hereby granted, free of charge, to any person obtaining a copy
[Line 4] Single-line comment:
  // of this software and associated documentation files (the "Software"), to deal
[Line 5] Single-line comment:
  // in the Software without restriction, including without limitation the rights
[Line 6] Single-line comment:
  // to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
[Line 7] Single-line comment:
  // copies of the Software, and to permit persons to whom the Software is
[Line 8] Single-line comment:
  // furnished to do so, subject to the following conditions:
[Line 9] Single-line comment:
  //
[Line 10] Single-line comment:
  // The above copyright notice and this permission notice shall be included in
[Line 11] Single-line comment:
  // all copies or substantial portions of the Software.
[Line 12] Single-line comment:
  //
[Line 13] Single-line comment:
  // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
[Line 14] Single-line comment:
  // IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
[Line 15] Single-line comment:
  // FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
[Line 16] Single-line comment:
  // SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
[Line 17] Single-line comment:
  // OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
[Line 18] Single-line comment:
  // FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
[Line 19] Single-line comment:
  // IN THE SOFTWARE.
[Line 36] Single-line comment:
  /// change this to a user options setting, optional fee can be zero
[Line 37] Single-line comment:
  ///static const unsigned int MINPROOFOFWORK = 40; /// need to decide the right difficulty to start with
[Line 38] Single-line comment:
  /// ridiculously easy for testing
[Line 184] Single-line comment:
  //
[Line 185] Single-line comment:
  // An input of a transaction.  It contains the location of the previous
[Line 186] Single-line comment:
  // transaction's output that it claims and a signature that matches the
[Line 187] Single-line comment:
  // output's public key.
[Line 188] Single-line comment:
  //
[Line 255] Single-line comment:
  //
[Line 256] Single-line comment:
  // An output of a transaction.  It contains the public key that the next input
[Line 257] Single-line comment:
  // must be able to sign with to claim it.
[Line 258] Single-line comment:
  //
[Line 266] Single-line comment:
  // disk only
[Line 267] Single-line comment:
  //// so far this is only used as a flag, nothing uses the location
[Line 335] Single-line comment:
  //
[Line 336] Single-line comment:
  // The basic transaction that is broadcasted on the network and contained in
[Line 337] Single-line comment:
  // blocks.  A transaction can contain multiple inputs and outputs.
[Line 338] Single-line comment:
  //
[Line 357] Single-line comment:
  // Set version on stream for writing back same version
[Line 439] Single-line comment:
  // Basic checks that don't depend on any context
[Line 443] Single-line comment:
  // Check for negative values
[Line 511] Single-line comment:
  // Read transaction
[Line 516] Single-line comment:
  // Return file pointer
[Line 598] Single-line comment:
  //
[Line 599] Single-line comment:
  // A transaction with a merkle branch linking it to the timechain
[Line 600] Single-line comment:
  //
[Line 644] Single-line comment:
  //
[Line 645] Single-line comment:
  // A transaction with a bunch of additional info that only the owner cares
[Line 646] Single-line comment:
  // about.  It includes any unrecorded transactions needed to link it back
[Line 647] Single-line comment:
  // to the timechain.
[Line 648] Single-line comment:
  //
[Line 659] Single-line comment:
  //// probably need to sign the order info so know it came from payer
[Line 685] Single-line comment:
  /// would be nice for it to return the version number it reads, maybe use a reference
[Line 718] Single-line comment:
  //
[Line 719] Single-line comment:
  // Nodes collect new transactions into a block, hash them into a hash tree,
[Line 720] Single-line comment:
  // and scan through nonce values to make the block's hash satisfy proof-of-work
[Line 721] Single-line comment:
  // requirements.  When they solve the proof-of-work, they broadcast the block
[Line 722] Single-line comment:
  // to everyone and the block is added to the timechain.  The first transaction
[Line 723] Single-line comment:
  // in the block is a special one that creates a new coin owned by the creator
[Line 724] Single-line comment:
  // of the block.
[Line 725] Single-line comment:
  //
[Line 726] Single-line comment:
  // Blocks are appended to blk0001.dat files on disk.  Their location on disk
[Line 727] Single-line comment:
  // is indexed by CBlockIndex objects in memory.
[Line 728] Single-line comment:
  //
[Line 732] Single-line comment:
  // header
[Line 739] Single-line comment:
  // network and disk
[Line 742] Single-line comment:
  // memory only
[Line 761] Single-line comment:
  // ConnectBlock depends on vtx being last so it can calculate offset
[Line 840] Single-line comment:
  // Open history file to append
[Line 847] Single-line comment:
  // Write index header
[Line 851] Single-line comment:
  // Write block
[Line 864] Single-line comment:
  // Open history file to read
[Line 871] Single-line comment:
  // Read block
[Line 874] Single-line comment:
  // Check the header
[Line 918] Single-line comment:
  //
[Line 919] Single-line comment:
  // The timechain is a tree shaped structure starting with the
[Line 920] Single-line comment:
  // genesis block at the root, with each block potentially having multiple
[Line 921] Single-line comment:
  // candidates to be the next block.  pprev and pnext link a path through the
[Line 922] Single-line comment:
  // main/longest chain.  A blockindex may have multiple pprev pointing back
[Line 923] Single-line comment:
  // to it, but pnext will only point forward to the longest branch, or will
[Line 924] Single-line comment:
  // be null if the block is not part of the longest chain.
[Line 925] Single-line comment:
  //
[Line 961] Single-line comment:
  // Open history file
[Line 966] Single-line comment:
  // Overwrite with empty null block
[Line 1025] Single-line comment:
  //
[Line 1026] Single-line comment:
  // Describes a place in the timechain to another node such that if the
[Line 1027] Single-line comment:
  // other node doesn't have the same branch, it can find a recent common trunk.
[Line 1028] Single-line comment:
  // The further back it is, the further before the branch point it may be.
[Line 1029] Single-line comment:
  //
[Line 1069] Single-line comment:
  // Exponentially larger steps back
[Line 1079] Single-line comment:
  // Find the first block the caller has in the main chain
[Line 1095] Single-line comment:
  // Find the first block the caller has in the main chain

File: /home/user/bitcoinArchive/nov08/node.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2008 Satoshi Nakamoto
[Line 2] Single-line comment:
  //
[Line 3] Single-line comment:
  // Permission is hereby granted, free of charge, to any person obtaining a copy
[Line 4] Single-line comment:
  // of this software and associated documentation files (the "Software"), to deal
[Line 5] Single-line comment:
  // in the Software without restriction, including without limitation the rights
[Line 6] Single-line comment:
  // to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
[Line 7] Single-line comment:
  // copies of the Software, and to permit persons to whom the Software is
[Line 8] Single-line comment:
  // furnished to do so, subject to the following conditions:
[Line 9] Single-line comment:
  //
[Line 10] Single-line comment:
  // The above copyright notice and this permission notice shall be included in
[Line 11] Single-line comment:
  // all copies or substantial portions of the Software.
[Line 12] Single-line comment:
  //
[Line 13] Single-line comment:
  // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
[Line 14] Single-line comment:
  // IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
[Line 15] Single-line comment:
  // FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
[Line 16] Single-line comment:
  // SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
[Line 17] Single-line comment:
  // OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
[Line 18] Single-line comment:
  // FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
[Line 19] Single-line comment:
  // IN THE SOFTWARE.
[Line 33] Single-line comment:
  //
[Line 34] Single-line comment:
  // Global state variables
[Line 35] Single-line comment:
  //
[Line 64] Single-line comment:
  // New address
[Line 74] Single-line comment:
  // Services have been added
[Line 90] Single-line comment:
  // If the dialog might get closed before the reply comes back,
[Line 91] Single-line comment:
  // call this in the destructor so it doesn't get called after it's deleted.
[Line 146] Single-line comment:
  // Look for an existing connection
[Line 157] Single-line comment:
  // Connect
[Line 170] Single-line comment:
  /// debug print
[Line 177] Single-line comment:
  /// debug print
[Line 181] Single-line comment:
  // Add node
[Line 193] Single-line comment:
  //// todo: need to set last failed connect time, and increment a failed to connect counter
[Line 194] Single-line comment:
  /// debug print
[Line 207] Single-line comment:
  // All of a nodes broadcasts and subscriptions are automatically torn down
[Line 208] Single-line comment:
  // when it goes down, so a node has to stay up to keep its broadcast going.
[Line 210] Single-line comment:
  // Cancel and delete unsourced broadcasts
[Line 218] Single-line comment:
  // Cancel subscriptions
[Line 263] Single-line comment:
  //
[Line 264] Single-line comment:
  // Disconnect nodes
[Line 265] Single-line comment:
  //
[Line 268] Single-line comment:
  // Disconnect duplicate connections
[Line 275] Single-line comment:
  // In case two nodes connect to each other at once,
[Line 276] Single-line comment:
  // the lower ip disconnects its outbound connection
[Line 297] Single-line comment:
  // Disconnect unused nodes
[Line 303] Single-line comment:
  // remove from vNodes
[Line 307] Single-line comment:
  // hold in disconnected pool until all refs are released
[Line 315] Single-line comment:
  // Delete disconnected nodes
[Line 319] Single-line comment:
  // wait until threads are done using it
[Line 343] Single-line comment:
  //
[Line 344] Single-line comment:
  // Find which sockets have data to receive
[Line 345] Single-line comment:
  //
[Line 348] Single-line comment:
  // frequency to poll pnode->vSend
[Line 388] Single-line comment:
  //// debug
[Line 389] Single-line comment:
  //foreach(CNode* pnode, vNodes)
[Line 390] Single-line comment:
  //{
[Line 391] Single-line comment:
  //    printf("vRecv = %-5d ", pnode->vRecv.size());
[Line 392] Single-line comment:
  //    printf("vSend = %-5d    ", pnode->vSend.size());
[Line 393] Single-line comment:
  //}
[Line 394] Single-line comment:
  //printf("\n");
[Line 397] Single-line comment:
  //
[Line 398] Single-line comment:
  // Accept new connections
[Line 399] Single-line comment:
  //
[Line 423] Single-line comment:
  //
[Line 424] Single-line comment:
  // Service each socket
[Line 425] Single-line comment:
  //
[Line 434] Single-line comment:
  //
[Line 435] Single-line comment:
  // Receive
[Line 436] Single-line comment:
  //
[Line 444] Single-line comment:
  // typical socket buffer is 8K-64K
[Line 451] Single-line comment:
  // socket closed gracefully
[Line 458] Single-line comment:
  // socket error
[Line 470] Single-line comment:
  //
[Line 471] Single-line comment:
  // Send
[Line 472] Single-line comment:
  //
[Line 539] Single-line comment:
  //// number of connections may still need to be increased before release
[Line 540] Single-line comment:
  // Initiate network connections
[Line 543] Single-line comment:
  // Make a list of unique class C's
[Line 557] Single-line comment:
  // Taking advantage of mapAddresses being in sorted order,
[Line 558] Single-line comment:
  // with IPs of the same class C grouped together.
[Line 565] Single-line comment:
  //
[Line 566] Single-line comment:
  // The IP selection process is designed to limit vulnerability to address flooding.
[Line 567] Single-line comment:
  // Any class C (a.b.c.?) has an equal chance of being chosen, then an IP is
[Line 568] Single-line comment:
  // chosen within the class C.  An attacker may be able to allocate many IPs, but
[Line 569] Single-line comment:
  // they would normally be concentrated in blocks of class C's.  They can hog the
[Line 570] Single-line comment:
  // attention within their class C, but not the whole IP address space overall.
[Line 571] Single-line comment:
  // A lone node in a class C will get as much attention as someone holding all 255
[Line 572] Single-line comment:
  // IPs in another class C.
[Line 573] Single-line comment:
  //
[Line 578] Single-line comment:
  // Choose a random class C
[Line 583] Single-line comment:
  // Organize all addresses in the class C by IP
[Line 596] Single-line comment:
  // Choose a random IP in the class C
[Line 601] Single-line comment:
  // Once we've chosen an IP, we'll try every given port before moving on
[Line 612] Single-line comment:
  // Advertise our address
[Line 617] Single-line comment:
  // Get as many addresses as we can
[Line 620] Single-line comment:
  ////// should the one on the receiving end do this too?
[Line 621] Single-line comment:
  // Subscribe our local subscription list
[Line 635] Single-line comment:
  // Wait
[Line 673] Single-line comment:
  // Poll the connected nodes for messages
[Line 681] Single-line comment:
  // Receive messages
[Line 685] Single-line comment:
  // Send messages
[Line 692] Single-line comment:
  // Wait and allow messages to bunch up
[Line 708] Single-line comment:
  //// todo: start one thread per processor, use getenv("NUMBER_OF_PROCESSORS")
[Line 737] Single-line comment:
  // Sockets startup
[Line 747] Single-line comment:
  // Get local host ip
[Line 767] Single-line comment:
  // Create socket for listening for incoming connections
[Line 776] Single-line comment:
  // Set to nonblocking, incomming connections will also inherit this
[Line 785] Single-line comment:
  // The sockaddr_in structure specifies the address family,
[Line 786] Single-line comment:
  // IP address, and port for the socket that is being bound
[Line 804] Single-line comment:
  // Listen for incoming connections
[Line 813] Single-line comment:
  //
[Line 814] Single-line comment:
  // Start threads
[Line 815] Single-line comment:
  //
[Line 849] Single-line comment:
  // Sockets shutdown


================================================================================
STUDY FILES
================================================================================

File: /home/user/bitcoinArchive/study/main.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 12] Single-line comment:
  //
[Line 13] Single-line comment:
  // Global state
[Line 14] Single-line comment:
  //
[Line 48] Single-line comment:
  // Settings
[Line 60] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 61] Single-line comment:
  //
[Line 62] Single-line comment:
  // mapKeys
[Line 63] Single-line comment:
  //
[Line 87] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 88] Single-line comment:
  //
[Line 89] Single-line comment:
  // mapWallet
[Line 90] Single-line comment:
  //
[Line 97] Single-line comment:
  // Inserts only if not already there, returns tx inserted or tx found
[Line 104] Single-line comment:
  //// debug print
[Line 109] Single-line comment:
  // Merge
[Line 136] Single-line comment:
  // Write to disk
[Line 140] Single-line comment:
  // Notify UI
[Line 144] Single-line comment:
  // Refresh UI
[Line 154] Single-line comment:
  // Get merkle branch if transaction was found in a block
[Line 180] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 181] Single-line comment:
  //
[Line 182] Single-line comment:
  // mapOrphanTransactions
[Line 183] Single-line comment:
  //
[Line 226] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 227] Single-line comment:
  //
[Line 228] Single-line comment:
  // CTransaction
[Line 229] Single-line comment:
  //
[Line 267] Single-line comment:
  // If we did not receive the transaction directly, we rely on the block's
[Line 268] Single-line comment:
  // time to figure out when it happened.  We use the median over a range
[Line 269] Single-line comment:
  // of blocks to try to filter out inaccurate block times.
[Line 298] Single-line comment:
  // Load the block this tx is in
[Line 307] Single-line comment:
  // Update the tx's hashBlock
[Line 310] Single-line comment:
  // Locate the transaction
[Line 322] Single-line comment:
  // Fill in merkle branch
[Line 326] Single-line comment:
  // Is the tx in a block that's in the main chain
[Line 350] Single-line comment:
  // This critsect is OK because txdb is already open
[Line 411] Single-line comment:
  // Coinbase is only valid in a block, not as a loose transaction
[Line 418] Single-line comment:
  // Do we already have it?
[Line 427] Single-line comment:
  // Check for conflicts with in-memory transactions
[Line 434] Single-line comment:
  // Allow replacing with a newer version of the same transaction
[Line 450] Single-line comment:
  // Check against previous transactions
[Line 460] Single-line comment:
  // Store transaction in memory
[Line 471] Single-line comment:
  ///// are we sure this is ok when loading transactions or restoring block txes
[Line 472] Single-line comment:
  // If updated, erase old tx from wallet
[Line 483] Single-line comment:
  // Add to memory pool without checking anything.  Don't call this directly,
[Line 484] Single-line comment:
  // call AcceptTransaction to properly check the transaction first.
[Line 499] Single-line comment:
  // Remove transaction from memory pool
[Line 520] Single-line comment:
  // Find the block it claims to be in
[Line 528] Single-line comment:
  // Make sure the merkle branch connects to this block
[Line 585] Single-line comment:
  // Reaccept any txes of ours that aren't already in a block
[Line 628] Single-line comment:
  // Rebroadcast any of our txes that aren't in a block yet
[Line 633] Single-line comment:
  // Sort them in chronological order
[Line 657] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 658] Single-line comment:
  //
[Line 659] Single-line comment:
  // CBlock and CBlockIndex
[Line 660] Single-line comment:
  //
[Line 669] Single-line comment:
  // Work back to the first block in the orphan chain
[Line 679] Single-line comment:
  // Subsidy is cut in half every 4 years
[Line 687] Single-line comment:
  // two weeks
[Line 691] Single-line comment:
  // Genesis block
[Line 695] Single-line comment:
  // Only change once per interval
[Line 699] Single-line comment:
  // Go back by what we want to be 14 days worth of blocks
[Line 705] Single-line comment:
  // Limit adjustment step
[Line 713] Single-line comment:
  // Retarget
[Line 722] Single-line comment:
  /// debug print
[Line 741] Single-line comment:
  // Relinquish previous transactions' spent pointers
[Line 748] Single-line comment:
  // Get prev txindex from disk
[Line 756] Single-line comment:
  // Mark outpoint as not spent
[Line 759] Single-line comment:
  // Write back
[Line 764] Single-line comment:
  // Remove transaction from index
[Line 774] Single-line comment:
  // Take over previous transactions' spent pointers
[Line 782] Single-line comment:
  // Read txindex
[Line 787] Single-line comment:
  // Get txindex from current proposed changes
[Line 792] Single-line comment:
  // Read txindex from txdb
[Line 798] Single-line comment:
  // Read txPrev
[Line 802] Single-line comment:
  // Get prev tx from single transactions in memory
[Line 814] Single-line comment:
  // Get prev tx from disk
[Line 822] Single-line comment:
  // If prev is coinbase, check that it's matured
[Line 828] Single-line comment:
  // Verify signature
[Line 832] Single-line comment:
  // Check for conflicts
[Line 836] Single-line comment:
  // Mark outpoints as spent
[Line 839] Single-line comment:
  // Write back
[Line 848] Single-line comment:
  // Tally transaction fees
[Line 859] Single-line comment:
  // Add transaction to disk index
[Line 865] Single-line comment:
  // Add transaction to test pool
[Line 878] Single-line comment:
  // Take over previous transactions' spent pointers
[Line 884] Single-line comment:
  // Get prev tx from single transactions in memory
[Line 893] Single-line comment:
  // Verify signature
[Line 897] Single-line comment:
  ///// this is redundant with the mapNextTx stuff, not sure which I want to get rid of
[Line 898] Single-line comment:
  ///// this has to go away now that posNext is gone
[Line 899] Single-line comment:
  // // Check for conflicts
[Line 900] Single-line comment:
  // if (!txPrev.vout[prevout.n].posNext.IsNull())
[Line 901] Single-line comment:
  //     return error("ConnectInputs() : prev tx already used");
[Line 902] Single-line comment:
  //
[Line 903] Single-line comment:
  // // Flag outpoints as used
[Line 904] Single-line comment:
  // txPrev.vout[prevout.n].posNext = posThisTx;
[Line 920] Single-line comment:
  // Disconnect in reverse order
[Line 925] Single-line comment:
  // Update block index on disk without changing it in memory.
[Line 926] Single-line comment:
  // The memory index structure will be changed after the db commits.
[Line 939] Single-line comment:
  //// issue here: it doesn't know the version
[Line 956] Single-line comment:
  // Update block index on disk without changing it in memory.
[Line 957] Single-line comment:
  // The memory index structure will be changed after the db commits.
[Line 965] Single-line comment:
  // Watch for transactions paying to me
[Line 978] Single-line comment:
  // Find the fork
[Line 990] Single-line comment:
  // List of what to disconnect
[Line 995] Single-line comment:
  // List of what to connect
[Line 1001] Single-line comment:
  // Disconnect shorter branch
[Line 1011] Single-line comment:
  // Queue memory transactions to resurrect
[Line 1017] Single-line comment:
  // Connect longer branch
[Line 1027] Single-line comment:
  // Invalid block, delete the rest of this branch
[Line 1040] Single-line comment:
  // Queue memory transactions to delete
[Line 1047] Single-line comment:
  // Commit now because resurrecting could take some time
[Line 1050] Single-line comment:
  // Disconnect shorter branch
[Line 1055] Single-line comment:
  // Connect longer branch
[Line 1060] Single-line comment:
  // Resurrect memory transactions that were in the disconnected branch
[Line 1064] Single-line comment:
  // Delete redundant memory transactions that are in the connected branch
[Line 1074] Single-line comment:
  // Check for duplicate
[Line 1079] Single-line comment:
  // Construct new block index object
[Line 1096] Single-line comment:
  // New best
[Line 1106] Single-line comment:
  // Adding to current best branch
[Line 1118] Single-line comment:
  // Delete redundant memory transactions
[Line 1124] Single-line comment:
  // New best branch
[Line 1132] Single-line comment:
  // New best link
[Line 1143] Single-line comment:
  // Relay wallet transactions that haven't gotten in yet
[Line 1156] Single-line comment:
  // These are checks that are independent of context
[Line 1157] Single-line comment:
  // that can be verified before saving an orphan block.
[Line 1159] Single-line comment:
  // Size limits
[Line 1163] Single-line comment:
  // Check timestamp
[Line 1167] Single-line comment:
  // First transaction must be coinbase, the rest must not be
[Line 1174] Single-line comment:
  // Check transactions
[Line 1179] Single-line comment:
  // Check proof of work matches claimed amount
[Line 1185] Single-line comment:
  // Check merkleroot
[Line 1194] Single-line comment:
  // Check for duplicate
[Line 1199] Single-line comment:
  // Get prev block index
[Line 1205] Single-line comment:
  // Check timestamp against prev
[Line 1209] Single-line comment:
  // Check proof of work
[Line 1213] Single-line comment:
  // Write block to history file
[Line 1224] Single-line comment:
  // // Add atoms to user reviews for coins created
[Line 1225] Single-line comment:
  // vector<unsigned char> vchPubKey;
[Line 1226] Single-line comment:
  // if (ExtractPubKey(vtx[0].vout[0].scriptPubKey, false, vchPubKey))
[Line 1227] Single-line comment:
  // {
[Line 1228] Single-line comment:
  //     unsigned short nAtom = GetRand(USHRT_MAX - 100) + 100;
[Line 1229] Single-line comment:
  //     vector<unsigned short> vAtoms(1, nAtom);
[Line 1230] Single-line comment:
  //     AddAtomsAndPropagate(Hash(vchPubKey.begin(), vchPubKey.end()), vAtoms, true);
[Line 1231] Single-line comment:
  // }
[Line 1238] Single-line comment:
  // Check for duplicate
[Line 1245] Single-line comment:
  // Preliminary checks
[Line 1252] Single-line comment:
  // If don't already have its previous block, shunt it off to holding area until we get it
[Line 1259] Single-line comment:
  // Ask this guy to fill in what we're missing
[Line 1265] Single-line comment:
  // Store to disk
[Line 1273] Single-line comment:
  // Recursively process any orphan blocks that depended on this one
[Line 1306] Single-line comment:
  // Scan ahead to the next pchMessageStart, which should normally be immediately
[Line 1307] Single-line comment:
  // at the file pointer.  Leaves file pointer at end of pchMessageStart.
[Line 1409] Single-line comment:
  // FAT32 filesize max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
[Line 1422] Single-line comment:
  //
[Line 1423] Single-line comment:
  // Load block index
[Line 1424] Single-line comment:
  //
[Line 1430] Single-line comment:
  //
[Line 1431] Single-line comment:
  // Init with genesis block
[Line 1432] Single-line comment:
  //
[Line 1439] Single-line comment:
  // Genesis Block:
[Line 1440] Single-line comment:
  // GetHash()      = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
[Line 1441] Single-line comment:
  // hashMerkleRoot = 0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
[Line 1442] Single-line comment:
  // txNew.vin[0].scriptSig     = 486604799 4 0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854
[Line 1443] Single-line comment:
  // txNew.vout[0].nValue       = 5000000000
[Line 1444] Single-line comment:
  // txNew.vout[0].scriptPubKey = 0x5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704 OP_CHECKSIG
[Line 1445] Single-line comment:
  // block.nVersion = 1
[Line 1446] Single-line comment:
  // block.nTime    = 1231006505
[Line 1447] Single-line comment:
  // block.nBits    = 0x1d00ffff
[Line 1448] Single-line comment:
  // block.nNonce   = 2083236893
[Line 1449] Single-line comment:
  // CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
[Line 1450] Single-line comment:
  //   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
[Line 1451] Single-line comment:
  //     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
[Line 1452] Single-line comment:
  //     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
[Line 1453] Single-line comment:
  //   vMerkleTree: 4a5e1e
[Line 1455] Single-line comment:
  // Genesis block
[Line 1472] Single-line comment:
  //// debug print, delete this later
[Line 1482] Single-line comment:
  // Start new block file
[Line 1498] Single-line comment:
  // precompute tree structure
[Line 1504] Single-line comment:
  // test
[Line 1505] Single-line comment:
  //while (rand() % 3 == 0)
[Line 1506] Single-line comment:
  //    mapNext[pindex->pprev].push_back(pindex);
[Line 1519] Single-line comment:
  // print split or gap
[Line 1534] Single-line comment:
  // print columns
[Line 1538] Single-line comment:
  // print item
[Line 1560] Single-line comment:
  // put the main timechain first
[Line 1571] Single-line comment:
  // iterate children
[Line 1586] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 1587] Single-line comment:
  //
[Line 1588] Single-line comment:
  // Messages
[Line 1589] Single-line comment:
  //
[Line 1601] Single-line comment:
  // Don't know what it is, just say we already got one
[Line 1618] Single-line comment:
  //
[Line 1619] Single-line comment:
  // Message format
[Line 1620] Single-line comment:
  //  (4) message start
[Line 1621] Single-line comment:
  //  (12) command
[Line 1622] Single-line comment:
  //  (4) size
[Line 1623] Single-line comment:
  //  (x) data
[Line 1624] Single-line comment:
  //
[Line 1628] Single-line comment:
  // Scan for message start
[Line 1643] Single-line comment:
  // Read header
[Line 1653] Single-line comment:
  // Message size
[Line 1657] Single-line comment:
  // Rewind and wait for rest of message
[Line 1658] Single-line comment:
  ///// need a mechanism to give up waiting for overlong message size error
[Line 1665] Single-line comment:
  // Copy message to its own buffer
[Line 1669] Single-line comment:
  // Process message
[Line 1707] Single-line comment:
  // Can only do this once
[Line 1729] Single-line comment:
  // Ask the first connected node for block updates
[Line 1743] Single-line comment:
  // Must have a version message before anything else
[Line 1753] Single-line comment:
  // Store the new addresses
[Line 1761] Single-line comment:
  // Put on lists to send to other nodes
[Line 1808] Single-line comment:
  // Send block from disk
[Line 1812] Single-line comment:
  //// could optimize this to send header straight from blockindex for client
[Line 1820] Single-line comment:
  // Send stream from relay memory
[Line 1838] Single-line comment:
  // Find the first block the caller has in the main chain
[Line 1841] Single-line comment:
  // Send the rest of the chain
[Line 1853] Single-line comment:
  // Bypass setInventoryKnown in case an inventory message got lost
[Line 1857] Single-line comment:
  // returns true if wasn't already contained in the set
[Line 1886] Single-line comment:
  // Recursively process any orphan transactions that depended on this one
[Line 1932] Single-line comment:
  // Relay the original message as-is in case it's a higher version than we know how to parse
[Line 1944] Single-line comment:
  //// debug print
[Line 1958] Single-line comment:
  //// need to expand the time range if not enough found
[Line 1959] Single-line comment:
  // in the last hour
[Line 1980] Single-line comment:
  /// we have a chance to check the order here
[Line 1982] Single-line comment:
  // Keep giving the same key to the same ip until they use it
[Line 1986] Single-line comment:
  // Send back approval of order and pubkey to use
[Line 1999] Single-line comment:
  // Broadcast
[Line 2010] Single-line comment:
  // Send back confirmation
[Line 2037] Single-line comment:
  // Ignore unknown commands for extensibility
[Line 2061] Single-line comment:
  // Don't send anything until we get their version message
[Line 2066] Single-line comment:
  //
[Line 2067] Single-line comment:
  // Message: addr
[Line 2068] Single-line comment:
  //
[Line 2079] Single-line comment:
  //
[Line 2080] Single-line comment:
  // Message: inventory
[Line 2081] Single-line comment:
  //
[Line 2088] Single-line comment:
  // returns true if wasn't already contained in the set
[Line 2099] Single-line comment:
  //
[Line 2100] Single-line comment:
  // Message: getdata
[Line 2101] Single-line comment:
  //
[Line 2133] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 2134] Single-line comment:
  //
[Line 2135] Single-line comment:
  // BitcoinMiner
[Line 2136] Single-line comment:
  //
[Line 2206] Single-line comment:
  //
[Line 2207] Single-line comment:
  // Create coinbase tx
[Line 2208] Single-line comment:
  //
[Line 2217] Single-line comment:
  //
[Line 2218] Single-line comment:
  // Create new block
[Line 2219] Single-line comment:
  //
[Line 2224] Single-line comment:
  // Add our coinbase tx as first transaction
[Line 2227] Single-line comment:
  // Collect the latest transactions into the block
[Line 2249] Single-line comment:
  // Transaction fee requirements, mainly only needed for flood control
[Line 2250] Single-line comment:
  // Under 10K (about 80 inputs) is free for first 100 transactions
[Line 2251] Single-line comment:
  // Base rate is 0.01 per KB
[Line 2271] Single-line comment:
  //
[Line 2272] Single-line comment:
  // Prebuild hash buffer
[Line 2273] Single-line comment:
  //
[Line 2303] Single-line comment:
  //
[Line 2304] Single-line comment:
  // Search
[Line 2305] Single-line comment:
  //
[Line 2320] Single-line comment:
  //// debug print
[Line 2328] Single-line comment:
  // Save key
[Line 2333] Single-line comment:
  // Process this block the same as if we had received it from another node
[Line 2343] Single-line comment:
  // Update nTime every few seconds
[Line 2380] Single-line comment:
  //////////////////////////////////////////////////////////////////////////////
[Line 2381] Single-line comment:
  //
[Line 2382] Single-line comment:
  // Actions
[Line 2383] Single-line comment:
  //
[Line 2404] Single-line comment:
  ///printf(" GetBalance() time = %16I64d\n", nEnd - nStart);
[Line 2414] Single-line comment:
  // List of values less than target
[Line 2456] Single-line comment:
  // Solve subset sum by stochastic approximation
[Line 2491] Single-line comment:
  // If the next larger is still closer, return it
[Line 2500] Single-line comment:
  //// debug print
[Line 2519] Single-line comment:
  // txdb must be opened before the mapWallet lock
[Line 2533] Single-line comment:
  // Choose coins to use
[Line 2541] Single-line comment:
  // Fill vout[0] to the payee
[Line 2544] Single-line comment:
  // Fill vout[1] back to self with any change
[Line 2547] Single-line comment:
  // Use the same key as one of the coins
[Line 2557] Single-line comment:
  // Fill vout[1] to ourself
[Line 2563] Single-line comment:
  // Fill vin
[Line 2569] Single-line comment:
  // Sign
[Line 2576] Single-line comment:
  // Check that enough fee is included
[Line 2583] Single-line comment:
  // Fill vtxPrev by copying from previous transactions vtxPrev
[Line 2594] Single-line comment:
  // Call after CreateTransaction unless you want to abort
[Line 2600] Single-line comment:
  //// todo: make this transactional, never want to add a transaction
[Line 2601] Single-line comment:
  ////  without marking spent transactions
[Line 2603] Single-line comment:
  // Add tx to wallet, because if it has change it's also ours,
[Line 2604] Single-line comment:
  // otherwise just for transaction history.
[Line 2607] Single-line comment:
  // Mark old coins as spent
[Line 2648] Single-line comment:
  // Broadcast
[Line 2651] Single-line comment:
  // This must not fail. The transaction has already been signed and recorded.

File: /home/user/bitcoinArchive/study/db.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 12] Single-line comment:
  //
[Line 13] Single-line comment:
  // CDB
[Line 14] Single-line comment:
  //
[Line 68] Single-line comment:
  /// debug
[Line 69] Single-line comment:
  ///dbenv.log_set_config(DB_LOG_AUTO_REMOVE, 1); /// causes corruption
[Line 91] Single-line comment:
  // Txn pointer
[Line 92] Single-line comment:
  // Filename
[Line 93] Single-line comment:
  // Logical db name
[Line 94] Single-line comment:
  // Database type
[Line 95] Single-line comment:
  // Flags
[Line 134] Single-line comment:
  // Flush log data to the actual data file
[Line 135] Single-line comment:
  //  on all files that are not in use
[Line 169] Single-line comment:
  //
[Line 170] Single-line comment:
  // CTxDB
[Line 171] Single-line comment:
  //
[Line 190] Single-line comment:
  // Add to tx index
[Line 215] Single-line comment:
  // Get cursor
[Line 223] Single-line comment:
  // Read next record
[Line 235] Single-line comment:
  // Unserialize
[Line 243] Single-line comment:
  // Read transaction
[Line 307] Single-line comment:
  // Return existing
[Line 312] Single-line comment:
  // Create new
[Line 324] Single-line comment:
  // Get cursor
[Line 332] Single-line comment:
  // Read next record
[Line 344] Single-line comment:
  // Unserialize
[Line 352] Single-line comment:
  // Construct block index object
[Line 365] Single-line comment:
  // Watch for genesis block and best block
[Line 395] Single-line comment:
  //
[Line 396] Single-line comment:
  // CAddrDB
[Line 397] Single-line comment:
  //
[Line 408] Single-line comment:
  // Load user provided addresses
[Line 425] Single-line comment:
  // Get cursor
[Line 432] Single-line comment:
  // Read next record
[Line 441] Single-line comment:
  // Unserialize
[Line 452] Single-line comment:
  //// debug print
[Line 470] Single-line comment:
  //
[Line 471] Single-line comment:
  // CReviewDB
[Line 472] Single-line comment:
  //
[Line 476] Single-line comment:
  // msvc workaround, just need to do anything with vReviews
[Line 491] Single-line comment:
  //
[Line 492] Single-line comment:
  // CWalletDB
[Line 493] Single-line comment:
  //
[Line 499] Single-line comment:
  //// todo: shouldn't we catch exceptions and try to recover and continue?
[Line 503] Single-line comment:
  // Get cursor
[Line 510] Single-line comment:
  // Read next record
[Line 519] Single-line comment:
  // Unserialize
[Line 520] Single-line comment:
  // Taking advantage of the fact that pair serialization
[Line 521] Single-line comment:
  // is just the two items serialized one after the other
[Line 540] Single-line comment:
  //// debug print
[Line 541] Single-line comment:
  //printf("LoadWallet  %s\n", wtx.GetHash().ToString().c_str());
[Line 542] Single-line comment:
  //printf(" %12I64d  %s  %s  %s\n",
[Line 543] Single-line comment:
  //    wtx.vout[0].nValue,
[Line 544] Single-line comment:
  //    DateTimeStr(wtx.nTime).c_str(),
[Line 545] Single-line comment:
  //    wtx.hashBlock.ToString().substr(0,14).c_str(),
[Line 546] Single-line comment:
  //    wtx.mapValue["message"].c_str());
[Line 562] Single-line comment:
  /// or settings or option or options or config?
[Line 588] Single-line comment:
  // Set keyUser
[Line 594] Single-line comment:
  // Create new keyUser and set as default key

File: /home/user/bitcoinArchive/study/irc.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 82] Single-line comment:
  // socket closed
[Line 88] Single-line comment:
  // socket error
[Line 204] Single-line comment:
  // index 7 is limited to 16 characters
[Line 205] Single-line comment:
  // could get full length name at index 10, but would be different from join messages
[Line 212] Single-line comment:
  // :username!username@50000007.F000000B.90000002.IP JOIN :#channelname

File: /home/user/bitcoinArchive/study/script.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 28] Single-line comment:
  // Lengthen the shorter one
[Line 37] Single-line comment:
  //
[Line 38] Single-line comment:
  // Script is a stack machine (like Forth) that evaluates a predicate
[Line 39] Single-line comment:
  // returning a bool indicating valid or not.  There are no loops.
[Line 40] Single-line comment:
  //
[Line 62] Single-line comment:
  //
[Line 63] Single-line comment:
  // Read instruction
[Line 64] Single-line comment:
  //
[Line 75] Single-line comment:
  //
[Line 76] Single-line comment:
  // Push value
[Line 77] Single-line comment:
  //
[Line 96] Single-line comment:
  // ( -- value)
[Line 103] Single-line comment:
  //
[Line 104] Single-line comment:
  // Control
[Line 105] Single-line comment:
  //
[Line 121] Single-line comment:
  // <expression> if [statements] [else [statements]] endif
[Line 158] Single-line comment:
  // (true -- ) or
[Line 159] Single-line comment:
  // (false -- false) and return
[Line 177] Single-line comment:
  //
[Line 178] Single-line comment:
  // Stack ops
[Line 179] Single-line comment:
  //
[Line 200] Single-line comment:
  // (x1 x2 -- )
[Line 208] Single-line comment:
  // (x1 x2 -- x1 x2 x1 x2)
[Line 220] Single-line comment:
  // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
[Line 234] Single-line comment:
  // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
[Line 246] Single-line comment:
  // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
[Line 259] Single-line comment:
  // (x1 x2 x3 x4 -- x3 x4 x1 x2)
[Line 269] Single-line comment:
  // (x - 0 | x x)
[Line 280] Single-line comment:
  // -- stacksize
[Line 288] Single-line comment:
  // (x -- )
[Line 297] Single-line comment:
  // (x -- x x)
[Line 307] Single-line comment:
  // (x1 x2 -- x2)
[Line 316] Single-line comment:
  // (x1 x2 -- x1 x2 x1)
[Line 327] Single-line comment:
  // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
[Line 328] Single-line comment:
  // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
[Line 344] Single-line comment:
  // (x1 x2 x3 -- x2 x3 x1)
[Line 345] Single-line comment:
  //  x2 x1 x3  after first swap
[Line 346] Single-line comment:
  //  x2 x3 x1  after second swap
[Line 356] Single-line comment:
  // (x1 x2 -- x2 x1)
[Line 365] Single-line comment:
  // (x1 x2 -- x2 x1 x2)
[Line 374] Single-line comment:
  //
[Line 375] Single-line comment:
  // Splice ops
[Line 376] Single-line comment:
  //
[Line 379] Single-line comment:
  // (x1 x2 -- out)
[Line 391] Single-line comment:
  // (in begin size -- out)
[Line 413] Single-line comment:
  // (in size -- out)
[Line 432] Single-line comment:
  // (in -- in size)
[Line 441] Single-line comment:
  //
[Line 442] Single-line comment:
  // Bitwise logic
[Line 443] Single-line comment:
  //
[Line 446] Single-line comment:
  // (in - out)
[Line 459] Single-line comment:
  // (x1 x2 - out)
[Line 486] Single-line comment:
  //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
[Line 488] Single-line comment:
  // (x1 x2 - bool)
[Line 494] Single-line comment:
  // OP_NOTEQUAL is disabled because it would be too easy to say
[Line 495] Single-line comment:
  // something like n != 1 and have some wiseguy pass in 1 with extra
[Line 496] Single-line comment:
  // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
[Line 497] Single-line comment:
  //if (opcode == OP_NOTEQUAL)
[Line 498] Single-line comment:
  //    fEqual = !fEqual;
[Line 513] Single-line comment:
  //
[Line 514] Single-line comment:
  // Numeric
[Line 515] Single-line comment:
  //
[Line 525] Single-line comment:
  // (in -- out)
[Line 564] Single-line comment:
  // (x1 x2 -- out)
[Line 635] Single-line comment:
  // (x min max -- out)
[Line 650] Single-line comment:
  //
[Line 651] Single-line comment:
  // Crypto
[Line 652] Single-line comment:
  //
[Line 659] Single-line comment:
  // (in -- hash)
[Line 687] Single-line comment:
  // Hash starts after the code separator
[Line 695] Single-line comment:
  // (sig pubkey -- bool)
[Line 702] Single-line comment:
  ////// debug print
[Line 703] Single-line comment:
  //PrintHex(vchSig.begin(), vchSig.end(), "sig: %s\n");
[Line 704] Single-line comment:
  //PrintHex(vchPubKey.begin(), vchPubKey.end(), "pubkey: %s\n");
[Line 706] Single-line comment:
  // Subset of script starting at the most recent codeseparator
[Line 709] Single-line comment:
  // Drop the signature, since there's no way for a signature to sign itself
[Line 730] Single-line comment:
  // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)
[Line 752] Single-line comment:
  // Subset of script starting at the most recent codeseparator
[Line 755] Single-line comment:
  // Drop the signatures, since there's no way for a signature to sign itself
[Line 768] Single-line comment:
  // Check signature
[Line 777] Single-line comment:
  // If there are more signatures left than keys left,
[Line 778] Single-line comment:
  // then too many signatures have failed
[Line 827] Single-line comment:
  // In case concatenating two scripts ends up with two codeseparators,
[Line 828] Single-line comment:
  // or an extra one at the end, this prevents all those possible incompatibilities.
[Line 831] Single-line comment:
  // Blank out other inputs' signatures
[Line 836] Single-line comment:
  // Blank out some of the outputs
[Line 839] Single-line comment:
  // Wildcard payee
[Line 842] Single-line comment:
  // Let the others update at will
[Line 849] Single-line comment:
  // Only lockin the txout payee at same index as txin
[Line 860] Single-line comment:
  // Let the others update at will
[Line 866] Single-line comment:
  // Blank out other inputs completely, not recommended for open transactions
[Line 873] Single-line comment:
  // Serialize and hash
[Line 888] Single-line comment:
  // Hash type is one byte tacked on to the end of the signature
[Line 915] Single-line comment:
  // Templates
[Line 919] Single-line comment:
  // Standard tx, sender provides pubkey, receiver adds signature
[Line 922] Single-line comment:
  // Short account number tx, sender provides hash of pubkey, receiver provides signature and pubkey
[Line 926] Single-line comment:
  // Scan templates
[Line 934] Single-line comment:
  // Compare
[Line 943] Single-line comment:
  // Success
[Line 983] Single-line comment:
  // Compile solution
[Line 990] Single-line comment:
  // Sign
[Line 1005] Single-line comment:
  // Sign and give pubkey
[Line 1097] Single-line comment:
  // Leave out the signature from the hash, since a signature can't sign itself.
[Line 1098] Single-line comment:
  // The checksig op will also drop the signatures from its hash.
[Line 1106] Single-line comment:
  // Test solution

File: /home/user/bitcoinArchive/study/sha.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // This file is public domain
[Line 2] Single-line comment:
  // SHA routines extracted as a standalone file from:
[Line 3] Single-line comment:
  // Crypto++: a C++ Class Library of Cryptographic Schemes
[Line 4] Single-line comment:
  // Version 5.5.2 (9/24/2007)
[Line 5] Single-line comment:
  // http://www.cryptopp.com
[Line 7] Single-line comment:
  // sha.cpp - modified by Wei Dai from Steve Reid's public domain sha1.c
[Line 9] Single-line comment:
  // Steve Reid implemented SHA-1. Wei Dai implemented SHA-2.
[Line 10] Single-line comment:
  // Both are in the public domain.
[Line 19] Single-line comment:
  // start of Steve Reid's code
[Lines 38-38] Multi-line comment:
  /* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
[Lines 48-48] Multi-line comment:
      /* Copy context->state[] to working vars */
[Lines 54-54] Multi-line comment:
      /* 4 rounds of 20 operations each. Loop unrolled. */
[Lines 75-75] Multi-line comment:
      /* Add the working vars back into context.state[] */
[Line 83] Single-line comment:
  // end of Steve Reid's code
[Line 85] Single-line comment:
  // *************************************************************
[Line 135] Single-line comment:
  // for SHA256
[Lines 145-145] Multi-line comment:
      /* Copy context->state[] to working vars */
[Lines 147-147] Multi-line comment:
      /* 64 operations, partially loop unrolled */
[Lines 155-155] Multi-line comment:
      /* Add the working vars back into context.state[] */
[Lines 166-239] Multi-line comment:
  /*
  // smaller but slower
  void SHA256_Transform(word32 *state, const word32 *data)
  {
      word32 T[20];
      word32 W[32];
      unsigned int i = 0, j = 0;
      word32 *t = T+8;
  
      memcpy(t, state, 8*4);
      word32 e = t[4], a = t[0];
  
      do
      {
          word32 w = data[j];
          W[j] = w;
          w += K[j];
          w += t[7];
          w += S1(e);
          w += Ch(e, t[5], t[6]);
          e = t[3] + w;
          t[3] = t[3+8] = e;
          w += S0(t[0]);
          a = w + Maj(a, t[1], t[2]);
          t[-1] = t[7] = a;
          --t;
          ++j;
          if (j%8 == 0)
              t += 8;
      } while (j<16);
  
      do
      {
          i = j&0xf;
          word32 w = s1(W[i+16-2]) + s0(W[i+16-15]) + W[i] + W[i+16-7];
          W[i+16] = W[i] = w;
          w += K[j];
          w += t[7];
          w += S1(e);
          w += Ch(e, t[5], t[6]);
          e = t[3] + w;
          t[3] = t[3+8] = e;
          w += S0(t[0]);
          a = w + Maj(a, t[1], t[2]);
          t[-1] = t[7] = a;
  
          w = s1(W[(i+1)+16-2]) + s0(W[(i+1)+16-15]) + W[(i+1)] + W[(i+1)+16-7];
          W[(i+1)+16] = W[(i+1)] = w;
          w += K[j+1];
          w += (t-1)[7];
          w += S1(e);
          w += Ch(e, (t-1)[5], (t-1)[6]);
          e = (t-1)[3] + w;
          (t-1)[3] = (t-1)[3+8] = e;
          w += S0((t-1)[0]);
          a = w + Maj(a, (t-1)[1], (t-1)[2]);
          (t-1)[-1] = (t-1)[7] = a;
  
          t-=2;
          j+=2;
          if (j%8 == 0)
              t += 8;
      } while (j<64);
  
      state[0] += a;
      state[1] += t[1];
      state[2] += t[2];
      state[3] += t[3];
      state[4] += e;
      state[5] += t[5];
      state[6] += t[6];
      state[7] += t[7];
  }
  */
[Line 247] Single-line comment:
  // *************************************************************
[Line 315] Single-line comment:
  // put assembly version in separate function, otherwise MSVC 2005 SP1 doesn't generate correct code for the non-assembly version
[Line 333] Single-line comment:
  // 17*16 for expanded data, 20*8 for state
[Line 336] Single-line comment:
  // start at middle of state buffer. will decrement pointer each round to avoid copying
[Line 337] Single-line comment:
  // 16-byte alignment, then add 8
[Line 399] Single-line comment:
  // k + w is in mm0, a is in mm4, e is in mm5
[Line 400] Single-line comment:
  // h
[Line 401] Single-line comment:
  // f
[Line 402] Single-line comment:
  // g
[Line 407] Single-line comment:
  // h += Ch(e,f,g)
[Line 408] Single-line comment:
  // h += S1(e)
[Line 409] Single-line comment:
  // b
[Line 412] Single-line comment:
  // c
[Line 415] Single-line comment:
  // temp = h + Maj(a,b,c)
[Line 416] Single-line comment:
  // e = d + h
[Line 419] Single-line comment:
  // S0(a)
[Line 420] Single-line comment:
  // a = temp + S0(a)
[Line 425] Single-line comment:
  // first 16 rounds
[Line 440] Single-line comment:
  // rest of the rounds
[Line 443] Single-line comment:
  // data expansion, W[i-2] already in xmm0
[Line 458] Single-line comment:
  // 2 rounds
[Line 464] Single-line comment:
  // update indices and loop
[Line 470] Single-line comment:
  // do housekeeping every 8 rounds
[Line 509] Single-line comment:
  // #if CRYPTOPP_BOOL_SSE2_ASM_AVAILABLE
[Lines 531-531] Multi-line comment:
      /* Copy context->state[] to working vars */
[Lines 533-533] Multi-line comment:
      /* 80 operations, partially loop unrolled */
[Lines 541-541] Multi-line comment:
      /* Add the working vars back into context.state[] */

File: /home/user/bitcoinArchive/study/net.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 17] Single-line comment:
  //
[Line 18] Single-line comment:
  // Global state variables
[Line 19] Single-line comment:
  //
[Line 94] Single-line comment:
  // whatismyip.com 198-200
[Line 147] Single-line comment:
  // New address
[Line 157] Single-line comment:
  // Services have been added
[Line 173] Single-line comment:
  // If the dialog might get closed before the reply comes back,
[Line 174] Single-line comment:
  // call this in the destructor so it doesn't get called after it's deleted.
[Line 200] Single-line comment:
  //
[Line 201] Single-line comment:
  // Subscription methods for the broadcast and subscription system.
[Line 202] Single-line comment:
  // Channel numbers are message numbers, i.e. MSG_TABLE and MSG_PRODUCT.
[Line 203] Single-line comment:
  //
[Line 204] Single-line comment:
  // The subscription system uses a meet-in-the-middle strategy.
[Line 205] Single-line comment:
  // With 100,000 nodes, if senders broadcast to 1000 random nodes and receivers
[Line 206] Single-line comment:
  // subscribe to 1000 random nodes, 99.995% (1 - 0.99^1000) of messages will get through.
[Line 207] Single-line comment:
  //
[Line 234] Single-line comment:
  // Relay subscribe
[Line 249] Single-line comment:
  // Prevent from relaying cancel if wasn't subscribed
[Line 256] Single-line comment:
  // Relay subscription cancel
[Line 262] Single-line comment:
  // Clear memory, no longer subscribed
[Line 304] Single-line comment:
  // Look for an existing connection
[Line 315] Single-line comment:
  /// debug print
[Line 318] Single-line comment:
  // Connect
[Line 322] Single-line comment:
  /// debug print
[Line 325] Single-line comment:
  // Add node
[Line 352] Single-line comment:
  // All of a nodes broadcasts and subscriptions are automatically torn down
[Line 353] Single-line comment:
  // when it goes down, so a node has to stay up to keep its broadcast going.
[Line 359] Single-line comment:
  // Cancel subscriptions
[Line 404] Single-line comment:
  //
[Line 405] Single-line comment:
  // Disconnect nodes
[Line 406] Single-line comment:
  //
[Line 409] Single-line comment:
  // Disconnect duplicate connections
[Line 418] Single-line comment:
  // In case two nodes connect to each other at once,
[Line 419] Single-line comment:
  // the lower ip disconnects its outbound connection
[Line 440] Single-line comment:
  // Disconnect unused nodes
[Line 446] Single-line comment:
  // remove from vNodes
[Line 450] Single-line comment:
  // hold in disconnected pool until all refs are released
[Line 458] Single-line comment:
  // Delete disconnected nodes
[Line 462] Single-line comment:
  // wait until threads are done using it
[Line 486] Single-line comment:
  //
[Line 487] Single-line comment:
  // Find which sockets have data to receive
[Line 488] Single-line comment:
  //
[Line 491] Single-line comment:
  // frequency to poll pnode->vSend
[Line 529] Single-line comment:
  //// debug print
[Line 530] Single-line comment:
  //foreach(CNode* pnode, vNodes)
[Line 531] Single-line comment:
  //{
[Line 532] Single-line comment:
  //    printf("vRecv = %-5d ", pnode->vRecv.size());
[Line 533] Single-line comment:
  //    printf("vSend = %-5d    ", pnode->vSend.size());
[Line 534] Single-line comment:
  //}
[Line 535] Single-line comment:
  //printf("\n");
[Line 538] Single-line comment:
  //
[Line 539] Single-line comment:
  // Accept new connections
[Line 540] Single-line comment:
  //
[Line 563] Single-line comment:
  //
[Line 564] Single-line comment:
  // Service each socket
[Line 565] Single-line comment:
  //
[Line 574] Single-line comment:
  //
[Line 575] Single-line comment:
  // Receive
[Line 576] Single-line comment:
  //
[Line 584] Single-line comment:
  // typical socket buffer is 8K-64K
[Line 591] Single-line comment:
  // socket closed gracefully
[Line 598] Single-line comment:
  // socket error
[Line 610] Single-line comment:
  //
[Line 611] Single-line comment:
  // Send
[Line 612] Single-line comment:
  //
[Line 677] Single-line comment:
  // Initiate network connections
[Line 681] Single-line comment:
  // Wait
[Line 693] Single-line comment:
  // Make a list of unique class C's
[Line 707] Single-line comment:
  // Taking advantage of mapAddresses being in sorted order,
[Line 708] Single-line comment:
  // with IPs of the same class C grouped together.
[Line 715] Single-line comment:
  //
[Line 716] Single-line comment:
  // The IP selection process is designed to limit vulnerability to address flooding.
[Line 717] Single-line comment:
  // Any class C (a.b.c.?) has an equal chance of being chosen, then an IP is
[Line 718] Single-line comment:
  // chosen within the class C.  An attacker may be able to allocate many IPs, but
[Line 719] Single-line comment:
  // they would normally be concentrated in blocks of class C's.  They can hog the
[Line 720] Single-line comment:
  // attention within their class C, but not the whole IP address space overall.
[Line 721] Single-line comment:
  // A lone node in a class C will get as much attention as someone holding all 255
[Line 722] Single-line comment:
  // IPs in another class C.
[Line 723] Single-line comment:
  //
[Line 728] Single-line comment:
  // Choose a random class C
[Line 731] Single-line comment:
  // Organize all addresses in the class C by IP
[Line 751] Single-line comment:
  // Choose a random IP in the class C
[Line 755] Single-line comment:
  // Once we've chosen an IP, we'll try every given port before moving on
[Line 768] Single-line comment:
  // Advertise our address
[Line 774] Single-line comment:
  // Get as many addresses as we can
[Line 777] Single-line comment:
  ////// should the one on the receiving end do this too?
[Line 778] Single-line comment:
  // Subscribe our local subscription list
[Line 822] Single-line comment:
  // Poll the connected nodes for messages
[Line 830] Single-line comment:
  // Receive messages
[Line 834] Single-line comment:
  // Send messages
[Line 841] Single-line comment:
  // Wait and allow messages to bunch up
[Line 857] Single-line comment:
  //// todo: start one thread per processor, use getenv("NUMBER_OF_PROCESSORS")
[Line 885] Single-line comment:
  // Sockets startup
[Line 895] Single-line comment:
  // Get local host ip
[Line 915] Single-line comment:
  // Create socket for listening for incoming connections
[Line 924] Single-line comment:
  // Set to nonblocking, incoming connections will also inherit this
[Line 933] Single-line comment:
  // The sockaddr_in structure specifies the address family,
[Line 934] Single-line comment:
  // IP address, and port for the socket that is being bound
[Line 949] Single-line comment:
  // Listen for incoming connections
[Line 957] Single-line comment:
  // Get our external IP address for incoming connections
[Line 967] Single-line comment:
  // Get addresses from IRC and advertise ours
[Line 971] Single-line comment:
  //
[Line 972] Single-line comment:
  // Start threads
[Line 973] Single-line comment:
  //
[Line 1007] Single-line comment:
  // Sockets shutdown

File: /home/user/bitcoinArchive/study/util.cpp
--------------------------------------------------------------------------------
[Line 1] Single-line comment:
  // Copyright (c) 2009 Satoshi Nakamoto
[Line 2] Single-line comment:
  // Distributed under the MIT/X11 software license, see the accompanying
[Line 3] Single-line comment:
  // file license.txt or http://www.opensource.org/licenses/mit-license.php.
[Line 14] Single-line comment:
  // Init openssl library multithreading support
[Line 25] Single-line comment:
  // Init
[Line 31] Single-line comment:
  // Init openssl library multithreading support
[Line 37] Single-line comment:
  // Seed random number generator with screen scrape and other hardware sources
[Line 40] Single-line comment:
  // Seed random number generator with perfmon data
[Line 45] Single-line comment:
  // Shutdown openssl library multithreading support
[Line 59] Single-line comment:
  // Seed with CPU performance counter
[Line 70] Single-line comment:
  // Seed with the entire set of perfmon data
[Line 97] Single-line comment:
  // Safer snprintf
[Line 98] Single-line comment:
  //  - prints up to limit-1 characters
[Line 99] Single-line comment:
  //  - output string is always null terminated even if limit reached
[Line 100] Single-line comment:
  //  - return value is the number of characters actually printed
[Line 140] Single-line comment:
  // msvc optimisation
[Line 186] Single-line comment:
  //DebugBreak();
[Line 300] Single-line comment:
  // The range of the random source must be a multiple of the modulus
[Line 301] Single-line comment:
  // to give every possible output value an equal possibility
[Line 319] Single-line comment:
  //
[Line 320] Single-line comment:
  // "Never go to sea with two chronometers; take one or three."
[Line 321] Single-line comment:
  // Our three chronometers are:
[Line 322] Single-line comment:
  //  - System clock
[Line 323] Single-line comment:
  //  - Median of other server's clocks
[Line 324] Single-line comment:
  //  - NTP servers
[Line 325] Single-line comment:
  //
[Line 326] Single-line comment:
  // note: NTP isn't implemented yet, so until then we just use the median
[Line 327] Single-line comment:
  //  of other nodes clocks to correct ours.
[Line 328] Single-line comment:
  //
[Line 346] Single-line comment:
  // Ignore duplicates
[Line 351] Single-line comment:
  // Add data
[Line 364] Single-line comment:
  // Only let other nodes change our clock so far before we
[Line 365] Single-line comment:
  // go to the NTP servers
[Line 366] Single-line comment:
  /// todo: Get time from NTP servers, then set a flag
[Line 367] Single-line comment:
  ///    to make sure it doesn't get changed again


================================================================================
RPOW FILES
================================================================================

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/b64.c
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * b64.c
   * Base64 encoding and decoding, concise.
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 34-34] Multi-line comment:
  int	/* outlen */
[Lines 39-39] Multi-line comment:
  	int st = 0;	/* counts 0, 2, 4 */
[Lines 65-65] Multi-line comment:
  int	/* outlen */
[Lines 70-70] Multi-line comment:
  	int st = 0;	/* Counts 0, 2, 4, 6 */
[Lines 86-86] Multi-line comment:
  	/* assert (pc == 0); */
[Lines 92-92] Multi-line comment:
  /* Test the above */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/certvalid.c
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * certvalid.c
   * Validate a 4758 certificate chain.
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 59-65] Multi-line comment:
  /*
   * Acceptable class key moduli; these are for 4758-002
   * which is the high security version.
   * Note that the 04k9127v class key is a copy of
   * the 40h9952v file, although IBM suggests that they
   * are different.
   */
[Lines 113-113] Multi-line comment:
  /* Used for ISO 9796 padding */
[Lines 131-148] Multi-line comment:
  /*
   * Validate the cert chain starting at certbuf.  Return 0 if OK,
   * and set the three SHA-1 message digests for the three 4758
   * layers: miniboot, OS, and application.
   *
   * Pass fout non-null to get verbose progress reports to it.
   *
   * Return < 0 on validation error.
   *
   * On success, if these return pointers are non-null they get set:
   *
   * key, the OpenSSL format final RSA public key in the chain.
   * epochflag true for epoch keys, which persist across reloads, and
   *   false for configuration keys, which get cleared on reloads.
   * innerbuf, points within the certbuf at a block of data which can be
   *   embedded by the application in the final key in the chain.
   * innerbuflen, the length of innerbuf.
   */
[Lines 206-206] Multi-line comment:
  /* Returns success == 0, < 0 on failure */
[Lines 259-259] Multi-line comment:
  		stat = -2;			/* Unsupported */
[Lines 276-276] Multi-line comment:
  	/* Chain below us is OK.  Check our sig. */
[Lines 283-283] Multi-line comment:
  	/* Signature verifies OK */
[Lines 297-297] Multi-line comment:
  		/* Check class root key modulus against the ones we allow */
[Lines 336-336] Multi-line comment:
  		/* Require the OS to be the production or development owner */
[Lines 353-353] Multi-line comment:
  	/* Everything looks OK at this level */
[Lines 366-366] Multi-line comment:
  /* Check a pointer to a layer descriptor and pull out the message digest */
[Lines 399-402] Multi-line comment:
  /*
   * Verify the ISO 9796 signature used by IBM cert chains.  Return 0
   * if OK, < 0 on error.
   */
[Lines 425-425] Multi-line comment:
  		return -2;		/* Padding won't work */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/certvalid.h
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * certvalid.h
   *	Header file for 4758 certificate chain validation
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/connio.c
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * connio.c
   *	Manage connection I/O for RPOW client package
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 64-64] Multi-line comment:
  /* Maximum size we allow for a cert chain */
[Lines 69-76] Multi-line comment:
  /*
   * sha1sum's of the seg 1 ("miniboot", analogous to the bios),
   * seg 2 (OS), and seg 3 (application) that we accept as valid.
   * The application can be verified by (re)constructing the .rod
   * file (memory image) and computing the sha1sum of that file.
   * The OS and miniboot data were found by loading the current
   * versions into the card and seeing what hash it reports.
   */
[Lines 78-78] Multi-line comment:
  /* Maximum number of alternative hashes for each level */
[Lines 83-83] Multi-line comment:
  	unsigned char hash[MAXHASH][20];	/* actually 20 by nhash long */
[Lines 87-87] Multi-line comment:
  	/* Version 2.31-2.41 of the 4758 miniboot, "2.41 POST1, MB1" */
[Lines 94-94] Multi-line comment:
  /* Version 2.31 of the 4758 OS, "CCA 2.31 & PKCS#11 Segment-2" */
[Lines 98-98] Multi-line comment:
  /* Version 2.41-2.42 of the 4758 OS, "2.41 CP/Q++" */
[Lines 116-119] Multi-line comment:
  /*
   * Connect to card, reach cert chain, verify it, and if it is OK
   * we save the comm and signing keys in our files
   */
[Lines 145-145] Multi-line comment:
  	/* Retrieve certificate chain */
[Line 165] Single-line comment:
  //	printf ("Certificate chain:\n");
[Line 166] Single-line comment:
  //	dumpbuf (stdout, bigbuf, chainbuflen, 1, 1);
[Line 167] Single-line comment:
  //	printf ("\n");
[Line 210] Single-line comment:
  //			printf ("(Not validating hash values during debugging...)\n");
[Lines 218-218] Multi-line comment:
  	/* Now using embedded key for comm */
[Lines 252-252] Multi-line comment:
  	/* Delete rpows.dat file if we are starting fresh */
[Lines 260-262] Multi-line comment:
  /*
   * Connect to card, read and print status information to fout
   */
[Lines 295-295] Multi-line comment:
  	/* Prepare encryption key */
[Lines 304-304] Multi-line comment:
  	/* Returns a static buffer */
[Lines 311-311] Multi-line comment:
  	/* Retrieve status buffer */
[Lines 327-327] Multi-line comment:
  	/* Wait for response */
[Lines 344-344] Multi-line comment:
  	/* Returns a malloc buffer */
[Line 355] Single-line comment:
  //dumpbuf (fout, decbuf, decbuflen, 1, 1);
[Line 356] Single-line comment:
  //fprintf (fout, "\n");
[Lines 493-497] Multi-line comment:
  /*
   * Given a memory BIO, we send it to the 4758 and get a
   * response back, which we put back into the BIO for the caller
   * to read.
   */
[Lines 535-535] Multi-line comment:
  	/* Returns a static buffer */
[Lines 542-542] Multi-line comment:
  	/* Returns a malloc buffer */
[Lines 586-586] Multi-line comment:
  	/* Returns a malloc buffer */
[Lines 621-621] Multi-line comment:
  /* Support SOCKS V5 for anonymity */
[Lines 659-659] Multi-line comment:
  	/* See RFC 1928 for SOCKS V5 */
[Lines 660-660] Multi-line comment:
  	msg[0] = 5;	/* version */
[Lines 661-661] Multi-line comment:
  	msg[1] = 1;	/* number of authenticator methods */
[Lines 662-662] Multi-line comment:
  	msg[2] = 0;	/* 0 means no authentication */
[Lines 668-668] Multi-line comment:
  	/* Reply: version, selected auth */
[Lines 680-680] Multi-line comment:
  	msg[0] = 5;	/* version */
[Lines 681-681] Multi-line comment:
  	msg[1] = 1;	/* command: connect(1) */
[Lines 682-682] Multi-line comment:
  	msg[2] = 0;	/* reserved */
[Lines 683-683] Multi-line comment:
  	msg[3] = 3; /* address type */
[Lines 704-704] Multi-line comment:
  	/* Success! */
[Lines 748-748] Multi-line comment:
  /* Read data from socket until we reach count bytes, or error */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/cryptchan.c
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * cryptchan.c
   * Client side of a secure encrypted channel to the 4758.
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 44-44] Multi-line comment:
  /* Size of our master secret, matches HMAC input */
[Lines 48-52] Multi-line comment:
  /*
   * Given an RSA key, create a random master secret, encrypt it using
   * the key, and put it in the output.  Also generate our TDES
   * I/O keys and associated values and return those in encdata.
   */
[Lines 79-79] Multi-line comment:
  	/* Generate the shared keys */
[Lines 96-96] Multi-line comment:
  /* Increment a seqno */
[Lines 107-107] Multi-line comment:
  /* Do a TDES decrypt for coming from the card.  This also unpads. */
[Lines 131-133] Multi-line comment:
  /* Do a TDES encrypt for going to the card.  This also pads, so the output
   * buffer should be 8 bytes bigger than the input buffer.
   */
[Lines 159-159] Multi-line comment:
  /* TDES encrypt the buffer and put in the output */
[Lines 192-192] Multi-line comment:
  /* TDES decrypt input buffer, return in *buf and *buflen */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/cryptchan.h
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * cryptchan.h
   *	Header file for secure channel to 4758.
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 35-35] Multi-line comment:
  /* Host side secure channel to IBM 4758 */
[Lines 55-55] Multi-line comment:
  /* Functions for general buffers */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/gbignum.c
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * gbignum.c
   *	Generic bignum module implemented via OpenSSL
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 67-67] Multi-line comment:
  /* Return number of bytes requested on success, less on failure */
[Lines 77-77] Multi-line comment:
  /* Return a random in range min to maxp1 - 1 */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/gbignum.h
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * gbignum.h
   * Generic bignum module, wrapper around OpenSSL library.
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 43-43] Multi-line comment:
  #endif /* SHA1_DIGEST_LENGTH */
[Lines 124-124] Multi-line comment:
  #endif /* GBIGNUM_H */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/keys.c
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * keys.c
   *	Key related functions for RPOW package
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 45-45] Multi-line comment:
  /* Math functions */
[Lines 48-48] Multi-line comment:
  /* I/O functions */
[Lines 50-50] Multi-line comment:
  /* Compute keyid for pubkey */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/rpio.c
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * rpio.c
   *	Low level I/O for rpow package
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 107-107] Multi-line comment:
  /* gbignum I/O */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/rpowcli.c
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * rpowcli.c
   *	Reusable proof of work client
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 68-68] Multi-line comment:
  /* Continue to generate rpows until interrupted; consolidate them too */
[Line 81] Single-line comment:
  // Only appropriate for Mac PPC
[Lines 118-118] Multi-line comment:
  			/* Adjust size so it takes 10 to 60 minutes to do 8 rpows */
[Lines 131-131] Multi-line comment:
  /* Helper for doconsol - consolidate num items of size val */
[Lines 146-146] Multi-line comment:
  			/* Error, try to fix it as much as we can */
[Lines 172-172] Multi-line comment:
  /* Consolidate rpows into as few as possible */
[Lines 182-182] Multi-line comment:
  		/* Count rpows of value */
[Lines 228-228] Multi-line comment:
  	/* Read from stdin */
[Lines 245-245] Multi-line comment:
  		/* De-base64 */
[Lines 250-250] Multi-line comment:
  	/* Parse as a rpow */
[Lines 277-277] Multi-line comment:
  /* Helper for doout - break num outval items to create numo of size outval */
[Lines 294-294] Multi-line comment:
  			/* Error, try to fix it as much as we can */
[Lines 326-326] Multi-line comment:
  /* Helper for doout - break items to create some of size val */
[Lines 350-350] Multi-line comment:
  		return -1;		/* Insufficient rpows */
[Lines 388-388] Multi-line comment:
  	/* Convert to base64 and output to stdout */
[Lines 433-433] Multi-line comment:
  		/* Try putting the ones back we puled out */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/rpowcli.h
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * rpowcli.h
   *	Internal header file for reusable proof of work tokens
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 37-37] Multi-line comment:
  /* Default file names */
[Lines 47-47] Multi-line comment:
  /*typedef unsigned long ulong;*/
[Lines 51-51] Multi-line comment:
  /* "Pending" RPOW, one waiting to be signed by the server */
[Lines 52-52] Multi-line comment:
  /* rpow is in rpowclient.h */
[Lines 63-63] Multi-line comment:
  /* rpow.c */
[Lines 64-64] Multi-line comment:
  /* rpow functions are declared in rpowclient.h */
[Lines 75-75] Multi-line comment:
  #endif /* RPOWCLI_H */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/rpowclient.c
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * rpowclient.c
   *	External entry points into RPOW client library
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 51-51] Multi-line comment:
  /* Maximum number of in or out items in an exchange */
[Lines 54-54] Multi-line comment:
  /* Maximum size of config file line */
[Lines 57-57] Multi-line comment:
  /* File names for storing keys and data items */
[Lines 62-62] Multi-line comment:
  /* Host and port to use by default */
[Lines 66-66] Multi-line comment:
  /* SOCKS V5 host and port, optional */
[Lines 71-71] Multi-line comment:
  /* Temporary, the one public signing key we know about */
[Lines 93-98] Multi-line comment:
  /*
   * Given a set of input rpows, and the desired number and denomination
   * of output rpows, do an exchange at the server and return a status
   * code and, if OK, the output rpows.  Output array *rpout should be
   * pre-allocated as an array of pointers to rpow, nout items long.
   */
[Lines 140-140] Multi-line comment:
  	/* Output formatted request to bio buffer via rpio */
[Lines 143-143] Multi-line comment:
  	/* Do the exchange with the IBM4758 */
[Lines 154-154] Multi-line comment:
  	/* Read results. bio buffer rpio points at holds the output from server. */
[Lines 205-209] Multi-line comment:
  /*
   * Read a config line.  Return keyword and value.
   * On EOF return *key and *val as NULL.  Skip bad lines but
   * print a message.
   */
[Lines 390-390] Multi-line comment:
  	/* Now read config file */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/rpowclient.h
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * rpowclient.h
   *	External header file for reusable proof of work tokens
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 45-45] Multi-line comment:
  /* Public keys, for communication and rpow signature verification */
[Lines 58-58] Multi-line comment:
  /* Reusable proof of work */
[Lines 68-68] Multi-line comment:
  /* Generic I/O channel representative */
[Lines 75-75] Multi-line comment:
  /* File names for keys */
[Lines 80-80] Multi-line comment:
  /* Host and port for server */
[Lines 84-84] Multi-line comment:
  /* Optional SOCKS V5 host and port */
[Lines 90-90] Multi-line comment:
  /* rpowclient.c */
[Lines 96-96] Multi-line comment:
  /* connio.c */
[Lines 102-102] Multi-line comment:
  /* rpio.c */
[Lines 115-115] Multi-line comment:
  /* keys.c */
[Lines 120-120] Multi-line comment:
  /* rpowutil.c */
[Lines 136-136] Multi-line comment:
  #endif /* RPOWCLIENT_H */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/rpowutil.c
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * rpowutil.c
   *	Generate, read and write reusable proof of work tokens
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 52-71] Multi-line comment:
  /*
   * RPOW tokens come in two types.  In transit they are preceded by a type
   * byte and then a four byte value field, which is the equivalent of the
   * hashcash collision size, and must be in the range RPOW_VALUE_MIN to
   * RPOW_VALUE_MAX.  The hashcash type (type 2) then has a four byte length
   * field, and then a version 1 hashcash stamp.  The value in the stamp
   * should equal the earlier value field.
   *
   * The reusable type (type 1) then has a 20 byte keyid.  This is the hash of
   * the public key which issued the token.  It then has a 34 byte token id,
   * of which the last 14 bytes are the cardid where it can be exchanged.  Then
   * comes a value signed by the public key identified by the keyid.  The signed
   * value is in a bignum format where it is preceded by a 4-byte byte count.
   * The plaintext of that value consists of the 20 byte SHA-1 hash of the
   * token id, then the byte 2, then is padded to the width of the signing key's
   * modulus modulus.  The padding is done by repeatedly SHA-1 hashing what
   * we have so far and appending the hash, until we have the width we need
   * (the last append just uses the leftmost bytes of the hash).  We then
   * take that value mod the signing key's modulus.  This is what is signed.
   */
[Lines 93-93] Multi-line comment:
  /* Find the exponent corresponding to the given value */
[Lines 94-94] Multi-line comment:
  /* Exponents are consecutive primes starting with pk->e */
[Lines 103-103] Multi-line comment:
  		/* First time; fill exptab with consecutive primes */
[Lines 121-121] Multi-line comment:
  /* Convert a regular hashcash coin to a buffer in our format */
[Lines 148-148] Multi-line comment:
  /* Read an rpow value */
[Lines 197-197] Multi-line comment:
  /* Read an RPOW value from an ascii string */
[Lines 206-206] Multi-line comment:
  	/* Determine whether it is pure hashcash or a base64 rpow */
[Lines 211-211] Multi-line comment:
  		/* De-base64 */
[Lines 219-219] Multi-line comment:
  /* Read an RPOW value from a binary buffer */
[Lines 242-242] Multi-line comment:
  /* Output RPOW value to a malloc'd binary buffer */
[Lines 265-265] Multi-line comment:
  /* Return a malloc'd base64 string representing an RPOW */
[Lines 287-287] Multi-line comment:
  /* Write out an rpow value */
[Lines 303-303] Multi-line comment:
  	} else {	/* rp->type == RPOW_TYPE_RPOW */
[Lines 315-329] Multi-line comment:
  /* Prove possession of an RPOW signature without revealing it.  Both sides
   * know the value that got signed, and we emit a non interactive
   * zero knowledge proof that we know a root of that value.
   * sig is the signature we know.  value is the
   * value of the RP (used to derive the exponent), proofstrength is the log
   * of the work factor to forge a proof (should be 64-80 range).  pk is the
   * public key of the RPOW signer, and rpio is where the proof goes.
   * This is done with the Guillou-Quisquater identification protocol.
   * The protocol has prover give rn to verifier (supposedly r^n);
   * verifier gives c to prover;
   * prover gives v to verifier (supposedly nth root of rpow, to the c, times r);
   * verification is val^c * rn == v^n
   * We do it non-interactively, where we create all the commitments, then do
   * the challenge as the hash of the commitments.
   */
[Lines 412-412] Multi-line comment:
  /* Verify a proof written by the proof function; return 0 if OK */
[Lines 491-491] Multi-line comment:
  /* Free an rpow */
[Lines 501-501] Multi-line comment:
  /* Return the POW resource name in a static buffer */
[Lines 521-521] Multi-line comment:
  /* Generate a "hashcash" type of proof of work token */
[Lines 545-545] Multi-line comment:
  	/* rp->id holds a malloc buffer with the token */
[Lines 552-552] Multi-line comment:
  /* Generate the rpow field of an rpowpend */
[Lines 577-577] Multi-line comment:
  /* Generate an rpowpend of the specified value */
[Lines 578-578] Multi-line comment:
  /* dohide means to hide the value to be signed, used for splitting rpows */
[Lines 621-621] Multi-line comment:
  /* Read an rpowpend written by rpowpend_write */
[Lines 649-649] Multi-line comment:
  /* Write out an rpowpend */
[Lines 661-661] Multi-line comment:
  /* Read and validate a signed rpowpend from the server, producing a new rpow */
[Lines 680-680] Multi-line comment:
  	/* Validate signature */
[Lines 702-702] Multi-line comment:
  /* Free an rpowpend */
[Lines 714-714] Multi-line comment:
  /* Validate an rpow token, return 0 if OK, error code if bad */
[Lines 724-724] Multi-line comment:
  /* Given a POW token (hashcash version 1), parse out the fields */
[Lines 725-725] Multi-line comment:
  /* Example:  1:15:040719:rpow.net::9e6c82f8e4727a6d:1ec4 */
[Lines 726-726] Multi-line comment:
  /* The pointers returned are pointers into the input str */
[Lines 727-727] Multi-line comment:
  /* str does not have to be null terminated */
[Lines 728-728] Multi-line comment:
  /* Return error if no good */
[Lines 805-805] Multi-line comment:
  	/* Parse the POW and see if its fields are legal */
[Lines 819-819] Multi-line comment:
  	/* Now test the hash to see if it has the right number of high 0's */
[Lines 830-830] Multi-line comment:
  /* Temporary version of this, return the one public key we know about */
[Lines 960-960] Multi-line comment:
  	/* Delete entry from file */
[Lines 983-983] Multi-line comment:
  /* Fill in the counts array with how many rpows in the store of each value */
[Lines 1009-1009] Multi-line comment:
  			/* Skip invalid rpow */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/scc.h
--------------------------------------------------------------------------------
[Lines 1-4] Multi-line comment:
  /*
   * scc.h
   *	Definitions for IBM 4758 Secure Crypto Coprocessor data structures
   */
[Lines 41-41] Multi-line comment:
  /* SCC current time */
[Lines 61-61] Multi-line comment:
  /* RSA Key */
[Lines 62-62] Multi-line comment:
  /* This is just part of the SCC structure, relating to public keys */
[Lines 63-63] Multi-line comment:
  /* The actual structure is longer */
[Lines 159-159] Multi-line comment:
  /* Certificate header; vData field points to body */
[Lines 173-173] Multi-line comment:
  /* Certificate body */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/util4758.c
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * util4758.c
   * General utility functions for dealing with 4758 data.
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 82-82] Multi-line comment:
  /* Convert an RSA public key from 4758 format to openssl format */
[Lines 100-100] Multi-line comment:
  /* Extract an RSA key from the buffer the card embeds in the cert chain */
[Lines 101-101] Multi-line comment:
  /* Keys are stored as (n, e) pairs with each bignum preceded by 4 byte len */
[Lines 109-109] Multi-line comment:
  	/* Skip to the nth entry */
[Lines 130-134] Multi-line comment:
  /*
   * Find pointer to nth RSA key in the buffer the card embeds in the
   * cert chain.
   * Keys are stored as (n, e) pairs with each bignum preceded by 4 byte len
   */
[Lines 142-142] Multi-line comment:
  	/* Skip as needed */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/client/util4758.h
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * util4758.h
   *	General utility functions for dealing with 4758 data
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 39-39] Multi-line comment:
  /* Don't know how portable this will be... */
[Lines 42-43] Multi-line comment:
  /* The host byte order is the same as 4758 byte order,
     so these functions are all just identity.  */
[Lines 61-61] Multi-line comment:
  	/* Cannot determine endianness, do it as a call */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/common/commands.h
--------------------------------------------------------------------------------
[Lines 1-28] Multi-line comment:
  /*
   * commands.h
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 33-33] Multi-line comment:
  /* Initial keygen for the parent node in the family */
[Lines 36-36] Multi-line comment:
  /* Roll over node keys and create new ones */
[Lines 39-39] Multi-line comment:
  /* Add a new key from another RPOW node */
[Lines 42-42] Multi-line comment:
  /* Activate or de-activate another node's key */
[Lines 45-45] Multi-line comment:
  /* Return this node's certificate chain */
[Lines 48-48] Multi-line comment:
  /* The main event, receive rpows and sign rpends */
[Lines 51-51] Multi-line comment:
  /* Provide database authentication message as node checks for re-use */
[Lines 54-54] Multi-line comment:
  /* Return general node status information, memory usage, etc. */
[Lines 57-57] Multi-line comment:
  /* Clear the low battery latche */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/common/errors.h
--------------------------------------------------------------------------------
[Lines 1-28] Multi-line comment:
  /*
   * errors.h
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 55-55] Multi-line comment:
  /* Not an error, but a database query */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/common/rpow.h
--------------------------------------------------------------------------------
[Lines 1-28] Multi-line comment:
  /*
   * rpow.h
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 46-46] Multi-line comment:
  /* Our hashcash resource string, preceded by cardid in hex */
[Lines 50-53] Multi-line comment:
  /*
   * Exponent used for all rpow keys; signing keys use consecutive
   * primes starting from here.
   */
[Lines 60-60] Multi-line comment:
  /* Status codes */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/scc/certvalid.c
--------------------------------------------------------------------------------
[Lines 1-29] Multi-line comment:
  /*
   * certvalid.c
   * Validate a 4758 certificate chain.
   *
   * Copyright (C) 2004 Hal Finney
   * All rights reserved.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the above copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. The name of the author may not be used to endorse or promote products
   *    derived from this software without specific prior written permission.
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
   * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
   * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
[Lines 39-39] Multi-line comment:
  /* Version 2.31 of the 4758 OS, "CCA 2.31 & PKCS#11 Segment-2" */
[Lines 45-45] Multi-line comment:
  /* Version 2.41-2.42 of the 4758 OS, "2.41 CP/Q++" */
[Lines 64-81] Multi-line comment:
  /*
   * Validate the cert chain starting at certbuf.  Return 0 if OK.
   *
   * We require the cert to substantially match our own certification
   * chain: same application hash, one of two different OS hashes,
   * same miniboot hash.  And the OA key must be a configuration
   * key rather than an epoch key, because configuration keys are
   * volatile and will evaporate if the program is reloaded.  Of
   * course, if the hashes match then it should be axiomatic that
   * the OA key is legal, since we don't create epoch keys.
   *
   * Return nonzero on validation error.
   *
   * On success, returns these output pointers:
   * innerbuf, points within the certbuf at a block of data which can be
   *   embedded by the application in the final key in the chain.
   * innerbuflen, the length of innerbuf.
   */
[Lines 103-103] Multi-line comment:
  	/* Read my own cert to get my message digest */
[Lines 120-120] Multi-line comment:
  	/* Validate message hashes to see that it matches this card */
[Lines 131-131] Multi-line comment:
  	/* Success! */
[Lines 154-154] Multi-line comment:
  /* Returns success == 0, nonzero on failure */
[Lines 205-205] Multi-line comment:
  		stat = -2;			/* Unsupported */
[Lines 223-223] Multi-line comment:
  	/* Chain below us is OK.  Check our sig. */
[Lines 227-227] Multi-line comment:
  	/* If parent is root, check that class cert matches, else validate sig */
[Lines 232-232] Multi-line comment:
  		/* Cannot verify if tSig == 1, but works OK to change it! */
[Lines 241-241] Multi-line comment:
  	/* Signature verifies OK */
[Lines 248-248] Multi-line comment:
  		/* Actually a class root */
[Lines 268-268] Multi-line comment:
  		/* Require the OS to be the production or development owner */
[Lines 281-281] Multi-line comment:
  	/* Everything looks OK at this level */
[Lines 291-294] Multi-line comment:
  /*
   * Given the last cert in the chain, supposedly a class root cert,
   * verify that it matches our class root.
   */
[Lines 318-318] Multi-line comment:
  /* Check a pointer to a layer descriptor and pull out the message digest */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/scc/cryptchan.c
--------------------------------------------------------------------------------
[Lines 1-1] Multi-line comment:
  /* Set up a secure crypto channel from/to the host */
[Lines 9-9] Multi-line comment:
  /* Return a key in a malloc buffer */
[Lines 38-40] Multi-line comment:
  /*
   * OAEP helper function, hash input to specified output length
   */
[Lines 68-71] Multi-line comment:
  /*
   * Do a PKCS-1 V2 OAEP unpad, using SHA-1, MGF1 and empty param.
   * Assume input is full length of the modulus.
   */
[Lines 86-86] Multi-line comment:
  	int rc = 0;		/* return code */
[Lines 88-88] Multi-line comment:
  	/* OAEP unpadding */
[Lines 114-114] Multi-line comment:
  /* Decrypt encrypted master secret, setting up encstate for later work */
[Lines 115-115] Multi-line comment:
  /* We ignore padding errors but set a failed flag */
[Lines 116-116] Multi-line comment:
  /* This entry point takes an RSA private key */
[Lines 130-130] Multi-line comment:
  	/* Set up for decryption.  */
[Lines 147-147] Multi-line comment:
  /* Given our decrypted buffer, extract master secret and set up keys */
[Lines 161-161] Multi-line comment:
  	/* Generate the four keys */
[Lines 177-177] Multi-line comment:
  /* Increment sequence number */
[Lines 188-188] Multi-line comment:
  /* Pad and unpad buffers for TDES */
[Lines 189-189] Multi-line comment:
  /* Padding outputs to a malloc buffer */
[Lines 190-190] Multi-line comment:
  /* Note that we write to every byte of the buffer so we don't leak data */
[Lines 205-205] Multi-line comment:
  /* Unpadding remains in the same buffer */
[Lines 217-219] Multi-line comment:
  /* Do a TDES encrypt for going to the host.  obuf will get the IV so
   * must be buflen+TDESBYTES long
   */
[Lines 230-230] Multi-line comment:
  	/* Put IV into the beginning of the output buffer */
[Lines 233-233] Multi-line comment:
  	/* Encrypt the data (note that "in" is host relative */
[Lines 252-252] Multi-line comment:
  /* Do a TDES decrypt for coming from the host */
[Lines 253-253] Multi-line comment:
  /* buflen counts the iv, so obuf is TDESBYTES shorter than buflen */
[Lines 264-264] Multi-line comment:
  	/* Decrypt the data (note that "out" is host relative */
[Lines 283-283] Multi-line comment:
  /* TDES decrypt the input buffer, return in *buf and *buflen */
[Lines 345-345] Multi-line comment:
  /* TDES encrypt the buffer and send to the host */
[Lines 346-346] Multi-line comment:
  /* Note that we write to every byte of the output buffer */
[Lines 372-372] Multi-line comment:
  	encbuflen += TDESBYTES;		/* IV */
[Lines 378-378] Multi-line comment:
  	encbuflen += SHABYTES;		/* MAC */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/scc/cryptchan.h
--------------------------------------------------------------------------------
[Lines 1-4] Multi-line comment:
  /*
   * cryptchan.h
   *	Header file for SCC side of secure crypto channel
   */
[Lines 24-24] Multi-line comment:
  /* Limit our input size to guard against memory exhaustion */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/scc/dbverify.c
--------------------------------------------------------------------------------
[Lines 1-4] Multi-line comment:
  /*
   * dbverify.c
   *	Verify the correctness of updates to an off-card database
   */
[Lines 21-28] Multi-line comment:
  /*
   * Database is formatted as a btree.
   * Leaf nodes have from NODEKEYS/2 to NODEKEYS keys.
   * Each inner node has from NODEKEYS/2 to NODEKEYS keys,
   * and one more child than keys.
   * Top node has from 2 to NODEKEYS children.
   * We start up with 1 top node with 1 child, 1 empty leaf node.
   */
[Lines 30-30] Multi-line comment:
  /* Number of keys per node, must be even */
[Lines 43-43] Multi-line comment:
  /* Our DB proof structure from the host is an array of these */
[Lines 44-44] Multi-line comment:
  /* We allow NODEKEYS+1 keys in a node temporarily but will split it */
[Lines 48-48] Multi-line comment:
  	uchar hashdata[1][HASHSIZE];	/* Actually 2*nkeys+1 hashes */
[Lines 49-49] Multi-line comment:
  									/* First, nkeys key hashes, then */
[Lines 50-50] Multi-line comment:
  									/* if non-leaf, nkeys+1 childhashes */
[Lines 53-53] Multi-line comment:
  /* Compressed nodes have variable-sized array */
[Lines 58-72] Multi-line comment:
  /*
   * Persistent data
   * This data is not sensitive but must be preserved across reboots.
   * hashroot is the hash of the top node of the tree.  Each node contains
   * the hash of its children.  Hence this is in effect a hash of the whole
   * tree.  This is what allows us to validate proper behavior of the
   * untrusted host.  depth is the current depth of the tree, used in the
   * validation algorithm so we know when we get to a leaf node.
   * Btrees have the property that all branches are the same depth, because
   * we only add nodes at the top.
   *
   * We keep this data in both DRAM and BBRAM, which is persistent.
   * We read it from DRAM, and write it to both on every change.
   * After a reboot we read it back from BBRAM into DRAM.
   */
[Lines 78-81] Multi-line comment:
  /*
   * This data structure defines what we put into BBRAM.
   * The actual number of dbdata structs equals nfiles.
   */
[Lines 88-88] Multi-line comment:
  /* Arrays to give room to expand our nodes */
[Lines 93-93] Multi-line comment:
  /* Value of hash root on an empty database */
[Lines 100-100] Multi-line comment:
  /* Name for our persistent data */
[Lines 111-111] Multi-line comment:
  /* Return 0 on successful operation and set *found flag */
[Lines 122-122] Multi-line comment:
  	/* Compute the hash of the data */
[Lines 128-128] Multi-line comment:
  	/* Send hash to the host to be added to the DB */
[Lines 129-129] Multi-line comment:
  	/* Also include our hash root (to help resync after crashes) and fileid */
[Lines 139-139] Multi-line comment:
  	/* Get response from host */
[Lines 146-146] Multi-line comment:
  	/* Read validation data */
[Lines 157-157] Multi-line comment:
  	/* Check database branch for validity */
[Lines 166-166] Multi-line comment:
  /* Initialize DB persistent data.  Called when we start up on a fresh card. */
[Lines 182-189] Multi-line comment:
  /*
   * Make sure the fileid we got from the host is OK.
   * Can't be 0-2 as those are our POW files and they get reset
   * periodically.  If it is a new key (i.e. a rollover key)
   * it must be the next sequential key number.  If it is a
   * key from another node, it could be a new key number or it
   * could share an existing fileid.
   */
[Lines 202-202] Multi-line comment:
  /* Create a new fileid entry corresponding to a new empty DB. */
[Lines 214-214] Multi-line comment:
  	/* Do nothing if not adding a new one */
[Lines 228-228] Multi-line comment:
  	/* Add a new random prefix to the persistent sensitive data */
[Lines 235-235] Multi-line comment:
  /* Add a new random prefix to the persistent data */
[Lines 255-255] Multi-line comment:
  /* Called when card reboots */
[Lines 262-262] Multi-line comment:
  	/* We are rebooting */
[Lines 271-280] Multi-line comment:
  /*
   * Call periodically, at least once every two weeks(!)
   * Resets the unused POW DB during the first two weeks of the month
   * We use fileids 0-2 in round robin fashion for the month that a
   * POW was created.  We only accept them for a few days in the past and
   * less in the future.  So if we are in the first part of month 0, for
   * example, we will reset the database for month 1.  This assumes similar
   * actions on the part of the host, that it deletes and resets its POW
   * databases when they are no longer in use.
   */
[Lines 292-292] Multi-line comment:
  		/* Get number of next month's POW DB, which is unused */
[Lines 315-315] Multi-line comment:
  /*****************************  VALIDATE  *******************************/
[Lines 318-329] Multi-line comment:
  /*
  
  The idea here is that an untrusted system can maintain the DB, and provide
  evidence to a second system as to whether any given item is found or not
  (and added if missing).  The second system maintains a hash over the
  whole DB, following the btree structure.  It checks the returned evidence
  data against the hash to make sure it matches, verifies that the evidence
  does in fact prove presence or absence, and if adding, independently
  calculates the updated hash, using an algorithm that mirrors that done on
  the untrusted system.
  
  */
[Lines 332-332] Multi-line comment:
  /* Hash the given node key and childhash data (if nonleaf) and return result */
[Lines 357-357] Multi-line comment:
  /* Return <0, 0, or >0 as key1 is <, ==, or > key2 */
[Lines 392-392] Multi-line comment:
  	/* Pick up values from compnode */
[Lines 405-405] Multi-line comment:
  	/* Verify that this node's data matches expected hash */
[Lines 411-411] Multi-line comment:
  	/* Validate that keyind is correct */
[Lines 432-432] Multi-line comment:
  		/* Done, unfound, if not inserting */
[Lines 439-439] Multi-line comment:
  		/* Leaf node, just add the data */
[Lines 446-446] Multi-line comment:
  		/* Recurse */
[Lines 449-449] Multi-line comment:
  		childnodehash = node->hashdata[nkeys+keyind];	/* childhash field */
[Lines 462-462] Multi-line comment:
  			/* No split below us, just update our changed hash upwards */
[Lines 468-468] Multi-line comment:
  		/* Child did a split, new node is to right of old one */
[Lines 480-480] Multi-line comment:
  	/* Now split our node if it is too full */
[Lines 481-481] Multi-line comment:
  	/* We move one key up (to splitkey) and put NODEKEYS/2 in this one and */
[Lines 482-482] Multi-line comment:
  	/* the new one.  The new node gets the higher value keys and is the */
[Lines 483-483] Multi-line comment:
  	/* right sibling of the existing node. */
[Lines 491-491] Multi-line comment:
  		/* Now hash the split data into the two parent fields */
[Lines 496-496] Multi-line comment:
  		/* No split was done, just update parent hash */
[Lines 504-508] Multi-line comment:
  /*
   * Return true if valid, false if not.  Return *found as true if we found
   * the data item (if we are returning valid).
   * Update treehash if set is true and not found (and valid).
   */
[Lines 518-539] Multi-line comment:
  /*
  	First test: that each node either matches newhash on key[keyind] (in which
  	case it is found) or else newhash is between key[keyind] and key[keyind+1]
  	(or if keyind == nkeys-1 then newhash is above key[keyind]).
  
  	Second test: that hashing each node produces the parent childhash field.
  
  	Third test: that hashing the root node produces our saved treehash.
  
  	Given all these three tests, we validate the presence/absence of the
  	item.  If found, or if set is false, we are done.
  
  	Otherwise we have to do updates and ultimately we are updating treehash.
  	To do the updates we insert the new node data where it should go, and
  	split the node if necessary.
  
  	For recursive testing, first check the tree hash at the top level.
  	Then at each level first test the keyind value, then test the childhash
  	of the next level (if recursing).  I.e. before recursing check the
  	childhash to make sure it is as expected.  Thus we validate each data
  	before trusting it.
  */
[Lines 553-553] Multi-line comment:
  	/* Must create new top node because old top filled up and split */
[Lines 554-554] Multi-line comment:
  	/* Top node has only one item, the splitkey, and two hashes */
[Lines 555-555] Multi-line comment:
  	/* We only need to update the treehash from it */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/scc/gbignum.c
--------------------------------------------------------------------------------
[Lines 1-6] Multi-line comment:
  /*
   * gbignum.c
   *	Generic bignum module implemented via IBM4758 hardware
   *	This runs on the IBM4758
   *	We use little-endian mode, it makes the math a little simpler
   */
[Lines 14-14] Multi-line comment:
  #endif /* NULL */
[Lines 18-18] Multi-line comment:
  #endif /* MIN */
[Lines 22-22] Multi-line comment:
  #endif /* MAX */
[Lines 113-113] Multi-line comment:
  /* Return zero on success, negative on failure */
[Lines 134-134] Multi-line comment:
  /* Compute SHA1 of the specified buffer */
[Lines 158-158] Multi-line comment:
  /* For SHA, the engine can only update in mults of 64, so we buffer for it */
[Lines 228-228] Multi-line comment:
  /* Set bytesize and bitsize properly */
[Lines 251-251] Multi-line comment:
  /* Use the onboard math chip to do a mod, modmult, or modexp */
[Lines 264-264] Multi-line comment:
  	/* Don't overwrite bnc yet in case it is a copy of one of the others */
[Lines 265-265] Multi-line comment:
  	/* Getting a range overflow error, maybe the output buffer is too small */
[Lines 266-266] Multi-line comment:
  	/* Yes, adding 2 fixed it (maybe adding 1 would have worked too) */
[Lines 273-273] Multi-line comment:
  		/* Should not happen */
[Lines 274-274] Multi-line comment:
  		/*printf ("sccModMath failed with code 0x%x\n", err)*/;
[Lines 391-391] Multi-line comment:
  /* Mul by doing a mulmod with a big enough power of two! */
[Lines 419-419] Multi-line comment:
  /* Crazy idea to try multiplying by the inverse mod a large prime */
[Lines 488-488] Multi-line comment:
  /* Algorithm X from Knuth */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/scc/gbignum.h
--------------------------------------------------------------------------------
[Lines 1-1] Multi-line comment:
  /* Generic bignum module for IBM 4758 */
[Lines 2-2] Multi-line comment:
  /* Also includes some crypto functions */
[Lines 20-20] Multi-line comment:
  #endif /* SHA1_DIGEST_LENGTH */
[Lines 69-69] Multi-line comment:
  #endif /* GBIGNUM_H */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/scc/hmac.c
--------------------------------------------------------------------------------
[Lines 1-1] Multi-line comment:
  /* HMAC function for IBM 4758 */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/scc/hmac.h
--------------------------------------------------------------------------------
[Lines 1-1] Multi-line comment:
  /* hmac.h */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/scc/keygen.c
--------------------------------------------------------------------------------
[Lines 1-1] Multi-line comment:
  /* Gen an OA key and return its cert chain */
[Lines 8-8] Multi-line comment:
  /* Generate blinding factors for a signing key */
[Lines 9-9] Multi-line comment:
  /* Array consists of r^e, r_inv, each the size of the modulus */
[Lines 32-37] Multi-line comment:
  /*
   * Generate blinding factors for all signing exponents.  This is only
   * used on boot or on keygen.
   * Then the 4758 function generates new blinding factors after each
   * use.
   */
[Lines 81-81] Multi-line comment:
  /* Generate dp dq array for rpow key */
[Lines 82-82] Multi-line comment:
  /* Each represents a d value for e values that are consecutive primes */
[Lines 134-134] Multi-line comment:
  /* Check that the key is suitable for use as an rpow key */
[Lines 135-135] Multi-line comment:
  /* We want to make sure p-1 and q-1 are relatively prime to many values */
[Lines 136-136] Multi-line comment:
  /* Return 0 if OK, nonzero otherwise */
[Lines 148-148] Multi-line comment:
  	/* Require dp and dq to be exactly half the modulus length */
[Lines 152-152] Multi-line comment:
  	/* Require r and r1 to be exactly the modulus length */
[Lines 164-164] Multi-line comment:
  	/* Make sure p, q mod x is not 1 for all small primes */
[Lines 187-187] Multi-line comment:
  /* Generate an RSA key and then put its public part into the pubbuf */
[Lines 188-188] Multi-line comment:
  /* Caller supplies an adequately sized buffer, *pkeylen holds its length */
[Lines 219-219] Multi-line comment:
  	/* Store modulus and exponent fields for OA generate */
[Lines 220-220] Multi-line comment:
  	/* Precede them with four byte count, bigendian */
[Lines 238-238] Multi-line comment:
  /* Add the pubkey value from our private key */
[Lines 253-253] Multi-line comment:
  /* Set the pubkey version of current signing key */
[Lines 266-266] Multi-line comment:
  /* Generate an OA key and return its name */
[Lines 287-290] Multi-line comment:
  	/*
  	 * First we will generate two regular keys, then an OA key with
  	 * those keys embedded in it
  	 */
[Lines 306-306] Multi-line comment:
  	/* Generate dp, dq values for other exponents for rpowkey */
[Lines 309-335] Multi-line comment:
  	/*
  	 * Here is the problem.  We want to put out card ID into the cert chain.
  	 * But the card ID must be unique for every instantiation of the program,
  	 * including re-initializations.  We can't know reliably what instantiation
  	 * number we are based on our own data, because any persistent data might
  	 * have been left by a malicious program.  We can't trust anything on
  	 * reload unless our OA key is still intact, because as a configuration
  	 * key it will be erased on any software reload.  So if we start fresh,
  	 * with a new OA key, we can't trust any persistent data, hence we can't
  	 * know how many reloads we have had.  So we can't, on our own, create
  	 * a cardid which is guaranteed unique across reloads.
  	 *
   	 * The solution is to use the boot counter along with the OA manager's
  	 * index value.  It is guaranteed to be unique.  Unfortunately the only
  	 * way to get it is to generate an OA key.  But we want to put the data
  	 * into the OA key certificate!
  	 *
  	 * Therefore we will generate two OA keys.  We will generate the first
  	 * one and extract the boot counter information to generate a guaranteed
  	 * unique card id based on the concatenation of our AdapterID and the
  	 * boot counter plus index.  This we will put into the cardid field.
  	 * Then we will discard that OA key and generate the persistent one,
  	 * which will include the cardid along with the RSA keys generated
  	 * above in the certificate.  This way we will be able to propagate
  	 * our cardid in the one certificate we create, and it will still be
  	 * guaranteed unique.
  	 */
[Lines 339-339] Multi-line comment:
  		/* Generate a throw-away OA key just to get a unique instance ID */
[Lines 358-358] Multi-line comment:
  		/* Set the cardid from that OA cert, and then delete it */
[Lines 365-365] Multi-line comment:
  	/* Now generate the "real" OA key */
[Lines 367-367] Multi-line comment:
  	/* Add our card ID to the authenticated key data */
[Lines 370-370] Multi-line comment:
  	/* Generate the OA key embedding our keys */
[Lines 391-391] Multi-line comment:
  	/* Add a new pubkey item from the new private key */
[Lines 393-393] Multi-line comment:
  	/* Set the global variable holding our new signing key id */
[Lines 395-395] Multi-line comment:
  	/* Generate blinding factors for all exponents of the signing key */
[Lines 398-398] Multi-line comment:
  	/* Update secret data in flash */
[Lines 405-408] Multi-line comment:
  /*
   * Get the cert chain that validates the named cert.
   * Return in a malloc buffer *pcertbuf, setting *pcertbuflen.
   */
[Lines 467-467] Multi-line comment:
  /* Send the host the hash chain for the named key */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/scc/persist.c
--------------------------------------------------------------------------------
[Lines 1-10] Multi-line comment:
  /*
   * persist.c
   *	Manage persistent data for IBM 4758 RPOW server
   *
   *	"Nothing in the world can take the place of persistence. Talent will
   *	not; nothing is more common than unsuccessful men with talent. Genius
   *	will not; unrewarded genius is almost a proverb. Education will not;
   *	the world is full of educated derelicts. Persistence and determination
   *	are omnipotent." - Calvin Coolidge
   */
[Lines 12-67] Multi-line comment:
  /*
   *
   * There are many ways to categorize the data used in the RPOW system.
   * One is persistent vs transient.  Persistent data must be preserved
   * across reboots.  A reboot occurs when the power goes away and comes back,
   * or on command from the host.  At a reboot, DRAM memory is cleared and
   * the program restarts from the beginning (from main).  The 4758 has two
   * categories of persistent memory: battery-backed RAM (BBRAM) and flash.
   * Flash has a limited number of write cycles while BBRAM can be written to
   * as many times as desired.  BBRAM is automatically cleared on tamper, while
   * flash is not.  This module is responsible for managing persistent data.
   *
   * Another way to divide the data is stable versus dynamic.  Dynamic data
   * changes relatively often, while stable data changes seldom.
   *
   * A third way is sensitive versus non-sensitive.  Sensitive data must be
   * kept secret from the outside world in order for the program to reach its
   * security goals.
   *
   * Among the persistent data, this gies four possible categories.  We use
   * three of them.  The only one we don't use is persistent, dynamic,
   * sensitive data.  Let us consider the other categories and what is there.
   *
   * Persistent, dynamic, non-sensitive data includes the external database
   * validation data.  For each external database we track, we maintain a hash
   * tree root, which is in effect a hash of the entire file.  This allows
   * us to validate that the information provided by the host computer is
   * accurate.  We also maintain the depth of the tree as an aide to performing
   * updates.  This data is not sensitive because it is not secret; the host
   * knows what it is.  It changes every time we change the database, which
   * is on every signature issuance, so it is highly dynamic.  And it must
   * persist for the life of the database file, which is potentially forever.
   * We put this data into BBRAM because flash could not handle the number of
   * write cycles we anticipate performing in the lifetime of the software,
   * potentially billions of signature issuances.  We don't manage this data
   * within this module, it is done in the DB validation module.
   *
   * Persistent, stable, sensitive data includes our private keys.  We have
   * three private keys.  One is the Outbound Authentication key maintained by
   * the IBM OS.  We don't even have access to the private part of that key.
   * It is automatically deleted whenever the software configuration changes.
   * We also have a communications key and our main rpow signing key.  All of
   * these are persistent and sensitive, and change only on key rollover
   * (when we retire an old key and create a new one).  The IBM OS stores
   * the OA private key in BBRAM, and we use that key to encrypt the private
   * parts of our other keys and store them in flash.  Because the OA key is
   * wiped on software configuration change, that also effectively eliminates
   * access to the rpow signing key and the comm key.
   *
   * Persistent, stable, non-sensitive data includes the public keys that
   * we recognize and accept as RPOW issuers.  These come from two places;
   * one is our previous RPOW signing keys that we have retired in rollovers;
   * and the other is the RPOW signing keys of other cards that are part of
   * the same family and were created via the spawning process.
   *
   */
[Lines 74-78] Multi-line comment:
  /*
   * Persistent data.
   * This data is sensitive but hardly ever changes.
   * We store it in flash rom, encrypted with the OA key.
   */
[Lines 81-84] Multi-line comment:
  /*
   * This data is not sensitive but hardly ever changes.
   * We store it in flash rom, unencrypted.
   */
[Lines 87-87] Multi-line comment:
  /* Names for our persistent data */
[Lines 100-100] Multi-line comment:
  /* Persistent data for signing and communications */
[Lines 104-109] Multi-line comment:
  /*
   * Blinding factors for our signing.  Array consists of entries
   * the size of the modulus, r^e and r_inv pairs, one for each
   * exponent.  Generated at keygen time and re-initialized on every
   * reboot.
   */
[Lines 112-112] Multi-line comment:
  /* Pubkey version of our signing keyid, computed at keygen and reboot */
[Lines 116-116] Multi-line comment:
  /* Set of public keys we support */
[Lines 117-117] Multi-line comment:
  /* Actual size of pkeys array is npkeys entries */
[Lines 122-122] Multi-line comment:
  /* Cardid field is also saved with pubkeys structure in flash memory */
[Lines 123-123] Multi-line comment:
  /* Card ID is unique across all IBM 4758 cards */
[Lines 124-124] Multi-line comment:
  /* And also across all re-initializations of the rpow program */
[Lines 127-127] Multi-line comment:
  /* powresource field is based on cardid and ".rpow.net" */
[Lines 132-132] Multi-line comment:
  /* Compute keyid for pubkey */
[Lines 162-162] Multi-line comment:
  /* Called to set up the pubkeys array on reboot */
[Lines 193-193] Multi-line comment:
  	/* Convert cardid to powresource */
[Lines 207-207] Multi-line comment:
  /* Called to init the pubkeys value on fresh start */
[Lines 221-225] Multi-line comment:
  /*
   * Set the cardid and powresource variables.
   * Cardid includes the AdapterID and the boot count when the OA cert
   * was made.
   */
[Lines 248-248] Multi-line comment:
  	/* Set the powresource (note, this code is duplicated above) */
[Lines 260-260] Multi-line comment:
  	/* Make sure we had enough room in powresource */
[Lines 268-268] Multi-line comment:
  /* Save the pubkeys data into flash */
[Lines 297-297] Multi-line comment:
  /* Called to add a new pubkey that we will support */
[Lines 298-298] Multi-line comment:
  /* This does not check for validity, that should be done before */
[Lines 299-299] Multi-line comment:
  /* We do check to make sure it is not a duplicate */
[Lines 317-317] Multi-line comment:
  	/* Check for duplicate keyid */
[Lines 324-324] Multi-line comment:
  	/* OK, add it */
[Lines 327-327] Multi-line comment:
  		/* Turn old signing key to ACTIVE */
[Lines 344-344] Multi-line comment:
  /* Change the state (enable/disable) of an existing key */
[Lines 364-364] Multi-line comment:
  	/* Can't change state of signing key */
[Lines 377-377] Multi-line comment:
  /* Add a new key which we are asked to trust as a signer */
[Lines 419-419] Multi-line comment:
  	/* Ignore first key */
[Lines 427-427] Multi-line comment:
  		/* Should not happen since we validated the cert chain */
[Lines 450-450] Multi-line comment:
  /* Find the pubkey in our list of trusted signers corresponding to the keyid */
[Lines 456-456] Multi-line comment:
  	/* Search from end to find newest first */
[Lines 474-474] Multi-line comment:
  /* Called on card reboot to get our secrets from flash memory */
[Lines 486-486] Multi-line comment:
  	/* Retrieve OA public key (in a malloc buffer) */
[Lines 490-490] Multi-line comment:
  	/* On a restart we must retrieve our secret prefix from flash */
[Lines 497-497] Multi-line comment:
  	/* Now we must decrypt it with our OA key */
[Lines 508-508] Multi-line comment:
  	/* Now we retrieve encrypted persistent keys from flash */
[Lines 517-517] Multi-line comment:
  	/* Decrypt them to memory */
[Lines 533-533] Multi-line comment:
  	/* Set up for pdata swappage */
[Lines 548-557] Multi-line comment:
  /*
   * Store our secrets into the flash memory so that we can retrieve
   * them on reboot after power off.
   * We encrypt the secrets using the OA key, ensuring that after any reload
   * of OS or application, which wipes the OA private key, our other secrets
   * are permanently erased.
   * We call this whenever we make a change to the secret data, such as after
   * keygen or also after adding a new database fileid, because those have
   * secret hash prefixes.
   */
[Lines 569-569] Multi-line comment:
  	/* Retrieve OA public key (in a malloc buffer) */
[Lines 573-573] Multi-line comment:
  	/* Choose a random tdes key */
[Lines 576-576] Multi-line comment:
  	/* Now encrypt the data using our OA key */
[Lines 578-578] Multi-line comment:
  	/* Make sdata be legal for RSA operations */
[Lines 596-596] Multi-line comment:
  	/* Store the encrypted prefix+key in flash */
[Lines 604-604] Multi-line comment:
  	/* Encrypt our persistent signing keys for flash */
[Lines 615-615] Multi-line comment:
  	/* Store encrypted persistent rpow keys in flash */
[Lines 630-630] Multi-line comment:
  /* Call periodically to swap pdata1 and pdata2 to prevent memory burn-in */
[Lines 644-644] Multi-line comment:
  	/* Note that PDATALEN(pdata) is not reliable in the loop */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/scc/rpio.c
--------------------------------------------------------------------------------
[Lines 1-4] Multi-line comment:
  /*
   * rpio.c
   *	Low level I/O for rpow package
   */
[Lines 87-87] Multi-line comment:
  /* gbignum I/O */
[Lines 119-119] Multi-line comment:
  	if (len > 2048/8)		/* Limit size of data we try to read */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/scc/rpow.c
--------------------------------------------------------------------------------
[Lines 1-4] Multi-line comment:
  /*
   * rpow.c
   *	Reusable Proof of Work implementation for IBM 4758
   */
[Lines 10-10] Multi-line comment:
  /* Toggle persistent data to prevent burn-in every this many calls */
[Lines 13-13] Multi-line comment:
  /* Reset unused POW database field, check at least once every few days */
[Lines 16-16] Multi-line comment:
  /* Time out on waiting for a call this often, to allow burn-in prevention */
[Lines 19-19] Multi-line comment:
  /* Size of RSA keys we gen for comm and for signing */
[Lines 60-60] Multi-line comment:
  	/* General initialization - setup bignum lib */
[Lines 63-63] Multi-line comment:
  	/* Look for an OA cert.  These get wiped on reload, so if it is present */
[Lines 64-64] Multi-line comment:
  	/* then we are just rebooting, and if it is absent this is a fresh load. */
[Lines 69-77] Multi-line comment:
  		/*
  		 * Having no cert means that we have been freshly loaded, or there has
  		 * been a configuration change (because our certified key is
  		 * created as a configuration key, it goes inactive on any reload
  		 * of the application or the OS).  We will treat this as an initial
  		 * boot.  It shouldn't be necessary, but for safety we will delete
  		 * all our persistent data now.  The INITKEYGEN command must be given to
  		 * reinitialize everything.
  		 */
[Lines 82-82] Multi-line comment:
  		/* Finding a cert means we are restarting in a valid state */
[Lines 87-87] Multi-line comment:
  			/* On failure, force re-initialization */
[Lines 97-99] Multi-line comment:
  		/*
  		* Get the next SCC message header
  		*/
[Lines 102-102] Multi-line comment:
  		/* Periodically swap our keys in DRAM to prevent burn-in */
[Lines 111-111] Multi-line comment:
  			/*printf("sccGetNextHeader failed 0x%lx\n",rc)*/;
[Lines 136-136] Multi-line comment:
  				/* Eliminate old OA keys so we only have one active one */
[Lines 138-138] Multi-line comment:
  				/* Reset other old data */
[Lines 143-143] Multi-line comment:
  				/* Set up 3 POW dbs and an RPOW db */
[Lines 167-167] Multi-line comment:
  				/* Eliminate old OA key */
[Lines 201-203] Multi-line comment:
  				/* This value gets latched so this must be called after the
  				 * batteries are changed.
  				 */
[Lines 216-216] Multi-line comment:
  /* Find an active application configuration key and return its name */
[Lines 217-217] Multi-line comment:
  /* Return -1 if we can't find one, 0 on success */
[Lines 259-259] Multi-line comment:
  /* Eliminate other SEG3 certs, active or inactive */
[Lines 298-298] Multi-line comment:
  /* Return general status information on the card, memory usage, battery state, etc. */
[Lines 385-385] Multi-line comment:
  	/* Encrypt data and return it */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/scc/rpowscc.h
--------------------------------------------------------------------------------
[Lines 1-4] Multi-line comment:
  /*
   * rpowscc.h
   *	Header file for SCC code of RPOW
   */
[Lines 30-30] Multi-line comment:
  /* Prefix used for hashing data we store in database */
[Lines 33-33] Multi-line comment:
  /* Hash size for data we store in database */
[Lines 54-54] Multi-line comment:
  /* Reusable proof of work */
[Lines 65-65] Multi-line comment:
  /* "Pending" RPOW, one waiting to be signed by the server */
[Lines 71-71] Multi-line comment:
  /* rpio.c */
[Lines 84-84] Multi-line comment:
  /* keygen.c */
[Lines 86-92] Multi-line comment:
  /*
   * Persistent data.
   * This data is sensitive but hardly ever changes.
   * We store it in flash rom, encrypted with the OA key.
   * The tdkey is used to encrypt our rpow signature data we store in
   * flash.
   */
[Lines 99-103] Multi-line comment:
  /*
   * We store persistent data encrypted in flash, and also two copies in
   * DRAM memory.  One copy is xored with FF's.  Every so often we switch
   * copies.  This is hoped to prevent memory burn-in.
   */
[Lines 115-115] Multi-line comment:
  	unsigned char			prefix[PREFIXSIZE];		/* actually nprefixes*PREFIXSIZE */
[Lines 123-123] Multi-line comment:
  /* Pubkey version of our signing key, includes our signing keyid */
[Lines 126-126] Multi-line comment:
  /* Card ID is unique among all cards; taken from AdapterInfo_t structure */
[Lines 129-129] Multi-line comment:
  /* Our hashcash resource string, based on cardid, null terminated */
[Lines 132-132] Multi-line comment:
  /* Flag values for dokeygen */
[Lines 142-142] Multi-line comment:
  /* rpowsign.c */
[Lines 147-147] Multi-line comment:
  /* rpowutil.c */
[Lines 158-158] Multi-line comment:
  /* persist.c */
[Lines 172-172] Multi-line comment:
  /* dbverify.c */
[Lines 181-181] Multi-line comment:
  /* certvalid.c */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/scc/rpowsign.c
--------------------------------------------------------------------------------
[Lines 1-4] Multi-line comment:
  /*
   * rpowsign.c
   *	Perform the signature function for RPOW
   */
[Lines 8-8] Multi-line comment:
  /* Maximum allowed rpows at a time */
[Lines 15-15] Multi-line comment:
  /* Implement the rpow signature function */
[Lines 42-42] Multi-line comment:
  	/* First do the RSA decryption on input data */
[Lines 46-46] Multi-line comment:
  	/* Then the TDES decryption on the rest */
[Lines 59-59] Multi-line comment:
  	/* Create our pointer for reading from this buffer */
[Lines 60-60] Multi-line comment:
  	/* buf now belongs to this rpio */
[Lines 82-82] Multi-line comment:
  	/* Read and verify the incoming rpows */
[Lines 91-91] Multi-line comment:
  			/* Check the seen-rpow database */
[Lines 94-94] Multi-line comment:
  				return rc;			/* host lied, should not happen */
[Lines 121-121] Multi-line comment:
  	/* Read the outgoing rpowpend values to be signed */
[Lines 132-132] Multi-line comment:
  	/* Make sure the incoming value == outgoing */
[Lines 139-139] Multi-line comment:
  	/* Everything is OK, sign the requested values */
[Lines 142-142] Multi-line comment:
  		/* Compute rpend[i]->rpow^d mod n using the CRT */
[Lines 155-155] Multi-line comment:
  	/* Prepare to write results to caller */
[Lines 220-220] Multi-line comment:
  /* Do a sign operation using the specified exponent */
[Lines 230-230] Multi-line comment:
  	/* Copy dp and dq to the key */
[Lines 236-236] Multi-line comment:
  	/* Copy blinding factors to the key */
[Lines 242-242] Multi-line comment:
  	/* Check for input value of 0 - defense against timing attacks */
[Lines 250-250] Multi-line comment:
  	/* Put val into buffer */
[Lines 266-266] Multi-line comment:
  	/* Copy blinding factors out of the key */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/scc/rpowutil.c
--------------------------------------------------------------------------------
[Lines 1-4] Multi-line comment:
  /*
   * rpowutil.c
   *	Generate, read and write reusable proof of work tokens
   */
[Lines 8-27] Multi-line comment:
  /*
   * RPOW tokens come in two types.  In transit they are preceded by a type
   * byte and then a four byte value field, which is the equivalent of the
   * hashcash collision size, and must be in the range RPOW_VALUE_MIN to
   * RPOW_VALUE_MAX.  The hashcash type (type 2) then has a four byte length
   * field, and then a version 1 hashcash stamp.  The value in the stamp
   * should equal the earlier value field.
   *
   * The reusable type (type 1) then has a 20 byte keyid.  This is the hash of
   * the public key which issued the token.  It then has a 34 byte token id,
   * of which the last 14 bytes must match the cardid of this card.  Then comes
   * a value signed by the public key identified by the keyid.  The signed
   * value is in a bignum format where it is preceded by a 4-byte byte count.
   * The plaintext of that value consists of the 20 byte SHA-1 hash of the
   * token id, then the byte 2, then is padded to the width of the signing key's
   * modulus modulus.  The padding is done by repeatedly SHA-1 hashing what
   * we have so far and appending the hash, until we have the width we need
   * (the last append just uses the leftmost bytes of the hash).  We then
   * take that value mod the signing key's modulus.  This is what is signed.
   */
[Lines 39-39] Multi-line comment:
  /* Quick and dirty test for primality */
[Lines 54-54] Multi-line comment:
  /* Find the exponent corresponding to the given value */
[Lines 55-55] Multi-line comment:
  /* Exponents are consecutive primes starting with pk->e */
[Lines 64-64] Multi-line comment:
  		/* First time; fill exptab with consecutive primes */
[Lines 82-82] Multi-line comment:
  /* Read an rpow value */
[Lines 131-131] Multi-line comment:
  /* Write out an rpow value */
[Lines 147-147] Multi-line comment:
  	} else {	/* rp->type == RPOW_TYPE_RPOW */
[Lines 159-159] Multi-line comment:
  /* Free an rpow */
[Lines 170-170] Multi-line comment:
  /* Generate the rpow field of an rpowpend */
[Lines 193-193] Multi-line comment:
  /* Read an rpowpend written by rpowpend_write */
[Lines 216-216] Multi-line comment:
  /* Free an rpowpend */
[Lines 225-227] Multi-line comment:
  /*
   * Validate a POW or RPOW token.  As a side effect, set the fileid.
   */
[Lines 237-237] Multi-line comment:
  /* Given a POW token (hashcash version 1), parse out the fields */
[Lines 238-238] Multi-line comment:
  /* Example:  1:15:040719:rpow.net::9e6c82f8e4727a6d:1ec4 */
[Lines 239-239] Multi-line comment:
  /* The pointers returned are pointers into the input str */
[Lines 240-240] Multi-line comment:
  /* str does not have to be null terminated */
[Lines 241-241] Multi-line comment:
  /* Return error if no good */
[Lines 318-318] Multi-line comment:
  	/* Parse the POW and see if its fields are legal */
[Lines 332-332] Multi-line comment:
  	/* Now test the hash to see if it has the right number of high 0's */
[Lines 340-340] Multi-line comment:
  	/* Set the fileid from the month field */
[Lines 362-362] Multi-line comment:
  	/* We only accept id's for our cardid */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/server/dbproof.c
--------------------------------------------------------------------------------
[Lines 1-7] Multi-line comment:
  /*
   * dbproof.c
   *	Maintain a database of used items on behalf of a remote host,
   *  proving correctness of operations to that host even though it
   *	does not have the ability to remember more than a few bytes about
   *	the whole database.
   */
[Lines 29-46] Multi-line comment:
  /*
  
  Now we are going to use M-ary trees rather than binary.
  We are also going to take out locking; our current architecture will
  be basically single threaded, and if we support multiple servers each
  will have its own spent list(s).
  
  This will use true B-trees.  Each node will have between NODEKEYS/2 and
  NODEKEYS keys, except the top node which may have fewer.  Also we will
  possibly change the top node.
  
  Clean up use of multiple files, one for inner nodes and one for bottom
  nodes.  Eliminate our hash prefix, not necessary with btrees.
  
  Add evidence field (nodinfo) for use in proving to a third party that the
  DB is being maintained consistently.
  
  */
[Lines 48-48] Multi-line comment:
  /* Number of keys per node, must be even */
[Lines 59-59] Multi-line comment:
  /* Compressed nodes have variable-sized array */
[Lines 69-69] Multi-line comment:
  /* We allow NODEKEYS+1 keys in a node temporarily but will split it */
[Lines 71-71] Multi-line comment:
  									/* leafnode must prefix innernode */
[Lines 72-72] Multi-line comment:
  	ulong nkeys;					/* Number of keys in node */
[Lines 73-73] Multi-line comment:
  	uchar key[NODEKEYS+1][HASHSIZE];	/* Keys are kept sorted */
[Lines 75-75] Multi-line comment:
  	ulong child[NODEKEYS+2];		/* Node number in file of children */
[Lines 79-79] Multi-line comment:
  	ulong nkeys;					/* Number of keys in node */
[Lines 80-80] Multi-line comment:
  	uchar key[NODEKEYS+1][HASHSIZE];	/* Keys are kept sorted */
[Lines 83-83] Multi-line comment:
  /* Compressed nodes are what are put into the nodeinfo array */
[Lines 87-87] Multi-line comment:
  	uchar hashdata[1][HASHSIZE];	/* Actually 2*nkeys+1 hashes */
[Lines 88-88] Multi-line comment:
  									/* First, nkeys key hashes, then */
[Lines 89-89] Multi-line comment:
  									/* if non-leaf, nkeys+1 childhashes */
[Lines 94-94] Multi-line comment:
  	int fdi;		/* inner nodes */
[Lines 95-95] Multi-line comment:
  	int fdl;		/* leaf nodes */
[Lines 96-96] Multi-line comment:
  	int depth;		/* Depth of tree */
[Lines 97-97] Multi-line comment:
  	int rootnode;	/* Root node number in fdi file */
[Lines 98-98] Multi-line comment:
  	innernode newnode;	/* Used and re-used for adding nodes to the tree */
[Lines 99-99] Multi-line comment:
  						/* Remainder is used for proof of validity */
[Lines 102-102] Multi-line comment:
  	uchar treehash[HASHSIZE];	/* for testing */
[Lines 103-103] Multi-line comment:
  	int treedepth;				/* for testing */
[Lines 129-134] Multi-line comment:
  /*
   * See if a key is in a node.  Return true if it is, and set *keyind to the
   * index number of the key (0 to NODEKEYS-1).  Return false if it is not,
   * and set *keyind to the index number of the space between the keys where
   * it would go (0 to NODEKEYS).
   */
[Lines 143-143] Multi-line comment:
  	/* Binary search */
[Lines 167-167] Multi-line comment:
  /* Functions to seek to, read from and write to a node */
[Lines 213-213] Multi-line comment:
  /* Debugging */
[Lines 214-214] Multi-line comment:
  /* Was having some weird timing problems when rapidly filling the db */
[Lines 237-241] Multi-line comment:
  /*
   * Return 1 if present, 0 if was absent.  If set is true, add it if absent.
   * Also return *proof and *prooflen as a buffer (within proofdb) which proves
   * our correctness.
   */
[Lines 259-259] Multi-line comment:
  	/* Set things up for validity proof */
[Lines 263-263] Multi-line comment:
  	/* Do the recursive search */
[Lines 276-276] Multi-line comment:
  	/* Must create new top node because old top filled up and split */
[Lines 288-288] Multi-line comment:
  	/* Write out new top node */
[Lines 294-294] Multi-line comment:
  	/* Put its position in block 0 */
[Lines 310-320] Multi-line comment:
  /*
   * Search the tree starting at the node with number nodepos.  Return 1
   * if newhash is found, 0 if it was not found.  If it was not found and
   * set is true, insert it in the tree.  Insertion may require node
   * splitting.  If that happens, we set *pnewnodenum to the number of the
   * new node (which will be the right sibling of the existing node).
   * We set splitkey to be the key at which we split, the middle key, which
   * is supposed to move up into the parent node.  And we set newnodehash
   * to be the hash of the new node.  Also if we made a change to the
   * existing node, we set thisnodehash to the new hash of the node.
   */
[Lines 341-341] Multi-line comment:
  	/* Save data in nodeinfo chain for later proof of correctness */
[Lines 359-359] Multi-line comment:
  		/* Done, unfound, if not inserting */
[Lines 363-363] Multi-line comment:
  		/* Leaf node, just add data */
[Lines 368-368] Multi-line comment:
  		/* Traverse the tree */
[Lines 380-380] Multi-line comment:
  			/* No split below us, just write out with our updated hash */
[Lines 386-386] Multi-line comment:
  			/* And update our parent's hash */
[Lines 391-391] Multi-line comment:
  		/* Child did a split, newnode is to the right of the old one */
[Lines 403-403] Multi-line comment:
  	/* Now split our node if it is too full */
[Lines 404-404] Multi-line comment:
  	/* We move one key up (to splitkey) and put NODEKEYS/2 in this one and */
[Lines 405-405] Multi-line comment:
  	/* the new one.  The new node gets the higher value keys and is the */
[Lines 406-406] Multi-line comment:
  	/* right sibling of the existing node. */
[Lines 426-426] Multi-line comment:
  		/* Write the old node first, then the new one */
[Lines 436-436] Multi-line comment:
  		/* And update parent's hashes */
[Lines 442-442] Multi-line comment:
  		/* No split needed, just write the old node */
[Lines 443-443] Multi-line comment:
  		*pnewnodenum = 0;		/* Flag that no splits were done here */
[Lines 450-450] Multi-line comment:
  		/* And update parent hash */
[Lines 458-458] Multi-line comment:
  /* Hash the given node key and childhash data (if nonleaf) and return result */
[Lines 475-475] Multi-line comment:
  /* Compute 128 bit hash of node keys and their subtrees */
[Lines 484-484] Multi-line comment:
  /*****************************  VALIDATE  *******************************/
[Lines 487-498] Multi-line comment:
  /*
  
  The idea here is that an untrusted system can maintain the DB, and provide
  evidence to a second system as to whether any given item is found or not
  (and added if missing).  The second system maintains a hash over the
  whole DB, following the btree structure.  It checks the returned evidence
  data against the hash to make sure it matches, verifies that the evidence
  does in fact prove presence or absence, and if adding, independently
  calculates the updated hash, using an algorithm that mirrors that done on
  the untrusted system.
  
  */
[Lines 501-501] Multi-line comment:
  /* Arrays to give room to expand our nodes */
[Lines 505-509] Multi-line comment:
  /*
   * Return true if valid, false if not.  Return *found as true if we found
   * the data item (if we are returning valid).
   * Update treehash if set is true and not found (and valid).
   */
[Lines 519-540] Multi-line comment:
  /*
  	First test: that each node either matches newhash on key[keyind] (in which
  	case it is found) or else newhash is between key[keyind] and key[keyind+1]
  	(or if keyind == nkeys-1 then newhash is above key[keyind]).
  
  	Second test: that hashing each node produces the parent childhash field.
  
  	Third test: that hashing the root node produces our saved treehash.
  
  	Given all these three tests, we validate the presence/absence of the
  	item.  If found, or if set is false, we are done.
  
  	Otherwise we have to do updates and ultimately we are updating treehash.
  	To do the updates we insert the new node data where it should go, and
  	split the node if necessary.
  
  	For recursive testing, first check the tree hash at the top level.
  	Then at each level first test the keyind value, then test the childhash
  	of the next level (if recursing).  I.e. before recursing check the
  	childhash to make sure it is as expected.  Thus we validate each data
  	before trusting it.
  */
[Lines 554-554] Multi-line comment:
  	/* Must create new top node because old top filled up and split */
[Lines 555-555] Multi-line comment:
  	/* Top node has only one item, the splitkey, and two hashes */
[Lines 556-556] Multi-line comment:
  	/* We only need to update the treehash from it */
[Lines 581-581] Multi-line comment:
  	/* Pick up values from compnode */
[Lines 594-594] Multi-line comment:
  	/* Verify that this node's data matches expected hash */
[Lines 600-600] Multi-line comment:
  	/* Validate that keyind is correct */
[Lines 621-621] Multi-line comment:
  		/* Done, unfound, if not inserting */
[Lines 628-628] Multi-line comment:
  		/* Leaf node, just add the data */
[Lines 635-635] Multi-line comment:
  		/* Recurse */
[Lines 638-638] Multi-line comment:
  		childnodehash = node->hashdata[nkeys+keyind];	/* childhash field */
[Lines 651-651] Multi-line comment:
  			/* No split below us, just update our changed hash upwards */
[Lines 657-657] Multi-line comment:
  		/* Child did a split, new node is to right of old one */
[Lines 669-669] Multi-line comment:
  	/* Now split our node if it is too full */
[Lines 670-670] Multi-line comment:
  	/* We move one key up (to splitkey) and put NODEKEYS/2 in this one and */
[Lines 671-671] Multi-line comment:
  	/* the new one.  The new node gets the higher value keys and is the */
[Lines 672-672] Multi-line comment:
  	/* right sibling of the existing node. */
[Lines 680-680] Multi-line comment:
  		/* Now hash the split data into the two parent fields */
[Lines 685-685] Multi-line comment:
  		/* No split was done, just update parent hash */
[Lines 693-696] Multi-line comment:
  /*
   * Local test of the validity verification.
   * Resets treehash and maxdepth just as the remote host should.
   */
[Lines 722-722] Multi-line comment:
  /*****************************  DEBUG  *******************************/
[Lines 724-724] Multi-line comment:
  /* For debugging */
[Line 740] Single-line comment:
  //		for (j=0; j<depth; j++)
[Line 741] Single-line comment:
  //			fprintf (f, " ");
[Lines 816-816] Multi-line comment:
  /*****************************  INIT  *******************************/
[Lines 825-825] Multi-line comment:
  	/* First leaf node block is unused */
[Lines 828-828] Multi-line comment:
  	/* First leaf node starts off empty */
[Lines 831-831] Multi-line comment:
  	/* Top inner node just points at root inner node */
[Lines 832-832] Multi-line comment:
  	/* And encodes depth in child[1] */
[Lines 837-837] Multi-line comment:
  	/* Root node will start pointing at leaf */
[Lines 843-843] Multi-line comment:
  	/* Set top level hash for testing validation */
[Lines 850-853] Multi-line comment:
  /*
   * Open the database file of the specified name.
   * Create it if it doesn't exist.
   */
[Lines 873-873] Multi-line comment:
  		/* First entry is dummy and just holds top node pointer and depth */
[Lines 882-882] Multi-line comment:
  	/* Failed to open DB, try creating it */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/server/dbproof.h
--------------------------------------------------------------------------------
[Lines 4-7] Multi-line comment:
  /*
   * dbproof.h
   *	Maintain database for remote host in a provable way
   */
[Lines 13-13] Multi-line comment:
  /* The database holds values of size HASHSIZE */
[Lines 16-21] Multi-line comment:
  /*
   * Return 1 if present, 0 if was absent.  If set is true, add it if absent.
   * Return *proof and *prooflen as a buffer that proves our correct operation,
   * suitable for presenting to the remote host where a verification algorithm
   * can confirm that we are operating properly.
   */
[Lines 28-28] Multi-line comment:
  /* Return the depth of the DB btree */
[Lines 31-34] Multi-line comment:
  /*
   * Locally test the validity proof; the exact same algorithm should be
   * used by the remote host.
   */
[Lines 38-42] Multi-line comment:
  /*
   * Open the database file of the specified name.
   * Create it if it doesn't exist.
   * Another file with extension .vals added is also used.
   */
[Lines 47-47] Multi-line comment:
  #endif /* DBPROOF_H */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/server/gbignum.h
--------------------------------------------------------------------------------
[Lines 1-1] Multi-line comment:
  /* Generic bignum module, wrappers around other bignum libraries */
[Lines 15-15] Multi-line comment:
  #endif /* SHA1_DIGEST_LENGTH */
[Lines 96-96] Multi-line comment:
  #endif /* GBIGNUM_H */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/server/rpowsrv.c
--------------------------------------------------------------------------------
[Lines 1-8] Multi-line comment:
  /*
   * rpowsrv.c
   *	Host server for RPOW package
   *
   *	This runs on the host, listens for network connections,
   *	and communicates with the RPOW server running on an IBM 4758
   *	Secure Cryptographic Coprocessor card.
   */
[Lines 59-59] Multi-line comment:
  /* Bit size of RSA key used to secure communication */
[Lines 62-62] Multi-line comment:
  /* For blocksigs() */
[Lines 66-66] Multi-line comment:
  /* How long to wait on incoming connections */
[Lines 117-117] Multi-line comment:
  /* Return how many DB files (consecutively numbered from 0) are in the CWD */
[Lines 161-161] Multi-line comment:
  		/* Discard first two arguments */
[Lines 563-563] Multi-line comment:
  	/* Read certificate chain file for responding to requests */
[Lines 572-572] Multi-line comment:
  	/* Open DBs */
[Lines 588-588] Multi-line comment:
  	/* Begin listening on socket */
[Lines 611-611] Multi-line comment:
  		/* Handle commands */
[Lines 684-684] Multi-line comment:
  			/* Return reply to the client */
[Line 721] Single-line comment:
  // holds profile timing
[Lines 734-734] Multi-line comment:
  			/* Handle database queries from card */
[Lines 737-737] Multi-line comment:
  				/* We expect to get a hash back */
[Lines 745-745] Multi-line comment:
  				/* Now we query our database to see if the item is present */
[Lines 760-760] Multi-line comment:
  				/* Send the proof */
[Lines 768-768] Multi-line comment:
  				/* Get back the card's official answer */
[Line 775] Single-line comment:
  // holds profile timing
[Lines 789-789] Multi-line comment:
  			/* Send card status preceding reply message if any */
[Lines 800-800] Multi-line comment:
  			/* Return reply to the client */
[Lines 813-813] Multi-line comment:
  	/* never gets here */
[Line 838] Single-line comment:
  //		printf ("%02x%s", buf[i], ((i+1)%16 == 0) ? "\n" : " ");
[Lines 846-846] Multi-line comment:
  /* Read until we reach count bytes, or error */
[Lines 953-953] Multi-line comment:
  /* Block or unblock signals */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/server/sha.h
--------------------------------------------------------------------------------
[Lines 1-25] Multi-line comment:
  /*
   * sha.h
   *
   * Originally taken from the public domain SHA1 implementation
   * written by by Steve Reid <steve@edmweb.com>
   *
   * Modified by Aaron D. Gifford <agifford@infowest.com>
   *
   * NO COPYRIGHT - THIS IS 100% IN THE PUBLIC DOMAIN
   *
   * The original unmodified version is available at:
   *    ftp://ftp.funet.fi/pub/crypt/hash/sha/sha1.c
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) AND CONTRIBUTORS ``AS IS'' AND
   * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR(S) OR CONTRIBUTORS BE LIABLE
   * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
   * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
   * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
   * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
   * SUCH DAMAGE.
   */
[Lines 34-34] Multi-line comment:
  /* Define this if your machine is LITTLE_ENDIAN, otherwise #undef it: */
[Lines 39-39] Multi-line comment:
  /* Make sure you define these types for your architecture: */
[Lines 40-40] Multi-line comment:
  typedef unsigned long sha1_quadbyte;     /* 4 byte type */
[Lines 41-41] Multi-line comment:
  typedef unsigned char sha1_byte;	/* single byte type */
[Lines 43-49] Multi-line comment:
  /*
   * Be sure to get the above definitions right.  For instance, on my
   * x86 based FreeBSD box, I define LITTLE_ENDIAN and use the type
   * "unsigned long" for the quadbyte.  On FreeBSD on the Alpha, however,
   * while I still use LITTLE_ENDIAN, I must define the quadbyte type
   * as "unsigned int" instead.
   */
[Lines 54-54] Multi-line comment:
  /* The SHA1 structure: */

File: /home/user/bitcoinArchive/precursor/rpow-1.2.0/server/sha1.c
--------------------------------------------------------------------------------
[Lines 1-24] Multi-line comment:
  /*
   * sha1.c
   *
   * Originally witten by Steve Reid <steve@edmweb.com>
   *
   * Modified by Aaron D. Gifford <agifford@infowest.com>
   *
   * NO COPYRIGHT - THIS IS 100% IN THE PUBLIC DOMAIN
   *
   * The original unmodified version is available at:
   *    ftp://ftp.funet.fi/pub/crypt/hash/sha/sha1.c
   *
   * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) AND CONTRIBUTORS ``AS IS'' AND
   * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR(S) OR CONTRIBUTORS BE LIABLE
   * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
   * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
   * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
   * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
   * SUCH DAMAGE.
   */
[Lines 30-30] Multi-line comment:
  /* blk0() and blk() perform the initial expand. */
[Lines 31-31] Multi-line comment:
  /* I got the idea of expanding during the round function from SSLeay */
[Lines 43-43] Multi-line comment:
  /* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
[Lines 55-55] Multi-line comment:
  /* Hash a single 512-bit block. This is the core of the algorithm. */
[Lines 61-61] Multi-line comment:
  	/* Copy context->state[] to working vars */
[Lines 67-67] Multi-line comment:
  	/* 4 rounds of 20 operations each. Loop unrolled. */
[Lines 88-88] Multi-line comment:
  	/* Add the working vars back into context.state[] */
[Lines 94-94] Multi-line comment:
  	/* Wipe variables */
[Lines 99-99] Multi-line comment:
  /* SHA1_Init - Initialize new context */
[Lines 101-101] Multi-line comment:
  	/* SHA1 initialization constants */
[Lines 110-110] Multi-line comment:
  /* Run your data through this. */
[Lines 130-130] Multi-line comment:
  /* Add padding and return the message digest. */
[Lines 137-137] Multi-line comment:
  	     >> ((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
[Lines 143-143] Multi-line comment:
  	/* Should cause a SHA1_Transform() */
[Lines 149-149] Multi-line comment:
  	/* Wipe variables */


================================================================================
EXTRACTION COMPLETE
================================================================================
