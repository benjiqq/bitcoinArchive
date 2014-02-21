// Copyright (c) 2008 Satoshi Nakamoto
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "headers.h"
#include "sha.h"





//
// Global state
//

map<uint256, CTransaction> mapTransactions;
CCriticalSection cs_mapTransactions;
unsigned int nTransactionsUpdated = 0;
/// mapNextTx is only used anymore to track disk tx outpoints used by memory txes
map<COutPoint, CInPoint> mapNextTx;

map<uint256, CBlockIndex*> mapBlockIndex;
const uint256 hashGenesisBlock("0x000006b15d1327d67e971d1de9116bd60a3a01556c91b6ebaa416ebc0cfaa646");
CBlockIndex* pindexGenesisBlock = NULL;
int nBestHeight = -1;
uint256 hashTimeChainBest = 0;
CBlockIndex* pindexBest = NULL;

map<uint256, CBlock*> mapOrphanBlocks;
multimap<uint256, CBlock*> mapOrphanBlocksByPrev;

map<uint256, CWalletTx> mapWallet;
vector<pair<uint256, bool> > vWalletUpdated;
CCriticalSection cs_mapWallet;

map<vector<unsigned char>, CPrivKey> mapKeys;
map<uint160, vector<unsigned char> > mapPubKeys;
CCriticalSection cs_mapKeys;
CKey keyUser;

int fGenerateBitcoins;












//////////////////////////////////////////////////////////////////////////////
//
// mapKeys
//

bool AddKey(const CKey& key)
{
    CRITICAL_BLOCK(cs_mapKeys)
    {
        mapKeys[key.GetPubKey()] = key.GetPrivKey();
        mapPubKeys[Hash160(key.GetPubKey())] = key.GetPubKey();
    }
    return CWalletDB().WriteKey(key.GetPubKey(), key.GetPrivKey());
}

vector<unsigned char> GenerateNewKey()
{
    CKey key;
    key.MakeNewKey();
    if (!AddKey(key))
        throw runtime_error("GenerateNewKey() : AddKey failed\n");
    return key.GetPubKey();
}




//////////////////////////////////////////////////////////////////////////////
//
// mapWallet
//

bool AddToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    CRITICAL_BLOCK(cs_mapWallet)
    {
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        bool fInsertedNew = ret.second;

        //// debug print
        printf("AddToWallet %s  %d\n", wtxIn.GetHash().ToString().c_str(), fInsertedNew);

        if (!fInsertedNew)
        {
            // Merge
            bool fUpdated = false;
            if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
            if (wtxIn.fSpent && wtxIn.fSpent != wtx.fSpent)
            {
                wtx.fSpent = wtxIn.fSpent;
                fUpdated = true;
            }
            if (!fUpdated)
                return true;
        }

        // Write to disk
        if (!wtx.WriteToDisk())
            return false;

        // Notify UI
        vWalletUpdated.push_back(make_pair(hash, fInsertedNew));
    }

    // Refresh UI
    MainFrameRepaint();
    return true;
}

bool AddToWalletIfMine(const CTransaction& tx, const CBlock* pblock)
{
    if (tx.IsMine())
    {
        CWalletTx wtx(tx);
        if (pblock)
        {
            wtx.hashBlock = pblock->GetHash();
            wtx.nTime = pblock->nTime;
        }
        else
        {
            wtx.nTime = GetAdjustedTime();
        }
        return AddToWallet(wtx);
    }
    return true;
}

void ReacceptWalletTransactions()
{
    // Reaccept any txes of ours that aren't already in a block
    CRITICAL_BLOCK(cs_mapWallet)
    {
        CTxDB txdb("r");
        foreach(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            if (!txdb.ContainsTx(wtx.GetHash()))
                wtx.AcceptWalletTransaction(txdb, false);
        }
    }
}

void RelayWalletTransactions()
{
    static int64 nLastTime;
    if (GetTime() - nLastTime < 15 * 60)
        return;
    nLastTime = GetTime();

    // Rebroadcast any of our txes that aren't in a block yet
    CRITICAL_BLOCK(cs_mapWallet)
    {
        CTxDB txdb("r");
        foreach(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
            item.second.RelayWalletTransaction(txdb);
    }
}











//////////////////////////////////////////////////////////////////////////////
//
// CTransaction
//

bool CTxIn::IsMine() const
{
    map<uint256, CWalletTx>::iterator mi = mapWallet.find(prevout.hash);
    if (mi != mapWallet.end())
    {
        const CWalletTx& prev = (*mi).second;
        if (prevout.n < prev.vout.size())
            if (prev.vout[prevout.n].IsMine())
                return true;
    }
    return false;
}

int64 CTxIn::GetDebit() const
{
    map<uint256, CWalletTx>::iterator mi = mapWallet.find(prevout.hash);
    if (mi != mapWallet.end())
    {
        const CWalletTx& prev = (*mi).second;
        if (prevout.n < prev.vout.size())
            if (prev.vout[prevout.n].IsMine())
                return prev.vout[prevout.n].nValue;
    }
    return 0;
}




int CMerkleTx::SetMerkleBranch()
{
    if (fClient)
    {
        if (hashBlock == 0)
            return 0;
    }
    else
    {
        // Load the block this tx is in
        CDiskTxPos pos;
        if (!CTxDB("r").ReadTxPos(GetHash(), pos))
            return 0;
        CBlock block;
        if (!block.ReadFromDisk(pos.nFile, pos.nBlockPos, true))
            return 0;

        // Update the tx's hashBlock
        hashBlock = block.GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < block.vtx.size(); nIndex++)
            if (block.vtx[nIndex] == *(CTransaction*)this)
                break;
        if (nIndex == block.vtx.size())
        {
            vMerkleBranch.clear();
            nIndex = -1;
            printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = block.GetMerkleBranch(nIndex);
    }

    // Is the tx in a block that's in the main chain
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return pindexBest->nHeight - pindex->nHeight + 1;
}

void CWalletTx::AddSupportingTransactions(CTxDB& txdb)
{
    vtxPrev.clear();

    const int COPY_DEPTH = 3;
    if (SetMerkleBranch() < COPY_DEPTH)
    {
        vector<uint256> vWorkQueue;
        foreach(const CTxIn& txin, vin)
            vWorkQueue.push_back(txin.prevout.hash);

        map<uint256, const CMerkleTx*> mapWalletPrev;
        set<uint256> setAlreadyDone;
        for (int i = 0; i < vWorkQueue.size(); i++)
        {
            uint256 hash = vWorkQueue[i];
            if (setAlreadyDone.count(hash))
                continue;
            setAlreadyDone.insert(hash);

            CMerkleTx tx;
            if (mapWallet.count(hash))
            {
                tx = mapWallet[hash];
                foreach(const CMerkleTx& txWalletPrev, mapWallet[hash].vtxPrev)
                    mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
            }
            else if (mapWalletPrev.count(hash))
            {
                tx = *mapWalletPrev[hash];
            }
            else if (!fClient && txdb.ReadDiskTx(hash, tx))
            {
                ;
            }
            else
            {
                printf("ERROR: AddSupportingTransactions() : unsupported transaction\n");
                continue;
            }

            int nDepth = tx.SetMerkleBranch();
            vtxPrev.push_back(tx);

            if (nDepth < COPY_DEPTH)
                foreach(const CTxIn& txin, tx.vin)
                    vWorkQueue.push_back(txin.prevout.hash);
        }
    }

    reverse(vtxPrev.begin(), vtxPrev.end());
}










bool CTransaction::DisconnectInputs(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool, bool fTest)
{
    // Relinquish previous transactions' posNext pointers
    if (!IsCoinBase())
    {
        foreach(const CTxIn& txin, vin)
        {
            COutPoint prevout = txin.prevout;

            CAutoFile fileout = NULL;
            CTransaction txPrevBuf;
            CTransaction& txPrev = (fTest ? mapTestPool[prevout.hash] : txPrevBuf);
            if (txPrev.IsNull())
            {
                // Get prev tx from disk
                // Version -1 tells unserialize to set version so we write back same version
                fileout.SetVersion(-1);
                if (!txdb.ReadDiskTx(prevout.hash, txPrev, &fileout))
                    return false;
            }

            if (prevout.n >= txPrev.vout.size())
                return false;

            // Relinquish posNext pointer
            txPrev.vout[prevout.n].posNext.SetNull();

            // Write back
            if (!fTest)
                fileout << txPrev;
        }
    }

    if (fTest)
    {
        // Put a blocked-off copy of this transaction in the test pool
        CTransaction& txPool = mapTestPool[GetHash()];
        txPool = *this;
        foreach(CTxOut& txout, txPool.vout)
            txout.posNext = CDiskTxPos(1, 1, 1);
    }
    else
    {
        // Remove transaction from index
        if (!txdb.EraseTxPos(*this))
            return false;

        // Resurect single transaction objects
        if (!IsCoinBase())
            AcceptTransaction(txdb, false);
    }

    return true;
}


bool CTransaction::ConnectInputs(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool, CDiskTxPos posThisTx, int nHeight,
                                 bool fTest, bool fMemoryTx, bool fIgnoreDiskConflicts, int64& nFees)
{
    // Take over previous transactions' posNext pointers
    if (!IsCoinBase())
    {
        int64 nValueIn = 0;
        for (int i = 0; i < vin.size(); i++)
        {
            COutPoint prevout = vin[i].prevout;

            CAutoFile fileout = NULL;
            CTransaction txPrevBuf;
            CTransaction& txPrev = (fTest ? mapTestPool[prevout.hash] : txPrevBuf);
            if (txPrev.IsNull() && fTest && fMemoryTx && mapTransactions.count(prevout.hash))
            {
                // Get prev tx from single transactions in memory
                txPrev = mapTransactions[prevout.hash];
            }
            else if (txPrev.IsNull())
            {
                // Get prev tx from disk
                // Version -1 tells unserialize to set version so we write back same version
                fileout.SetVersion(-1);
                if (!txdb.ReadDiskTx(prevout.hash, txPrev, &fileout))
                    return error("ConnectInputs() : prev tx not found");

                // If tx will only be connected in a reorg,
                // then these outpoints will be checked at that time
                if (fIgnoreDiskConflicts)
                    foreach(CTxOut& txout, txPrev.vout)
                        txout.posNext.SetNull();
            }

            if (prevout.n >= txPrev.vout.size())
                return false;

            // Verify signature
            if (!VerifySignature(txPrev, *this, i))
                return error("ConnectInputs() : VerifySignature failed");

            // Check for conflicts
            if (!txPrev.vout[prevout.n].posNext.IsNull())
                return error("ConnectInputs() : prev tx already used");

            // Flag outpoints as used
            txPrev.vout[prevout.n].posNext = posThisTx;

            // Write back
            if (!fTest)
                fileout << txPrev;

            nValueIn += txPrev.vout[prevout.n].nValue;
        }

        // Tally transaction fees
        int64 nTransactionFee = nValueIn - GetValueOut();
        if (nTransactionFee < 0)
            return false;
        nFees += nTransactionFee;
    }

    if (fTest)
    {
        // Add transaction to test pool
        mapTestPool[GetHash()] = *this;
    }
    else
    {
        // Add transaction to disk index
        if (!txdb.WriteTxPos(*this, posThisTx, nHeight))
            return false;

        // Delete redundant single transaction objects
        CRITICAL_BLOCK(cs_mapTransactions)
        {
            foreach(const CTxIn& txin, vin)
                mapNextTx.erase(txin.prevout);
            mapTransactions.erase(GetHash());
        }
    }

    return true;
}




bool CTransaction::AcceptTransaction(CTxDB& txdb, bool fCheckInputs)
{
    // Coinbase is only valid in a block, not as a loose transaction
    if (IsCoinBase())
        return error("AcceptTransaction() : coinbase as individual tx");

    if (!CheckTransaction())
        return error("AcceptTransaction() : CheckTransaction failed");

    uint256 hash = GetHash();
    if (mapTransactions.count(hash))
        return false;

    // Check for conflicts with in-memory transactions
    // and allow replacing with a newer version of the same transaction
    CTransaction* ptxOld = NULL;
    for (int i = 0; i < vin.size(); i++)
    {
        COutPoint outpoint = vin[i].prevout;
        if (mapNextTx.count(outpoint))
        {
            if (ptxOld == NULL)
            {
                ptxOld = mapNextTx[outpoint].ptx;
                if (!IsUpdate(*ptxOld))
                    return false;
            }
            else if (ptxOld != mapNextTx[outpoint].ptx)
                return false;
        }
    }

    // Check against previous transactions
    map<uint256, CTransaction> mapTestPool;
    int64 nFees = 0;
    if (fCheckInputs)
        if (!TestConnectInputs(txdb, mapTestPool, true, false, nFees))
            return error("AcceptTransaction() : TestConnectInputs failed");

    // Store transaction in memory
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        if (ptxOld)
        {
            printf("mapTransaction.erase(%s) replacing with new version\n", ptxOld->GetHash().ToString().c_str());
            mapTransactions.erase(ptxOld->GetHash());
        }
        //printf("mapTransaction.insert(%s)\n  ", hash.ToString().c_str());
        //print();
        mapTransactions[hash] = *this;
        for (int i = 0; i < vin.size(); i++)
            mapNextTx[vin[i].prevout] = CInPoint(&mapTransactions[hash], i);
    }

    // If updated, erase old tx from wallet
    if (ptxOld)
        CRITICAL_BLOCK(cs_mapWallet)
            mapWallet.erase(ptxOld->GetHash());

    nTransactionsUpdated++;
    return true;
}





int CMerkleTx::IsInMainChain() const
{
    if (hashBlock == 0)
        return 0;

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Get merkle root
    CBlock block;
    if (!block.ReadFromDisk(pindex, false))
        return 0;

    // Make sure the merkle branch connects to this block
    if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != block.hashMerkleRoot)
        return 0;

    return pindexBest->nHeight - pindex->nHeight + 1;
}



bool CMerkleTx::AcceptTransaction(CTxDB& txdb, bool fCheckInputs)
{
    if (fClient)
    {
        if (!IsInMainChain() && !ClientConnectInputs())
            return false;
        return CTransaction::AcceptTransaction(txdb, false);
    }
    else
    {
        return CTransaction::AcceptTransaction(txdb, fCheckInputs);
    }
}



bool CWalletTx::AcceptWalletTransaction(CTxDB& txdb, bool fCheckInputs)
{
    foreach(CMerkleTx& tx, vtxPrev)
    {
        uint256 hash = tx.GetHash();
        if (!mapTransactions.count(hash) && !txdb.ContainsTx(hash))
            tx.AcceptTransaction(txdb, fCheckInputs);
    }
    return AcceptTransaction(txdb, fCheckInputs);
}


void CWalletTx::RelayWalletTransaction(CTxDB& txdb)
{
    foreach(CMerkleTx& tx, vtxPrev)
    {
        uint256 hash = tx.GetHash();
        if (!txdb.ContainsTx(hash))
            RelayMessage(CInv(MSG_TX, hash), (CTransaction)tx);
    }
    uint256 hash = GetHash();
    if (!txdb.ContainsTx(hash))
        RelayMessage(CInv(MSG_TX, hash), (CTransaction)*this);
}










//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

bool CBlock::ReadFromDisk(const CBlockIndex* pblockindex, bool fReadTransactions)
{
    return ReadFromDisk(pblockindex->nFile, pblockindex->nBlockPos, fReadTransactions);
}

int64 GetBlockValue(int64 nFees)
{
    int64 nSubsidy = 10000 * CENT;
    for (int i = 100000; i <= nBestHeight; i += 100000)
        nSubsidy /= 2;
    return nSubsidy + nFees;
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast)
{
    const unsigned int nTargetTimespan = 30 * 24 * 60 * 60;
    const unsigned int nTargetSpacing = 15 * 60;
    const unsigned int nIntervals = nTargetTimespan / nTargetSpacing;

    // Cache
    static const CBlockIndex* pindexLastCache;
    static unsigned int nBitsCache;
    static CCriticalSection cs_cache;
    CRITICAL_BLOCK(cs_cache)
        if (pindexLast && pindexLast == pindexLastCache)
            return nBitsCache;

    // Go back 30 days
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < nIntervals; i++)
        pindexFirst = pindexFirst->pprev;
    if (pindexFirst == NULL)
        return MINPROOFOFWORK;

    // Load first and last block
    CBlock blockFirst;
    if (!blockFirst.ReadFromDisk(pindexFirst, false))
        throw runtime_error("GetNextWorkRequired() : blockFirst.ReadFromDisk failed\n");
    CBlock blockLast;
    if (!blockLast.ReadFromDisk(pindexLast, false))
        throw runtime_error("GetNextWorkRequired() : blockLast.ReadFromDisk failed\n");

    // Limit one change per timespan
    unsigned int nBits = blockLast.nBits;
    if (blockFirst.nBits == blockLast.nBits)
    {
        unsigned int nTimespan = blockLast.nTime - blockFirst.nTime;
        if (nTimespan > nTargetTimespan * 2 && nBits >= MINPROOFOFWORK)
            nBits--;
        else if (nTimespan < nTargetTimespan / 2)
            nBits++;
    }

    CRITICAL_BLOCK(cs_cache)
    {
        pindexLastCache = pindexLast;
        nBitsCache = nBits;
    }
    return nBits;
}

uint256 GetOrphanRoot(const CBlock* pblock)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblock->hashPrevBlock))
        pblock = mapOrphanBlocks[pblock->hashPrevBlock];
    return pblock->hashPrevBlock;
}









bool CBlock::TestDisconnectBlock(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool)
{
    foreach(CTransaction& tx, vtx)
        if (!tx.TestDisconnectInputs(txdb, mapTestPool))
            return false;
    return true;
}

bool CBlock::TestConnectBlock(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool)
{
    int64 nFees = 0;
    foreach(CTransaction& tx, vtx)
        if (!tx.TestConnectInputs(txdb, mapTestPool, false, false, nFees))
            return false;

    if (vtx[0].GetValueOut() != GetBlockValue(nFees))
        return false;
    return true;
}

bool CBlock::DisconnectBlock()
{
    CTxDB txdb;
    foreach(CTransaction& tx, vtx)
        if (!tx.DisconnectInputs(txdb))
            return false;
    return true;
}

bool CBlock::ConnectBlock(unsigned int nFile, unsigned int nBlockPos, int nHeight)
{
    //// issue here: it doesn't know the version
    unsigned int nTxPos = nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK) - 1 + GetSizeOfCompactSize(vtx.size());

    CTxDB txdb;
    foreach(CTransaction& tx, vtx)
    {
        CDiskTxPos posThisTx(nFile, nBlockPos, nTxPos);
        nTxPos += ::GetSerializeSize(tx, SER_DISK);

        if (!tx.ConnectInputs(txdb, posThisTx, nHeight))
            return false;
    }
    txdb.Close();

    // Watch for transactions paying to me
    foreach(CTransaction& tx, vtx)
        AddToWalletIfMine(tx, this);

    return true;
}



bool Reorganize(CBlockIndex* pindexNew, bool fWriteDisk)
{
    // Find the fork
    CBlockIndex* pfork = pindexBest;
    CBlockIndex* plonger = pindexNew;
    while (pfork != plonger)
    {
        if (!(pfork = pfork->pprev))
            return false;
        while (plonger->nHeight > pfork->nHeight)
            if (!(plonger = plonger->pprev))
                return false;
    }

    // List of what to disconnect
    vector<CBlockIndex*> vDisconnect;
    for (CBlockIndex* pindex = pindexBest; pindex != pfork; pindex = pindex->pprev)
        vDisconnect.push_back(pindex);

    // List of what to connect
    vector<CBlockIndex*> vConnect;
    for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    // Pretest the reorg
    if (fWriteDisk)
    {
        CTxDB txdb("r");
        map<uint256, CTransaction> mapTestPool;

        foreach(CBlockIndex* pindex, vDisconnect)
            if (!pindex->TestDisconnectBlock(txdb, mapTestPool))
                return false;

        bool fValid = true;
        foreach(CBlockIndex* pindex, vConnect)
        {
            fValid = fValid && pindex->TestConnectBlock(txdb, mapTestPool);
            if (!fValid)
            {
                // Invalid block, delete the rest of this branch
                CBlock block;
                block.ReadFromDisk(pindex, false);
                pindex->EraseBlockFromDisk();
                mapBlockIndex.erase(block.GetHash());
                delete pindex;
            }
        }
        if (!fValid)
            return false;
    }

    // Disconnect shorter branch
    foreach(CBlockIndex* pindex, vDisconnect)
    {
        if (fWriteDisk && !pindex->DisconnectBlock())
            return false;
        if (pindex->pprev)
            pindex->pprev->pnext = NULL;
    }

    // Connect longer branch
    foreach(CBlockIndex* pindex, vConnect)
    {
        if (fWriteDisk && !pindex->ConnectBlock())
            return false;
        if (pindex->pprev)
            pindex->pprev->pnext = pindex;
    }

    return true;
}


bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos, bool fWriteDisk)
{
    uint256 hash = GetHash();

    // Add to block index
    CBlockIndex* pindexNew = new CBlockIndex(nFile, nBlockPos);
    if (!pindexNew)
        return false;
    mapBlockIndex[hash] = pindexNew;
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi != mapBlockIndex.end())
    {
        pindexNew->pprev = (*mi).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }

    // New best
    if (pindexNew->nHeight > nBestHeight)
    {
        if (pindexGenesisBlock == NULL && hash == hashGenesisBlock)
        {
            pindexGenesisBlock = pindexNew;
        }
        else if (hashPrevBlock == hashTimeChainBest)
        {
            // Adding to current best branch
            if (fWriteDisk)
                if (!pindexNew->ConnectBlock())
                    return false;
            pindexNew->pprev->pnext = pindexNew;
        }
        else
        {
            // New best branch
            if (!Reorganize(pindexNew, fWriteDisk))
                return false;
        }

        // New best link
        nBestHeight = pindexNew->nHeight;
        hashTimeChainBest = hash;
        pindexBest = pindexNew;
        nTransactionsUpdated++;

        // Relay wallet transactions that haven't gotten in yet
        if (fWriteDisk && nTime > GetAdjustedTime() - 30 * 60)
            RelayWalletTransactions();
    }

    MainFrameRepaint();
    return true;
}





template<typename Stream>
bool ScanMessageStart(Stream& s)
{
    // Scan ahead to the next pchMessageStart, which should normally be immediately
    // at the file pointer.  Leaves file pointer at end of pchMessageStart.
    s.clear(0);
    short prevmask = s.exceptions(0);
    const char* p = BEGIN(pchMessageStart);
    try
    {
        loop
        {
            char c;
            s.read(&c, 1);
            if (s.fail())
            {
                s.clear(0);
                s.exceptions(prevmask);
                return false;
            }
            if (*p != c)
                p = BEGIN(pchMessageStart);
            if (*p == c)
            {
                if (++p == END(pchMessageStart))
                {
                    s.clear(0);
                    s.exceptions(prevmask);
                    return true;
                }
            }
        }
    }
    catch (...)
    {
        s.clear(0);
        s.exceptions(prevmask);
        return false;
    }
}

FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if (nFile == -1)
        return NULL;
    FILE* file = fopen(strprintf("blk%04d.dat", nFile).c_str(), pszMode);
    if (!file)
        return NULL;
    if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);
            return NULL;
        }
    }
    return file;
}

static unsigned int nCurrentBlockFile = 1;

FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;
    loop
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (!file)
            return NULL;
        if (fseek(file, 0, SEEK_END) != 0)
            return NULL;
        // FAT32 filesize max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        if (ftell(file) < 0x7F000000 - MAX_SIZE)
        {
            nFileRet = nCurrentBlockFile;
            return file;
        }
        fclose(file);
        nCurrentBlockFile++;
    }
}

bool LoadBlockIndex(bool fAllowNew)
{
    //
    // Load from disk
    //
    for (nCurrentBlockFile = 1;; nCurrentBlockFile++)
    {
        CAutoFile filein = OpenBlockFile(nCurrentBlockFile, 0, "rb");
        if (filein == NULL)
        {
            if (nCurrentBlockFile > 1)
            {
                nCurrentBlockFile--;
                break;
            }
            if (!fAllowNew)
                return false;

            //// debug
            // Genesis Block:
            // GetHash()      = 0x000006b15d1327d67e971d1de9116bd60a3a01556c91b6ebaa416ebc0cfaa646
            // hashPrevBlock  = 0x0000000000000000000000000000000000000000000000000000000000000000
            // hashMerkleRoot = 0x769a5e93fac273fd825da42d39ead975b5d712b2d50953f35a4fdebdec8083e3
            // txNew.vin[0].scriptSig      = 247422313
            // txNew.vout[0].nValue        = 10000
            // txNew.vout[0].scriptPubKey  = OP_CODESEPARATOR 0x31D18A083F381B4BDE37B649AACF8CD0AFD88C53A3587ECDB7FAF23D449C800AF1CE516199390BFE42991F10E7F5340F2A63449F0B639A7115C667E5D7B051D404 OP_CHECKSIG
            // nTime          = 1221069728
            // nBits          = 20
            // nNonce         = 141755
            // CBlock(hashPrevBlock=000000, hashMerkleRoot=769a5e, nTime=1221069728, nBits=20, nNonce=141755, vtx=1)
            //   CTransaction(vin.size=1, vout.size=1, nLockTime=0)
            //     CTxIn(COutPoint(000000, -1), coinbase 04695dbf0e)
            //     CTxOut(nValue=10000, nSequence=4294967295, scriptPubKey=51b0, posNext=null)
            //   vMerkleTree: 769a5e

            // Genesis block
            CTransaction txNew;
            txNew.vin.resize(1);
            txNew.vout.resize(1);
            txNew.vin[0].scriptSig     = CScript() << 247422313;
            txNew.vout[0].nValue       = 10000;
            txNew.vout[0].scriptPubKey = CScript() << OP_CODESEPARATOR << CBigNum("0x31D18A083F381B4BDE37B649AACF8CD0AFD88C53A3587ECDB7FAF23D449C800AF1CE516199390BFE42991F10E7F5340F2A63449F0B639A7115C667E5D7B051D404") << OP_CHECKSIG;
            CBlock block;
            block.vtx.push_back(txNew);
            block.hashPrevBlock = 0;
            block.hashMerkleRoot = block.BuildMerkleTree();
            block.nTime  = 1221069728;
            block.nBits  = 20;
            block.nNonce = 141755;

                //// debug print
                printf("%s\n", block.GetHash().ToString().c_str());
                printf("%s\n", block.hashMerkleRoot.ToString().c_str());
                printf("%s\n", hashGenesisBlock.ToString().c_str());
                txNew.vout[0].scriptPubKey.print();
                block.print();
                assert(block.hashMerkleRoot == uint256("0x769a5e93fac273fd825da42d39ead975b5d712b2d50953f35a4fdebdec8083e3"));

            assert(block.GetHash() == hashGenesisBlock);

            // Start new block file
            unsigned int nFile;
            unsigned int nBlockPos;
            if (!block.WriteToDisk(true, nFile, nBlockPos))
                return false;
            if (!block.AddToBlockIndex(nFile, nBlockPos, true))
                return false;
            break;
        }

        int nFilesize = GetFilesize(filein);
        if (nFilesize == -1)
            return false;
        filein.nType |= SER_BLOCKHEADERONLY;

        while (ScanMessageStart(filein))
        {
            // Read index header
            unsigned int nSize;
            filein >> nSize;
            if (nSize > MAX_SIZE || ftell(filein) + nSize > nFilesize)
                continue;

            // Read block header
            int nBlockPos = ftell(filein);
            CBlock block;
            filein >> block;

            // Skip transactions
            if (fseek(filein, nBlockPos + nSize, SEEK_SET) != 0)
                break; //// is this all we want to do if there's a file error like this?

            // Add to block index without updating disk
            if (!block.AddToBlockIndex(nCurrentBlockFile, nBlockPos, false))
                return false;
        }
    }
    return true;
}



void PrintTimechain()
{
    // precompute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                printf("| ");
            printf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                printf("| ");
            printf("|\n");
        }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            printf("| ");

        // print item
        printf("%d (%u,%u)\n", pindex->nHeight, pindex->nFile, pindex->nBlockPos);

        // put the main timechain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}






bool CBlock::CheckBlock() const
{
    // Size limits
    if (vtx.empty() || vtx.size() > MAX_SIZE || ::GetSerializeSize(*this, SER_DISK) > MAX_SIZE)
        return error("CheckBlock() : size limits failed");

    // Check timestamp
    if (nTime > GetAdjustedTime() + 36 * 60 * 60)
        return error("CheckBlock() : block timestamp out of range");

    // Check proof of work matches claimed amount
    if (nBits < MINPROOFOFWORK)
        return error("CheckBlock() : nBits below minimum");
    if (GetHash() > (~uint256(0) >> nBits))
        return error("CheckBlock() : hash doesn't match nBits");

    // First transaction must be coinbase, the rest must not be
    if (vtx.empty() || !vtx[0].IsCoinBase())
        return error("CheckBlock() : first tx is not coinbase");
    for (int i = 1; i < vtx.size(); i++)
        if (vtx[i].IsCoinBase())
            return error("CheckBlock() : more than one coinbase");

    // Check transactions
    foreach(const CTransaction& tx, vtx)
        if (!tx.CheckTransaction())
            return error("CheckBlock() : CheckTransaction failed");

    // Check merkleroot
    if (hashMerkleRoot != BuildMerkleTree())
        return error("CheckBlock() : hashMerkleRoot mismatch");

    return true;
}

bool CBlock::AcceptBlock()
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return false;

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end())
        return false;
    CBlockIndex* pindexPrev = (*mi).second;

    // Check timestamp against prev
    CBlock blockPrev;
    if (!blockPrev.ReadFromDisk(pindexPrev, false))
        return false;
    if (nTime <= blockPrev.nTime)
        return false;

    // Check proof of work
    if (nBits != GetNextWorkRequired(pindexPrev))
        return false;

    // Check transaction inputs and verify signatures
    {
        CTxDB txdb("r");
        map<uint256, CTransaction> mapTestPool;
        bool fIgnoreDiskConflicts = (hashPrevBlock != hashTimeChainBest);
        int64 nFees = 0;
        foreach(CTransaction& tx, vtx)
            if (!tx.TestConnectInputs(txdb, mapTestPool, false, fIgnoreDiskConflicts, nFees))
                return error("AcceptBlock() : TestConnectInputs failed");
        if (vtx[0].GetValueOut() != GetBlockValue(nFees))
            return false;
    }

    // Write block to history file
    unsigned int nFile;
    unsigned int nBlockPos;
    if (!WriteToDisk(!fClient, nFile, nBlockPos))
        return false;
    if (!AddToBlockIndex(nFile, nBlockPos, true))
        return false;

    if (hashTimeChainBest == hash)
        RelayInventory(CInv(MSG_BLOCK, hash));

    // Add atoms to user reviews for coins created
    vector<unsigned char> vchPubKey;
    if (ExtractPubKey(vtx[0].vout[0].scriptPubKey, false, vchPubKey))
    {
        uint64 nRand = 0;
        RAND_bytes((unsigned char*)&nRand, sizeof(nRand));
        unsigned short nAtom = nRand % (USHRT_MAX - 100) + 100;
        vector<unsigned short> vAtoms(1, nAtom);
        AddAtomsAndPropagate(Hash(vchPubKey.begin(), vchPubKey.end()), vAtoms, true);
    }

    return true;
}

bool ProcessBlock(CNode* pfrom, CBlock* pblock)
{
    // Check for duplicate
    uint256 hash = pblock->GetHash();
    if (mapBlockIndex.count(hash) || mapOrphanBlocks.count(hash))
        return false;

    // Preliminary checks
    if (!pblock->CheckBlock())
    {
        printf("CheckBlock FAILED\n");
        delete pblock;
        return false;
    }

    // If don't already have its previous block, shunt it off to holding area until we get it
    if (!mapBlockIndex.count(pblock->hashPrevBlock))
    {
        mapOrphanBlocks.insert(make_pair(hash, pblock));
        mapOrphanBlocksByPrev.insert(make_pair(pblock->hashPrevBlock, pblock));

        // Ask this guy to fill in what we're missing
        if (pfrom)
            pfrom->PushMessage("getblocks", CBlockLocator(pindexBest), GetOrphanRoot(pblock));
        return true;
    }

    // Store to disk
    if (!pblock->AcceptBlock())
    {
        printf("AcceptBlock FAILED\n");
        delete pblock;
        return false;
    }
    delete pblock;

    // Now process any orphan blocks that depended on this one
    for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hash);
         mi != mapOrphanBlocksByPrev.upper_bound(hash);
         ++mi)
    {
        CBlock* pblockOrphan = (*mi).second;
        pblockOrphan->AcceptBlock();
        mapOrphanBlocks.erase(pblockOrphan->GetHash());
        delete pblockOrphan;
    }
    mapOrphanBlocksByPrev.erase(hash);

    return true;
}
