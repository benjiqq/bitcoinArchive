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

class COutPoint;
class CInPoint;
class CDiskTxPos;
class CCoinBase;
class CTxIn;
class CTxOut;
class CTransaction;
class CBlock;
class CBlockIndex;
class CWalletTx;
class CKeyItem;

static const unsigned int MAX_SIZE = 0x02000000;
static const int64 COIN = 1000000;
static const int64 CENT = 10000;
static const int64 TRANSACTIONFEE = 1 * CENT; /// change this to a user options setting, optional fee can be zero
///static const unsigned int MINPROOFOFWORK = 40; /// need to decide the right difficulty to start with
static const unsigned int MINPROOFOFWORK = 20;  /// ridiculously easy for testing







extern map<uint256, CBlockIndex*> mapBlockIndex;
extern const uint256 hashGenesisBlock;
extern CBlockIndex* pindexGenesisBlock;
extern int nBestHeight;
extern CBlockIndex* pindexBest;
extern unsigned int nTransactionsUpdated;
extern int fGenerateBitcoins;







FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode="rb");
FILE* AppendBlockFile(unsigned int& nFileRet);
bool AddKey(const CKey& key);
vector<unsigned char> GenerateNewKey();
bool AddToWallet(const CWalletTx& wtxIn);
void ReacceptWalletTransactions();
void RelayWalletTransactions();
bool LoadBlockIndex(bool fAllowNew=true);
bool BitcoinMiner();
bool ProcessMessages(CNode* pfrom);
bool ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv);
bool SendMessages(CNode* pto);
int64 CountMoney();
bool CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx& txNew);
bool SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew);











class CDiskTxPos
{
public:
    unsigned int nFile;
    unsigned int nBlockPos;
    unsigned int nTxPos;

    CDiskTxPos()
    {
        SetNull();
    }

    CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn, unsigned int nTxPosIn)
    {
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nTxPos = nTxPosIn;
    }

    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    void SetNull() { nFile = -1; nBlockPos = 0; nTxPos = 0; }
    bool IsNull() const { return (nFile == -1); }

    friend bool operator==(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return (a.nFile     == b.nFile &&
                a.nBlockPos == b.nBlockPos &&
                a.nTxPos    == b.nTxPos);
    }

    friend bool operator!=(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return !(a == b);
    }

    void print() const
    {
        if (IsNull())
            printf("null");
        else
            printf("(nFile=%d, nBlockPos=%d, nTxPos=%d)", nFile, nBlockPos, nTxPos);
    }
};




class CInPoint
{
public:
    CTransaction* ptx;
    unsigned int n;

    CInPoint() { SetNull(); }
    CInPoint(CTransaction* ptxIn, unsigned int nIn) { ptx = ptxIn; n = nIn; }
    void SetNull() { ptx = NULL; n = -1; }
    bool IsNull() const { return (ptx == NULL && n == -1); }
};




class COutPoint
{
public:
    uint256 hash;
    unsigned int n;

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, unsigned int nIn) { hash = hashIn; n = nIn; }
    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    void SetNull() { hash = 0; n = -1; }
    bool IsNull() const { return (hash == 0 && n == -1); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    void print() const
    {
        printf("COutPoint(%s, %d)", hash.ToString().substr(0,6).c_str(), n);
    }
};




//
// An input of a transaction.  It contains the location of the previous
// transaction's output that it claims and a signature that matches the
// output's public key.
//
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;

    CTxIn()
    {
    }

    CTxIn(COutPoint prevoutIn, CScript scriptSigIn)
    {
        prevout = prevoutIn;
        scriptSig = scriptSigIn;
    }

    CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn)
    {
        prevout = COutPoint(hashPrevTx, nOut);
        scriptSig = scriptSigIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(prevout);
        READWRITE(scriptSig);
    )

    bool IsPrevInMainChain() const
    {
        return CTxDB("r").ContainsTx(prevout.hash);
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout == b.prevout && a.scriptSig == b.scriptSig);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    void print() const
    {
        printf("CTxIn(");
        prevout.print();
        if (prevout.IsNull())
        {
            printf(", coinbase %s)\n", HexStr(scriptSig.begin(), scriptSig.end(), false).c_str());
        }
        else
        {
            if (scriptSig.size() >= 6)
                printf(", scriptSig=%02x%02x", scriptSig[4], scriptSig[5]);
            printf(")\n");
        }
    }

    bool IsMine() const;
    int64 GetDebit() const;
};




//
// An output of a transaction.  It contains the public key that the next input
// must be able to sign with to claim it.
//
class CTxOut
{
public:
    int64 nValue;
    unsigned int nSequence;
    CScript scriptPubKey;

    // disk only
    CDiskTxPos posNext;  //// so far this is only used as a flag, nothing uses the location

public:
    CTxOut()
    {
        nValue = 0;
        nSequence = UINT_MAX;
    }

    CTxOut(int64 nValueIn, CScript scriptPubKeyIn, int nSequenceIn=UINT_MAX)
    {
        nValue = nValueIn;
        scriptPubKey = scriptPubKeyIn;
        nSequence = nSequenceIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nValue);
        READWRITE(nSequence);
        READWRITE(scriptPubKey);
        if (nType & SER_DISK)
            READWRITE(posNext);
    )

    uint256 GetHash() const { return SerializeHash(*this); }

    bool IsFinal() const
    {
        return (nSequence == UINT_MAX);
    }

    bool IsMine() const
    {
        return ::IsMine(scriptPubKey);
    }

    int64 GetCredit() const
    {
        if (IsMine())
            return nValue;
        return 0;
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.nSequence    == b.nSequence &&
                a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    void print() const
    {
        if (scriptPubKey.size() >= 6)
            printf("CTxOut(nValue=%I64d, nSequence=%u, scriptPubKey=%02x%02x, posNext=", nValue, nSequence, scriptPubKey[4], scriptPubKey[5]);
        posNext.print();
        printf(")\n");
    }
};




//
// The basic transaction that is broadcasted on the network and contained in
// blocks.  A transaction can contain multiple inputs and outputs.
//
class CTransaction
{
public:
    vector<CTxIn> vin;
    vector<CTxOut> vout;
    unsigned int nLockTime;


    CTransaction()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);

        // Set version on stream for writing back same version
        if (fRead && s.nVersion == -1)
            s.nVersion = nVersion;

        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
    )

    void SetNull()
    {
        vin.clear();
        vout.clear();
        nLockTime = 0;
    }

    bool IsNull() const
    {
        return (vin.empty() && vout.empty());
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    bool AllPrevInMainChain() const
    {
        foreach(const CTxIn& txin, vin)
            if (!txin.IsPrevInMainChain())
                return false;
        return true;
    }

    bool IsFinal() const
    {
        if (nLockTime == 0)
            return true;
        if (nLockTime < GetAdjustedTime())
            return true;
        foreach(const CTxOut& txout, vout)
            if (!txout.IsFinal())
                return false;
        return true;
    }

    bool IsUpdate(const CTransaction& b) const
    {
        if (vin.size() != b.vin.size() || vout.size() != b.vout.size())
            return false;
        for (int i = 0; i < vin.size(); i++)
            if (vin[i].prevout != b.vin[i].prevout)
                return false;

        bool fNewer = false;
        unsigned int nLowest = UINT_MAX;
        for (int i = 0; i < vout.size(); i++)
        {
            if (vout[i].nSequence != b.vout[i].nSequence)
            {
                if (vout[i].nSequence <= nLowest)
                {
                    fNewer = false;
                    nLowest = vout[i].nSequence;
                }
                if (b.vout[i].nSequence < nLowest)
                {
                    fNewer = true;
                    nLowest = b.vout[i].nSequence;
                }
            }
        }
        return fNewer;
    }

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    bool CheckTransaction() const
    {
        // Basic checks that don't depend on any context
        if (vin.empty() || vout.empty())
            return false;

        // Check for negative values
        int64 nValueOut = 0;
        foreach(const CTxOut& txout, vout)
        {
            if (txout.nValue < 0)
                return false;
            nValueOut += txout.nValue;
        }

        if (IsCoinBase())
        {
            if (vin[0].scriptSig.size() > 100)
                return false;
        }
        else
        {
            foreach(const CTxIn& txin, vin)
                if (txin.prevout.IsNull())
                    return false;
        }

        return true;
    }

    bool IsMine() const
    {
        foreach(const CTxOut& txout, vout)
            if (txout.IsMine())
                return true;
        return false;
    }

    int64 GetDebit() const
    {
        int64 nDebit = 0;
        foreach(const CTxIn& txin, vin)
            nDebit += txin.GetDebit();
        return nDebit;
    }

    int64 GetCredit() const
    {
        int64 nCredit = 0;
        foreach(const CTxOut& txout, vout)
            nCredit += txout.GetCredit();
        return nCredit;
    }

    int64 GetValueOut() const
    {
        int64 nValueOut = 0;
        foreach(const CTxOut& txout, vout)
        {
            if (txout.nValue < 0)
                throw runtime_error("CTransaction::GetValueOut() : negative value");
            nValueOut += txout.nValue;
        }
        return nValueOut;
    }



    bool ReadFromDisk(CDiskTxPos pos, FILE** pfileRet=NULL)
    {
        CAutoFile filein = OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb");
        if (!filein)
            return false;

        // Read transaction
        if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
            return false;
        filein >> *this;

        // Return file pointer
        if (pfileRet)
        {
            if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
                return false;
            *pfileRet = filein.release();
        }
        return true;
    }


    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.vin       == b.vin &&
                a.vout      == b.vout &&
                a.nLockTime == b.nLockTime);
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }


    void print() const
    {
        printf("CTransaction(vin.size=%d, vout.size=%d, nLockTime=%d)\n",
            vin.size(),
            vout.size(),
            nLockTime);
        for (int i = 0; i < vin.size(); i++)
        {
            printf("    ");
            vin[i].print();
        }
        for (int i = 0; i < vout.size(); i++)
        {
            printf("    ");
            vout[i].print();
        }
    }



    bool TestDisconnectInputs(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool)
    {
        return DisconnectInputs(txdb, mapTestPool, true);
    }

    bool TestConnectInputs(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool, bool fMemoryTx, bool fIgnoreDiskConflicts, int64& nFees)
    {
        return ConnectInputs(txdb, mapTestPool, CDiskTxPos(1, 1, 1), 0, true, fMemoryTx, fIgnoreDiskConflicts, nFees);
    }

    bool DisconnectInputs(CTxDB& txdb)
    {
        static map<uint256, CTransaction> mapTestPool;
        return DisconnectInputs(txdb, mapTestPool, false);
    }

    bool ConnectInputs(CTxDB& txdb, CDiskTxPos posThisTx, int nHeight)
    {
        static map<uint256, CTransaction> mapTestPool;
        int64 nFees;
        return ConnectInputs(txdb, mapTestPool, posThisTx, nHeight, false, false, false, nFees);
    }

private:
    bool DisconnectInputs(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool, bool fTest);
    bool ConnectInputs(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool, CDiskTxPos posThisTx, int nHeight,
                       bool fTest, bool fMemoryTx, bool fIgnoreDiskConflicts, int64& nFees);

public:
    bool AcceptTransaction(CTxDB& txdb, bool fCheckInputs=true);
    bool AcceptTransaction() { CTxDB txdb("r"); return AcceptTransaction(txdb); }
    bool ClientConnectInputs();
};





//
// A transaction with a merkle branch linking it to the timechain
//
class CMerkleTx : public CTransaction
{
public:
    uint256 hashBlock;
    vector<uint256> vMerkleBranch;
    int nIndex;

    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = 0;
        nIndex = -1;
    }

    IMPLEMENT_SERIALIZE
    (
        nSerSize += SerReadWrite(s, *(CTransaction*)this, nType, nVersion, ser_action);
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    )


    int SetMerkleBranch();
    int IsInMainChain() const;
    bool AcceptTransaction(CTxDB& txdb, bool fCheckInputs=true);
    bool AcceptTransaction() { CTxDB txdb("r"); return AcceptTransaction(txdb); }
};




//
// A transaction with a bunch of additional info that only the owner cares
// about.  It includes any unrecorded transactions needed to link it back
// to the timechain.
//
class CWalletTx : public CMerkleTx
{
public:
    vector<CMerkleTx> vtxPrev;
    map<string, string> mapValue;
    vector<pair<string, string> > vOrderForm;
    unsigned int nTime;
    char fFromMe;
    char fSpent;

    //// probably need to sign the order info so know it came from payer

    CWalletTx()
    {
        Init();
    }

    CWalletTx(const CMerkleTx& txIn) : CMerkleTx(txIn)
    {
        Init();
    }

    CWalletTx(const CTransaction& txIn) : CMerkleTx(txIn)
    {
        Init();
    }

    void Init()
    {
        nTime = 0;
        fFromMe = false;
        fSpent = false;
    }

    IMPLEMENT_SERIALIZE
    (
        /// would be nice for it to return the version number it reads, maybe use a reference
        nSerSize += SerReadWrite(s, *(CMerkleTx*)this, nType, nVersion, ser_action);
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vtxPrev);
        READWRITE(mapValue);
        READWRITE(vOrderForm);
        READWRITE(nTime);
        READWRITE(fFromMe);
        READWRITE(fSpent);
    )

    bool WriteToDisk()
    {
        return CWalletDB().WriteTx(GetHash(), *this);
    }


    void AddSupportingTransactions(CTxDB& txdb);
    void AddSupportingTransactions() { CTxDB txdb("r"); AddSupportingTransactions(txdb); }

    bool AcceptWalletTransaction(CTxDB& txdb, bool fCheckInputs=true);
    bool AcceptWalletTransaction() { CTxDB txdb("r"); return AcceptWalletTransaction(txdb); }

    void RelayWalletTransaction(CTxDB& txdb);
    void RelayWalletTransaction() { CTxDB txdb("r"); RelayWalletTransaction(txdb); }
};






//
// Nodes collect new transactions into a block, hash them into a hash tree,
// and scan through nonce values to make the block's hash satisfy proof-of-work
// requirements.  When they solve the proof-of-work, they broadcast the block
// to everyone and the block is added to the timechain.  The first transaction
// in the block is a special one that creates a new coin owned by the creator
// of the block.
//
// Blocks are appended to blk0001.dat files on disk.  Their location on disk
// is indexed by CBlockIndex objects in memory.
//
class CBlock
{
public:
    // header
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;

    // network and disk
    vector<CTransaction> vtx;

    // memory only
    mutable vector<uint256> vMerkleTree;


    CBlock()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);

        // ConnectBlock depends on vtx being last so it can calculate offset
        if (!(nType & (SER_GETHASH|SER_BLOCKHEADERONLY)))
            READWRITE(vtx);
        else if (fRead)
            const_cast<CBlock*>(this)->vtx.clear();
    )

    void SetNull()
    {
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        vtx.clear();
        vMerkleTree.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const
    {
        return Hash(BEGIN(hashPrevBlock), END(nNonce));
    }

    uint256 BuildMerkleTree() const
    {
        vMerkleTree.clear();
        foreach(const CTransaction& tx, vtx)
            vMerkleTree.push_back(tx.GetHash());
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            for (int i = 0; i < nSize; i += 2)
            {
                int i2 = min(i+1, nSize-1);
                vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
                                           BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
            }
            j += nSize;
        }
        return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
    }

    vector<uint256> GetMerkleBranch(int nIndex) const
    {
        if (vMerkleTree.empty())
            BuildMerkleTree();
        vector<uint256> vMerkleBranch;
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            int i = min(nIndex^1, nSize-1);
            vMerkleBranch.push_back(vMerkleTree[j+i]);
            nIndex >>= 1;
            j += nSize;
        }
        return vMerkleBranch;
    }

    static uint256 CheckMerkleBranch(uint256 hash, const vector<uint256>& vMerkleBranch, int nIndex)
    {
        foreach(const uint256& otherside, vMerkleBranch)
        {
            if (nIndex & 1)
                hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
            else
                hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
            nIndex >>= 1;
        }
        return hash;
    }


    bool WriteToDisk(bool fWriteTransactions, unsigned int& nFileRet, unsigned int& nBlockPosRet)
    {
        // Open history file to append
        CAutoFile fileout = AppendBlockFile(nFileRet);
        if (!fileout)
            return false;
        if (!fWriteTransactions)
            fileout.nType |= SER_BLOCKHEADERONLY;

        // Write index header
        unsigned int nSize = fileout.GetSerializeSize(*this);
        fileout << FLATDATA(pchMessageStart) << nSize;

        // Write block
        nBlockPosRet = ftell(fileout);
        if (nBlockPosRet == -1)
            return false;
        fileout << *this;

        return true;
    }

    bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions)
    {
        SetNull();

        // Open history file to read
        CAutoFile filein = OpenBlockFile(nFile, nBlockPos, "rb");
        if (!filein)
            return false;
        if (!fReadTransactions)
            filein.nType |= SER_BLOCKHEADERONLY;

        // Read block
        filein >> *this;

        // Check the header
        if (nBits < MINPROOFOFWORK || GetHash() > (~uint256(0) >> nBits))
            return error("CBlock::ReadFromDisk : errors in block header");

        return true;
    }



    void print() const
    {
        printf("CBlock(hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%u, nNonce=%u, vtx=%d)\n",
            hashPrevBlock.ToString().substr(0,6).c_str(),
            hashMerkleRoot.ToString().substr(0,6).c_str(),
            nTime, nBits, nNonce,
            vtx.size());
        for (int i = 0; i < vtx.size(); i++)
        {
            printf("  ");
            vtx[i].print();
        }
        printf("  vMerkleTree: ");
        for (int i = 0; i < vMerkleTree.size(); i++)
            printf("%s ", vMerkleTree[i].ToString().substr(0,6).c_str());
        printf("\n");
    }



    bool ReadFromDisk(const CBlockIndex* blockindex, bool fReadTransactions);
    bool TestDisconnectBlock(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool);
    bool TestConnectBlock(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool);
    bool DisconnectBlock();
    bool ConnectBlock(unsigned int nFile, unsigned int nBlockPos, int nHeight);
    bool AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos, bool fWriteDisk);
    bool CheckBlock() const;
    bool AcceptBlock();
};






//
// The timechain is a tree shaped structure starting with the
// genesis block at the root, with each block potentially having multiple
// candidates to be the next block.  pprev and pnext link a path through the
// main/longest chain.  A blockindex may have multiple pprev pointing back
// to it, but pnext will only point forward to the longest branch, or will
// be null if the block is not part of the longest chain.
//
class CBlockIndex
{
public:
    CBlockIndex* pprev;
    CBlockIndex* pnext;
    unsigned int nFile;
    unsigned int nBlockPos;
    int nHeight;


    CBlockIndex()
    {
        pprev = NULL;
        pnext = NULL;
        nFile = 0;
        nBlockPos = 0;
        nHeight = 0;
    }

    CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn)
    {
        pprev = NULL;
        pnext = NULL;
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nHeight = 0;
    }

    bool IsInMainChain() const
    {
        return (pnext || this == pindexBest);
    }

    bool EraseBlockFromDisk()
    {
        // Open history file
        CAutoFile fileout = OpenBlockFile(nFile, nBlockPos, "rb+");
        if (!fileout)
            return false;

        // Overwrite with empty null block
        CBlock block;
        block.SetNull();
        fileout << block;

        return true;
    }



    bool TestDisconnectBlock(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool)
    {
        CBlock block;
        if (!block.ReadFromDisk(nFile, nBlockPos, true))
            return false;
        return block.TestDisconnectBlock(txdb, mapTestPool);
    }

    bool TestConnectBlock(CTxDB& txdb, map<uint256, CTransaction>& mapTestPool)
    {
        CBlock block;
        if (!block.ReadFromDisk(nFile, nBlockPos, true))
            return false;
        return block.TestConnectBlock(txdb, mapTestPool);
    }

    bool DisconnectBlock()
    {
        CBlock block;
        if (!block.ReadFromDisk(nFile, nBlockPos, true))
            return false;
        return block.DisconnectBlock();
    }

    bool ConnectBlock()
    {
        CBlock block;
        if (!block.ReadFromDisk(nFile, nBlockPos, true))
            return false;
        return block.ConnectBlock(nFile, nBlockPos, nHeight);
    }



    void print() const
    {
        printf("CBlockIndex(nprev=%08x, pnext=%08x, nFile=%d, nBlockPos=%d, nHeight=%d)\n",
            pprev, pnext, nFile, nBlockPos, nHeight);
    }
};

void PrintTimechain();







//
// Describes a place in the timechain to another node such that if the
// other node doesn't have the same branch, it can find a recent common trunk.
// The further back it is, the further before the branch point it may be.
//
class CBlockLocator
{
protected:
    vector<uint256> vHave;
public:

    CBlockLocator()
    {
    }

    explicit CBlockLocator(const CBlockIndex* pindex)
    {
        Set(pindex);
    }

    explicit CBlockLocator(uint256 hashBlock)
    {
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end())
            Set((*mi).second);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    )

    void Set(const CBlockIndex* pindex)
    {
        vHave.clear();
        int nStep = 1;
        while (pindex)
        {
            CBlock block;
            block.ReadFromDisk(pindex, false);
            vHave.push_back(block.GetHash());

            // Exponentially larger steps back
            for (int i = 0; pindex && i < nStep; i++)
                pindex = pindex->pprev;
            if (vHave.size() > 10)
                nStep *= 2;
        }
    }

    CBlockIndex* GetBlockIndex()
    {
        // Find the first block the caller has in the main chain
        foreach(const uint256& hash, vHave)
        {
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return pindex;
            }
        }
        return pindexGenesisBlock;
    }

    uint256 GetBlockHash()
    {
        // Find the first block the caller has in the main chain
        foreach(const uint256& hash, vHave)
        {
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return hash;
            }
        }
        return hashGenesisBlock;
    }

    int GetHeight()
    {
        CBlockIndex* pindex = GetBlockIndex();
        if (!pindex)
            return 0;
        return pindex->nHeight;
    }
};












extern map<uint256, CTransaction> mapTransactions;
extern map<uint256, CWalletTx> mapWallet;
extern vector<pair<uint256, bool> > vWalletUpdated;
extern CCriticalSection cs_mapWallet;
extern map<vector<unsigned char>, CPrivKey> mapKeys;
extern map<uint160, vector<unsigned char> > mapPubKeys;
extern CCriticalSection cs_mapKeys;
extern CKey keyUser;
