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
#include <winsock2.h>

void ThreadMessageHandler2(void* parg);
void ThreadSocketHandler2(void* parg);
void ThreadOpenConnections2(void* parg);






//
// Global state variables
//
bool fClient = false;
uint64 nLocalServices = (fClient ? 0 : NODE_NETWORK);
CAddress addrLocalHost(0, DEFAULT_PORT, nLocalServices);
CNode nodeLocalHost(INVALID_SOCKET, CAddress("127.0.0.1", nLocalServices));
CNode* pnodeLocalHost = &nodeLocalHost;
bool fShutdown = false;
array<bool, 10> vfThreadRunning;
vector<CNode*> vNodes;
CCriticalSection cs_vNodes;
map<vector<unsigned char>, CAddress> mapAddresses;
CCriticalSection cs_mapAddresses;
map<CInv, CDataStream> mapRelay;
deque<pair<int64, CInv> > vRelayExpiration;
CCriticalSection cs_mapRelay;
map<CInv, int64> mapAlreadyAskedFor;






bool AddAddress(CAddrDB& addrdb, const CAddress& addr)
{
    CRITICAL_BLOCK(cs_mapAddresses)
    {
        map<vector<unsigned char>, CAddress>::iterator it = mapAddresses.find(addr.GetKey());
        if (it == mapAddresses.end())
        {
            // New address
            mapAddresses.insert(make_pair(addr.GetKey(), addr));
            addrdb.WriteAddress(addr);
            return true;
        }
        else
        {
            CAddress& addrFound = (*it).second;
            if ((addrFound.nServices | addr.nServices) != addrFound.nServices)
            {
                // Services have been added
                addrFound.nServices |= addr.nServices;
                addrdb.WriteAddress(addrFound);
                return true;
            }
        }
    }
    return false;
}





void AbandonRequests(void (*fn)(void*, CDataStream&), void* param1)
{
    // If the dialog might get closed before the reply comes back,
    // call this in the destructor so it doesn't get called after it's deleted.
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
        {
            CRITICAL_BLOCK(pnode->cs_mapRequests)
            {
                for (map<uint256, CRequestTracker>::iterator mi = pnode->mapRequests.begin(); mi != pnode->mapRequests.end();)
                {
                    CRequestTracker& tracker = (*mi).second;
                    if (tracker.fn == fn && tracker.param1 == param1)
                        pnode->mapRequests.erase(mi++);
                    else
                        mi++;
                }
            }
        }
    }
}









CNode* FindNode(unsigned int ip)
{
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
            if (pnode->addr.ip == ip)
                return (pnode);
    }
    return NULL;
}

CNode* FindNode(CAddress addr)
{
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
            if (pnode->addr == addr)
                return (pnode);
    }
    return NULL;
}

CNode* ConnectNode(CAddress addrConnect, int64 nTimeout)
{
    if (addrConnect.ip == addrLocalHost.ip)
        return NULL;

    // Look for an existing connection
    CNode* pnode = FindNode(addrConnect.ip);
    if (pnode)
    {
        if (nTimeout != 0)
            pnode->AddRef(nTimeout);
        else
            pnode->AddRef();
        return pnode;
    }

    // Connect
    SOCKET hSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (hSocket == INVALID_SOCKET)
    {
        printf("socket failed\n");
        return NULL;
    }

    struct sockaddr_in sockaddr;
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = addrConnect.ip;
    sockaddr.sin_port = addrConnect.port;

        /// debug print
        static map<unsigned int, unsigned int> mapPrintLimit;
        if (mapPrintLimit[addrConnect.ip] % 20 == 0)
            printf("connecting to %d.%d.%d.%d\n", ((unsigned char*)&sockaddr.sin_addr.s_addr)[0], ((unsigned char*)&sockaddr.sin_addr.s_addr)[1], ((unsigned char*)&sockaddr.sin_addr.s_addr)[2], ((unsigned char*)&sockaddr.sin_addr.s_addr)[3]);

    if (connect(hSocket, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) != SOCKET_ERROR)
    {
            /// debug print
            mapPrintLimit[addrConnect.ip] = 0;
            printf("connected %d.%d.%d.%d\n", ((unsigned char*)&sockaddr.sin_addr.s_addr)[0], ((unsigned char*)&sockaddr.sin_addr.s_addr)[1], ((unsigned char*)&sockaddr.sin_addr.s_addr)[2], ((unsigned char*)&sockaddr.sin_addr.s_addr)[3]);

        // Add node
        CNode* pnode = new CNode(hSocket, addrConnect);
        if (nTimeout != 0)
            pnode->AddRef(nTimeout);
        else
            pnode->AddRef();
        CRITICAL_BLOCK(cs_vNodes)
            vNodes.push_back(pnode);
        return pnode;
    }
    else
    {
        //// todo: need to set last failed connect time, and increment a failed to connect counter
        /// debug print
        if ((mapPrintLimit[addrConnect.ip]++) % 20 == 0)
            printf("connection failed %d\n", WSAGetLastError());
        return NULL;
    }
}

void CNode::Disconnect()
{
    printf("disconnecting node %s\n", addr.ToString().c_str());

    closesocket(hSocket);

    // All of a nodes broadcasts and subscriptions are automatically torn down
    // when it goes down, so a node has to stay up to keep its broadcast going.

    // Cancel and delete unsourced broadcasts
    CRITICAL_BLOCK(cs_mapTables)
        for (map<uint256, CTable>::iterator mi = mapTables.begin(); mi != mapTables.end();)
            AdvertRemoveSource(this, MSG_TABLE, 0, (*(mi++)).second);
    CRITICAL_BLOCK(cs_mapProducts)
        for (map<uint256, CProduct>::iterator mi = mapProducts.begin(); mi != mapProducts.end();)
            AdvertRemoveSource(this, MSG_PRODUCT, 0, (*(mi++)).second);

    // Cancel subscriptions
    for (unsigned int nChannel = 0; nChannel < vfSubscribe.size(); nChannel++)
        if (vfSubscribe[nChannel])
            CancelSubscribe(nChannel);
}













void ThreadSocketHandler(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadSocketHandler(parg));

    loop
    {
        vfThreadRunning[0] = true;
        CheckForShutdown(0);
        try
        {
            ThreadSocketHandler2(parg);
        }
        CATCH_PRINT_EXCEPTION("ThreadSocketHandler()")
        vfThreadRunning[0] = false;
        Sleep(5000);
    }
}

void ThreadSocketHandler2(void* parg)
{
    printf("ThreadSocketHandler started\n");
    SOCKET hListenSocket = *(SOCKET*)parg;
    list<CNode*> vNodesDisconnected;
    int nPrevNodeCount = 0;

    loop
    {
        //
        // Disconnect nodes
        //
        CRITICAL_BLOCK(cs_vNodes)
        {
            // Disconnect duplicate connections
            map<unsigned int, CNode*> mapFirst;
            foreach(CNode* pnode, vNodes)
            {
                unsigned int ip = pnode->addr.ip;
                if (mapFirst.count(ip) && addrLocalHost.ip < ip)
                {
                    // In case two nodes connect to each other at once,
                    // the lower ip disconnects its outbound connection
                    CNode* pnodeExtra = mapFirst[ip];

                    if (pnodeExtra->GetRefCount() > (pnodeExtra->fNetworkNode ? 1 : 0))
                        swap(pnodeExtra, pnode);

                    if (pnodeExtra->GetRefCount() <= (pnodeExtra->fNetworkNode ? 1 : 0))
                    {
                        printf("(%d nodes) disconnecting duplicate: %s", vNodes.size(), pnodeExtra->addr.ToString().c_str());
                        if (pnodeExtra->fNetworkNode && !pnode->fNetworkNode)
                        {
                            pnode->AddRef();
                            swap(pnodeExtra->fNetworkNode, pnode->fNetworkNode);
                            pnodeExtra->Release();
                        }
                        pnodeExtra->fDisconnect = true;
                    }
                }
                mapFirst[ip] = pnode;
            }

            // Disconnect unused nodes
            vector<CNode*> vNodesCopy = vNodes;
            foreach(CNode* pnode, vNodesCopy)
            {
                if (pnode->ReadyToDisconnect() && pnode->vRecv.empty() && pnode->vSend.empty())
                {
                    // remove from vNodes
                    vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());
                    pnode->Disconnect();

                    // hold in disconnected pool until all refs are released
                    pnode->nReleaseTime = max(pnode->nReleaseTime, GetTime() + 5 * 60);
                    if (pnode->fNetworkNode)
                        pnode->Release();
                    vNodesDisconnected.push_back(pnode);
                }
            }

            // Delete disconnected nodes
            list<CNode*> vNodesDisconnectedCopy = vNodesDisconnected;
            foreach(CNode* pnode, vNodesDisconnectedCopy)
            {
                // wait until threads are done using it
                if (pnode->GetRefCount() <= 0)
                {
                    bool fDelete = false;
                    TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                     TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                      TRY_CRITICAL_BLOCK(pnode->cs_mapRequests)
                       TRY_CRITICAL_BLOCK(pnode->cs_inventory)
                        fDelete = true;
                    if (fDelete)
                    {
                        vNodesDisconnected.remove(pnode);
                        delete pnode;
                    }
                }
            }
        }
        if (vNodes.size() != nPrevNodeCount)
        {
            nPrevNodeCount = vNodes.size();
            MainFrameRepaint();
        }


        //
        // Find which sockets have data to receive
        //
        struct timeval timeout;
        timeout.tv_sec  = 0;
        timeout.tv_usec = 50000; // frequency to poll pnode->vSend

        struct fd_set fdsetRecv;
        struct fd_set fdsetSend;
        FD_ZERO(&fdsetRecv);
        FD_ZERO(&fdsetSend);
        SOCKET hSocketMax = 0;
        FD_SET(hListenSocket, &fdsetRecv);
        hSocketMax = max(hSocketMax, hListenSocket);
        CRITICAL_BLOCK(cs_vNodes)
        {
            foreach(CNode* pnode, vNodes)
            {
                FD_SET(pnode->hSocket, &fdsetRecv);
                hSocketMax = max(hSocketMax, pnode->hSocket);
                TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                    if (!pnode->vSend.empty())
                        FD_SET(pnode->hSocket, &fdsetSend);
            }
        }

        vfThreadRunning[0] = false;
        int nSelect = select(hSocketMax + 1, &fdsetRecv, &fdsetSend, NULL, &timeout);
        vfThreadRunning[0] = true;
        CheckForShutdown(0);
        if (nSelect == SOCKET_ERROR)
        {
            int nErr = WSAGetLastError();
            printf("select failed: %d\n", nErr);
            for (int i = 0; i <= hSocketMax; i++)
            {
                FD_SET(i, &fdsetRecv);
                FD_SET(i, &fdsetSend);
            }
            Sleep(timeout.tv_usec/1000);
        }
        LARGE_INTEGER PerformanceCount;
        QueryPerformanceCounter(&PerformanceCount);
        RAND_add(&PerformanceCount.LowPart, sizeof(PerformanceCount.LowPart), 1.0);

        //// debug
        //foreach(CNode* pnode, vNodes)
        //{
        //    printf("vRecv = %-5d ", pnode->vRecv.size());
        //    printf("vSend = %-5d    ", pnode->vSend.size());
        //}
        //printf("\n");


        //
        // Accept new connections
        //
        if (FD_ISSET(hListenSocket, &fdsetRecv))
        {
            struct sockaddr_in sockaddr;
            int len = sizeof(sockaddr);
            SOCKET hSocket = accept(hListenSocket, (struct sockaddr*)&sockaddr, &len);
            CAddress addr(sockaddr.sin_addr.s_addr, sockaddr.sin_port);
            if (hSocket == INVALID_SOCKET)
            {
                if (WSAGetLastError() != WSAEWOULDBLOCK)
                    printf("ERROR ThreadSocketHandler accept failed: %d\n", WSAGetLastError());
            }
            else
            {
                printf("%s accepted connection from %s\n", addrLocalHost.ToString().c_str(), addr.ToString().c_str());
                CNode* pnode = new CNode(hSocket, addr);
                pnode->AddRef();
                pnode->fInbound = true;
                CRITICAL_BLOCK(cs_vNodes)
                    vNodes.push_back(pnode);
            }
        }


        //
        // Service each socket
        //
        vector<CNode*> vNodesCopy;
        CRITICAL_BLOCK(cs_vNodes)
            vNodesCopy = vNodes;
        foreach(CNode* pnode, vNodesCopy)
        {
            CheckForShutdown(0);
            SOCKET hSocket = pnode->hSocket;

            //
            // Receive
            //
            if (FD_ISSET(hSocket, &fdsetRecv))
            {
                TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                {
                    CDataStream& vRecv = pnode->vRecv;
                    unsigned int nPos = vRecv.size();

                    // typical socket buffer is 8K-64K
                    const unsigned int nBufSize = 0x10000;
                    vRecv.resize(nPos + nBufSize);
                    int nBytes = recv(hSocket, &vRecv[nPos], nBufSize, 0);
                    vRecv.resize(nPos + max(nBytes, 0));
                    if (nBytes == 0)
                    {
                        // socket closed gracefully
                        if (!pnode->fDisconnect)
                            printf("recv: socket closed\n");
                        pnode->fDisconnect = true;
                    }
                    else if (nBytes < 0)
                    {
                        // socket error
                        int nErr = WSAGetLastError();
                        if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                        {
                            if (!pnode->fDisconnect)
                                printf("recv failed: %d\n", nErr);
                            pnode->fDisconnect = true;
                        }
                    }
                }
            }

            //
            // Send
            //
            if (FD_ISSET(hSocket, &fdsetSend))
            {
                TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                {
                    CDataStream& vSend = pnode->vSend;
                    if (!vSend.empty())
                    {
                        int nBytes = send(hSocket, &vSend[0], vSend.size(), 0);
                        if (nBytes > 0)
                        {
                            vSend.erase(vSend.begin(), vSend.begin() + nBytes);
                        }
                        else if (nBytes == 0)
                        {
                            if (pnode->ReadyToDisconnect())
                                pnode->vSend.clear();
                        }
                        else
                        {
                            printf("send error %d\n", nBytes);
                            if (pnode->ReadyToDisconnect())
                                pnode->vSend.clear();
                        }
                    }
                }
            }
        }


        Sleep(10);
    }
}










void ThreadOpenConnections(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadOpenConnections(parg));

    loop
    {
        vfThreadRunning[1] = true;
        CheckForShutdown(1);
        try
        {
            ThreadOpenConnections2(parg);
        }
        CATCH_PRINT_EXCEPTION("ThreadOpenConnections()")
        vfThreadRunning[1] = false;
        Sleep(5000);
    }
}

void ThreadOpenConnections2(void* parg)
{
    printf("ThreadOpenConnections started\n");
    unsigned int nTries = 0;
    loop
    {
        //// number of connections may still need to be increased before release
        // Initiate network connections
        if (vNodes.size() < 5 && vNodes.size() < mapAddresses.size())
        {
            // Make a list of unique class C's
            unsigned char pchIPCMask[4] = { 0xff, 0xff, 0xff, 0x00 };
            unsigned int nIPCMask = *(unsigned int*)pchIPCMask;
            vector<unsigned int> vIPC;
            CRITICAL_BLOCK(cs_mapAddresses)
            {
                vIPC.reserve(mapAddresses.size());
                unsigned int nPrev = 0;
                foreach(const PAIRTYPE(vector<unsigned char>, CAddress)& item, mapAddresses)
                {
                    const CAddress& addr = item.second;
                    if (!addr.IsIPv4())
                        continue;

                    // Taking advantage of mapAddresses being in sorted order,
                    // with IPs of the same class C grouped together.
                    unsigned int ipC = addr.ip & nIPCMask;
                    if (ipC != nPrev)
                        vIPC.push_back(nPrev = ipC);
                }
            }

            //
            // The IP selection process is designed to limit vulnerability to address flooding.
            // Any class C (a.b.c.?) has an equal chance of being chosen, then an IP is
            // chosen within the class C.  An attacker may be able to allocate many IPs, but
            // they would normally be concentrated in blocks of class C's.  They can hog the
            // attention within their class C, but not the whole IP address space overall.
            // A lone node in a class C will get as much attention as someone holding all 255
            // IPs in another class C.
            //
            bool fSuccess = false;
            int nLimit = vIPC.size();
            while (!fSuccess && nLimit-- > 0)
            {
                // Choose a random class C
                uint64 nRand;
                RAND_bytes((unsigned char*)&nRand, sizeof(nRand));
                unsigned int ipC = vIPC[nRand % vIPC.size()];

                // Organize all addresses in the class C by IP
                map<unsigned int, vector<CAddress> > mapIP;
                CRITICAL_BLOCK(cs_mapAddresses)
                {
                    for (map<vector<unsigned char>, CAddress>::iterator mi = mapAddresses.lower_bound(CAddress(ipC, 0).GetKey());
                         mi != mapAddresses.upper_bound(CAddress(ipC | ~nIPCMask, 0xffff).GetKey());
                         ++mi)
                    {
                        const CAddress& addr = (*mi).second;
                        mapIP[addr.ip].push_back(addr);
                    }
                }

                // Choose a random IP in the class C
                RAND_bytes((unsigned char*)&nRand, sizeof(nRand));
                map<unsigned int, vector<CAddress> >::iterator mi = mapIP.begin();
                advance(mi, nRand % mapIP.size());

                // Once we've chosen an IP, we'll try every given port before moving on
                foreach(const CAddress& addrConnect, (*mi).second)
                {
                    if (addrConnect.ip == addrLocalHost.ip || !addrConnect.IsIPv4() || FindNode(addrConnect.ip))
                        continue;

                    CNode* pnode = ConnectNode(addrConnect);
                    if (!pnode)
                        continue;
                    pnode->fNetworkNode = true;

                    // Advertise our address
                    vector<CAddress> vAddrToSend;
                    vAddrToSend.push_back(addrLocalHost);
                    pnode->PushMessage("addr", vAddrToSend);

                    // Get as many addresses as we can
                    pnode->PushMessage("getaddr");

                    ////// should the one on the receiving end do this too?
                    // Subscribe our local subscription list
                    const unsigned int nHops = 0;
                    for (unsigned int nChannel = 0; nChannel < pnodeLocalHost->vfSubscribe.size(); nChannel++)
                        if (pnodeLocalHost->vfSubscribe[nChannel])
                            pnode->PushMessage("subscribe", nChannel, nHops);

                    fSuccess = true;
                    break;
                }
            }

            nTries++;
        }

        // Wait
        vfThreadRunning[1] = false;
        Sleep(100 + nTries * 5);
        vfThreadRunning[1] = true;
        CheckForShutdown(1);
    }
}








void ThreadMessageHandler(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadMessageHandler(parg));

    loop
    {
        vfThreadRunning[2] = true;
        CheckForShutdown(2);
        try
        {
            ThreadMessageHandler2(parg);
        }
        CATCH_PRINT_EXCEPTION("ThreadMessageHandler()")
        vfThreadRunning[2] = false;
        Sleep(5000);
    }
}

void ThreadMessageHandler2(void* parg)
{
    printf("ThreadMessageHandler started\n");
    loop
    {
        // Poll the connected nodes for messages
        vector<CNode*> vNodesCopy;
        CRITICAL_BLOCK(cs_vNodes)
            vNodesCopy = vNodes;
        foreach(CNode* pnode, vNodesCopy)
        {
            pnode->AddRef();

            // Receive messages
            TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                ProcessMessages(pnode);

            // Send messages
            TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                SendMessages(pnode);

            pnode->Release();
        }

        // Wait and allow messages to bunch up
        vfThreadRunning[2] = false;
        Sleep(200);
        vfThreadRunning[2] = true;
        CheckForShutdown(2);
    }
}









//// todo: start one thread per processor, use getenv("NUMBER_OF_PROCESSORS")
void ThreadBitcoinMiner(void* parg)
{
    vfThreadRunning[3] = true;
    CheckForShutdown(3);
    try
    {
        bool fRet = BitcoinMiner();
        printf("BitcoinMiner returned %s\n\n\n", fRet ? "true" : "false");
    }
    CATCH_PRINT_EXCEPTION("BitcoinMiner()")
    vfThreadRunning[3] = false;
}











bool StartNode(string& strError)
{
    strError = "";


    // Sockets startup
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR)
    {
        strError = strprintf("Error: TCP/IP socket library failed to start (WSAStartup returned error %d)", ret);
        printf("%s\n", strError.c_str());
        return false;
    }

    // Get local host ip
    char pszHostName[255];
    if (gethostname(pszHostName, 255) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Unable to get IP address of this computer (gethostname returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }
    struct hostent* pHostEnt = gethostbyname(pszHostName);
    if (!pHostEnt)
    {
        strError = strprintf("Error: Unable to get IP address of this computer (gethostbyname returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }
    addrLocalHost = CAddress(*(long*)(pHostEnt->h_addr_list[0]),
                             DEFAULT_PORT,
                             nLocalServices);
    printf("addrLocalHost = %s\n", addrLocalHost.ToString().c_str());

    // Create socket for listening for incoming connections
    SOCKET hListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (hListenSocket == INVALID_SOCKET)
    {
        strError = strprintf("Error: Couldn't open socket for incoming connections (socket returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    // Set to nonblocking, incomming connections will also inherit this
    u_long nOne = 1;
    if (ioctlsocket(hListenSocket, FIONBIO, &nOne) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Couldn't set properties on socket for incoming connections (ioctlsocket returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    // The sockaddr_in structure specifies the address family,
    // IP address, and port for the socket that is being bound
    int nRetryLimit = 15;
    struct sockaddr_in sockaddr;
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = addrLocalHost.ip;
    sockaddr.sin_port = addrLocalHost.port;
    if (bind(hListenSocket, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        if (nErr == WSAEADDRINUSE)
            strError = strprintf("Error: Unable to bind to port %s on this computer. The program is probably already running.", addrLocalHost.ToString().c_str());
        else
            strError = strprintf("Error: Unable to bind to port %s on this computer (bind returned error %d)", addrLocalHost.ToString().c_str(), nErr);
        printf("%s\n", strError.c_str());
        return false;
    }
    printf("bound to addrLocalHost = %s\n\n", addrLocalHost.ToString().c_str());

    // Listen for incoming connections
    if (listen(hListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Listening for incoming connections failed (listen returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }


    //
    // Start threads
    //
    if (_beginthread(ThreadSocketHandler, 0, new SOCKET(hListenSocket)) == -1)
    {
        strError = "Error: _beginthread(ThreadSocketHandler) failed";
        printf("%s\n", strError.c_str());
        return false;
    }

    if (_beginthread(ThreadOpenConnections, 0, NULL) == -1)
    {
        strError = "Error: _beginthread(ThreadOpenConnections) failed";
        printf("%s\n", strError.c_str());
        return false;
    }

    if (_beginthread(ThreadMessageHandler, 0, NULL) == -1)
    {
        strError = "Error: _beginthread(ThreadMessageHandler) failed";
        printf("%s\n", strError.c_str());
        return false;
    }

    return true;
}

bool StopNode()
{
    printf("StopNode()\n");
    fShutdown = true;
    nTransactionsUpdated++;
    while (count(vfThreadRunning.begin(), vfThreadRunning.end(), true))
        Sleep(10);
    Sleep(50);

    // Sockets shutdown
    WSACleanup();
    return true;
}

void CheckForShutdown(int n)
{
    if (fShutdown)
    {
        if (n != -1)
            vfThreadRunning[n] = false;
        _endthread();
    }
}
