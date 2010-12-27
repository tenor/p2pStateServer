/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Threading;

//TODO: Undefine NET20 symbol if targeting .NET 3.5
namespace P2PStateServer
{
    /// <summary>
    /// Represents a state server 
    /// </summary>
    public class StateServer
    {
        const string aspnetVersion = "2.0.50727"; //The messaging version of the state server
        const int PeerConnectionTimeout = 15; //15 seconds timeout for peer connections

        //The maximum backlogged actions to process for a single session when the actions are waiting for a transfer to complete.
        //If backlog exceeds this value, the backlog is considered a flood and the entire list is discarded
        //Web pages with a lot of AJAX can generate lots of silmultaneous calls, however most browsers
        //only allow a low number of silmultaneous AJAX call. 
        //See http://stackoverflow.com/questions/561046/how-many-concurrent-ajax-xmlhttprequest-requests-are-allowed-in-popular-browser
        //This value should be greater (a few multiples) of the highest number of concurrent ajax request modern browsers allow.
        const int MaxTransferEndedActionBackLog = 20;

        //The maximum number of backlogged messages a user can have in his/her queue
        //if the backlog exceeds this value, the backlog is considered a flood and all messages are discarded
        //This value should be high and greater (in a few multiples) than MaxTransferEndedActionBackLog because a user queue can
        //get really long legitimately if the server is slow and the user keeps refreshing the webpage.
        //Also AJAX apps can make a lot of session requests silmultaneously.
        //See http://stackoverflow.com/questions/561046/how-many-concurrent-ajax-xmlhttprequest-requests-are-allowed-in-popular-browser
        const int MaxUserMessageQueueBacklog = 50;

        //The number of message processing threads spawn is derived from this value multipled 
        //by the number of CPUs on the machine.
        const int CPUMessageProcessorMuliplier = 2;

        SHA256_AESAuthenticator authenticator;
        ServerSettings settings;
        bool isstopping;

        System.Net.Sockets.Socket wsListener = null;
        System.Net.Sockets.Socket peerListener = null;
        MessageFactory msgFactory;

        List<HashList<ServiceMessage>> serviceMessageList = new List<HashList<ServiceMessage>>(); //Service request queue
        int serviceMessagePointer = -1;
        object syncServiceMessage = new object(); //Synchronization object for service requests

        object syncExpectedTransfers = new object(); //Synchronization object for the expected transfers list
        object syncActiveExports = new object(); //Synchronization object for the exported transfers list
        object syncLivePeers = new object(); //Synchronization object for the Live Peers list
        object syncConnections = new object(); //Synchronization object for connections list
        object syncLivePeerEndPointTracker = new object(); //sync object for livePeerEndPointTracker
        List<ServiceSocket> livePeers = new List<ServiceSocket>(); //list of permanenltly connected peers
        List<ServiceSocket> connections = new List<ServiceSocket>();//List of all accepted incoming connections
        int connectingPeersCount = 0; //This is the current number of pending connections to peers 
        Dictionary<ServiceSocket, ServerSettings.HostEndPoint> livePeerEndPointTracker = new Dictionary<ServiceSocket, ServerSettings.HostEndPoint>(); //Dictionary of the endpoint of all live peers
        string serverIP = null; //Stores the local IP address of the network adapter peers connect to, and on which this peer connects to other peers


        //The session dictionary
        SessionDictionary sessDict = new SessionDictionary();
        //This dictionary contains a list of asynchronous requests made
        DateSortedDictionary<ServiceSocket, AsyncResultActions<ServiceSocket>> asyncRequests = new DateSortedDictionary<ServiceSocket, AsyncResultActions<ServiceSocket>>();
        //This dictionary contains a list of transfers that have been requested
        DateSortedDictionary<string, List<AsyncResultActions<string>>> expectedTransfers = new DateSortedDictionary<string, List<AsyncResultActions<string>>>();
        //This dictionary contains a list of actively exporting (outgoing) transfers
        Dictionary<string, List<AsyncResultActions<string>>> activeExports = new Dictionary<string, List<AsyncResultActions<string>>>();
        //This dictionary contains a list of recent network queries initiated by this peer
        DateSortedDictionary<Guid, object> queriesInitiated = new DateSortedDictionary<Guid, object>();
        //This dictionary contains a list of recent forwarded network queries that this peer has received
        DateSortedDictionary<int, object> queriesReceived = new DateSortedDictionary<int, object>();
        //This dictionary contains a list of recent transfers that this peer sent
        DateSortedDictionary<string, object> sentTransfers = new DateSortedDictionary<string, object>();

              

        //SHUTDOWN Related variables/objects
        //List of neighboring peers involved in the shutdown process
        List<ServerSettings.HostEndPoint> shutdownPeers;
        //List of session keys exported in the shutsown process
        List<string> shutdownKeys;
        //Dictionary used in tracking which shutdown peer is ransferring which session key
        Dictionary<string, ServerSettings.HostEndPoint> shutdownKeyEndPointTracker;
        object syncShutdownPeers = new object(); //sync object for shutdownPeers list
        object syncShutdownKeys = new object(); //sync object for keys list
        object syncShutdownKeyEndPointTracker = new object(); //sync object for shutdownKeyEndPointTracker



        /// <summary>
        /// Initializes a new instance of the StateServer class
        /// </summary>
        /// <param name="Settings">Settings for the state server operation</param>
        /// <param name="Authenticator">The authenticator object used to authenticate peers and protect data</param>
        public StateServer(ServerSettings Settings, SHA256_AESAuthenticator Authenticator)
        {
            this.settings = Settings;
            this.authenticator = Authenticator;
            msgFactory = new MessageFactory(this);

        }


        #region Properties
        /// <summary>
        /// Gets the messaging version of the server
        /// </summary>
        internal string ASPNETVersion
        {
            get { return aspnetVersion; }
        }

        /// <summary>
        /// Gets the session dictionary
        /// </summary>
        internal SessionDictionary SessionTable
        {
            get { return sessDict; }
        }

        /// <summary>
        /// Gets the authentication/encryption object 
        /// </summary>
        internal SHA256_AESAuthenticator Authenticator
        {
            get { return authenticator; }
        }

        /// <summary>
        /// Gets the configured settings
        /// </summary>
        internal ServerSettings Settings
        {
            get { return settings; }
        }

        /// <summary>
        /// Gets a value indicating whether the server is shutting down
        /// </summary>
        internal bool IsStopping
        {
            get { return isstopping; }
        }

        /// <summary>
        /// Gets the dictionary of asynchronous requests recently made by this server
        /// </summary>
        internal DateSortedDictionary<ServiceSocket, AsyncResultActions<ServiceSocket>> AsyncRequests
        {
            get { return asyncRequests; }
        }

        /// <summary>
        /// Gets a copy of the list of neighboring peers curently connected to this server
        /// </summary>
        internal ServiceSocket[] LivePeers
        {
            get
            {
                lock (syncLivePeers)
                {
                    return livePeers.ToArray();
                }
            }
        }

        /// <summary>
        /// Gets the dictionary of network queries recently initiated by this server
        /// </summary>
        internal DateSortedDictionary<Guid, object> QueriesInitiated
        {
            get { return queriesInitiated; }
        }

        /// <summary>
        /// Gets the dictionary of network queries recently received by this server
        /// </summary>
        internal DateSortedDictionary<int, object> QueriesReceived
        {
            get { return queriesReceived; }
        }

        /// <summary>
        /// Gets the dictionary of transfers recently sent by this server
        /// </summary>
        internal DateSortedDictionary<string, object> SentTransfers
        {
            get { return sentTransfers; }
        }

        /// <summary>
        /// Gets the local server IP of the network adapter peers connect to, and on which this peer connects through
        /// </summary>
        internal string ServerIP
        {
            get { return serverIP; }
        }


        #endregion

        #region Server Methods

        /// <summary>
        /// Adds a new permanent peer to the list of permanently connected peers
        /// </summary>
        /// <param name="Peer">The ServiceSocket for the connected peer</param>
        internal void NewLivePeer(ServiceSocket Peer)
        {
            lock (syncLivePeers)
            {

                //Discover local server IP via local end point of new peer
                if (serverIP == null)
                {
                    string ip = Peer.LocalIP;
                    if (ip != null && ip != string.Empty)
                    {
                        serverIP = ip;
                    }
                }

                //Add Peer
                if (!livePeers.Contains(Peer))
                {
                    livePeers.Add(Peer);
                }

            }
        }

        /// <summary>
        /// Adds a new Expected Transfer to the list of expected transfers
        /// </summary>
        /// <param name="SessionKey">The session resource key for the new Expected Transfer</param>
        /// <param name="ReceivedAction">Action to call, if transfer is received</param>
        /// <param name="TimeoutAction">Action to call, if transfer times out</param>
        /// <param name="TimeoutStamp">The time at which the transfer is considered timed out</param>
        /// <returns>The number of actions for this session resource (including the newly added one)</returns>
        internal int NewExpectedTransfer(string SessionKey, Action<string> ReceivedAction, System.Threading.WaitCallback TimeoutAction, DateTime TimeoutStamp)
        {
            AsyncResultActions<string> asyncResults = new AsyncResultActions<string>(SessionKey);
            asyncResults.Result1Action = ReceivedAction;
            asyncResults.TimeoutAction = TimeoutAction;

            List<AsyncResultActions<string>> actionList;

            lock (syncExpectedTransfers)
            {
                if (expectedTransfers.TryGetValue(SessionKey, out actionList))
                {
                    actionList.Add(asyncResults);
                }
                else
                {
                    actionList = new List<AsyncResultActions<string>>();
                    actionList.Add(asyncResults);
                    expectedTransfers.Add(TimeoutStamp, SessionKey, actionList);
                }

                return actionList.Count;
            }

        }

        /// <summary>
        /// Adds a new Active Export List
        /// </summary>
        /// <param name="SessionKey">The Session Resource key for the new List</param>
        internal void NewActiveExport(string SessionKey)
        {
            AsyncResultActions<string> asyncResults = new AsyncResultActions<string>(SessionKey);

            lock (syncActiveExports)
            {
                if (!activeExports.ContainsKey(SessionKey))
                {
                    activeExports.Add(SessionKey, new List<AsyncResultActions<string>>());
                }
                else
                {
                    //this should never happen because exports are synchronized - if it does happen, it indicates a wrong code sequence somewhere
                    Diags.Fail("ASSERTION FAILED -- Active export already exist in NewActiveExport()");
                }
            }

        }

        /// <summary>
        /// Appends a new Active Export Ended event to an existing Active Export List
        /// </summary>
        /// <param name="SessionKey">The Session Resource key List to append to</param>
        /// <param name="ExportEndedAction">The Active Export Ended action to append</param>
        internal void AppendActiveExportEndedEvent(string SessionKey, Action<string> ExportEndedAction)
        {

            AsyncResultActions<string> asyncResults = new AsyncResultActions<string>(SessionKey);
            asyncResults.Result1Action = ExportEndedAction;

            bool notFound = false;
            List<AsyncResultActions<string>> actionList = null;
            lock (syncActiveExports)
            {
                if (activeExports.TryGetValue(SessionKey, out actionList))
                {
                    actionList.Add(asyncResults);

                }
                else
                {
                    notFound = true;
                }
            }

            if (notFound)
            {
                //Export must have already ended so call the ExportEndedAction
                asyncResults.InvokeResult1Action();
            }

        }

        /// <summary>
        /// Removes an Active export from the list of recent active exports
        /// </summary>
        /// <param name="Key">The session resource key</param>
        /// <returns>List of attached export ended actions of removed exports</returns>
        internal List<AsyncResultActions<string>> RemoveActiveExport(string Key)
        {
            List<AsyncResultActions<string>> calls;
            lock (syncActiveExports)
            {
                if (activeExports.TryGetValue(Key, out calls))
                {
                    //Now remove the item from the list
                    if (activeExports.Remove(Key))
                    {
                        if (calls != null && calls.Count > MaxTransferEndedActionBackLog)
                        {
                            Diags.LogContentionDetected(Key, "Actions waiting for outgoing transfer exceeded " + MaxTransferEndedActionBackLog + ". All Actions will be ignored.");
                            calls.Clear();
                        }
                        return calls;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Callback method for incoming connections (for clients (web servers) and peers).
        /// </summary>
        /// <param name="ar">AsyncResult object obtained from ServiceSocket.Listen or Socket.BeginAccept</param>
        private void AcceptCallback(IAsyncResult ar)
        {
            System.Net.Sockets.Socket listener, incoming;
            try
            {
                listener = (System.Net.Sockets.Socket)ar.AsyncState;
                incoming = listener.EndAccept(ar);
            }
            catch(Exception ex)
            {
                Diags.LogSocketException(ex);
                return;
            }

            //Log this connection
            if (listener == peerListener)
            {
                Diags.LogNewPeerConnection(incoming);
            }
            else
            {
                Diags.LogNewWebServerConnection(incoming);
            }

            //Accept the next incoming connection
            try
            {
                listener.BeginAccept(AcceptCallback, listener);
            }
            catch (Exception ex)
            {
                Diags.LogSocketException(ex);

            }

            ServiceSocket handler = new ServiceSocket(incoming, listener == peerListener);
            handler.ReferenceTime = DateTime.UtcNow;

            //Add new connection to connections list
            lock (syncConnections)
            {
                connections.Add(handler);
            }
            //Create partial data
            HTTPPartialData partialData = new HTTPPartialData(handler);

            //Let handler receive incoming data -- do this for all other sockets everywhere
            handler.BeginReceive(partialData.Buffer, ReadCallback, partialData);


        }

        /// <summary>
        /// Callback method for reading data from connected sockets.
        /// </summary>
        /// <param name="ar">AsyncResult object obtained from ServiceSocket.BeginReceive</param>
        private void ReadCallback(IAsyncResult ar)
        {            
            try
            {

                HTTPPartialData partialData = (HTTPPartialData)ar.AsyncState;

                //Read data
                int bytesRead;
                bool errorReading;
                partialData.HandlerSocket.EndReceive(ar,out errorReading,out bytesRead);

                if (errorReading)
                {
                    //Drop Connection
                    partialData.HandlerSocket.Abort();
                    partialData = null; //lose the partial data
                    return;
                }

                //Append read data
                if (bytesRead > 0)
                {
                    partialData.Append(bytesRead);
                }
                else
                {
                    return;
                }

                partialData.HandlerSocket.ReferenceTime = DateTime.UtcNow;

                if (partialData.IsError)
                {
                    //Drop Connection
                    partialData.HandlerSocket.Abort();

                    partialData = null;

                }
                else if (partialData.IsComplete)
                {
                    //Create a HTTPMessage from this complete partial data
                    ServiceMessage msg = msgFactory.CreateFrom(partialData);

                    //Enqueue Message
                    lock (syncServiceMessage)
                    {
                        //Tag this message for diagnostics purposes;
                        Diags.TagMessage(msg);

                        int msgHash = msg.Resource.GetHashCode();


                        if (serviceMessageList.Count == 0)
                        {
                            HashList<ServiceMessage> hList = new HashList<ServiceMessage>(msgHash);
                            hList.Add(msg);
                            serviceMessageList.Add(hList);
                            serviceMessagePointer = 0;
                        }
                        else
                        {
                            //Look for queue in list for item with the same session(resource)
                            bool found = false;
                            for (int i = 0; i < serviceMessageList.Count; i++)
                            {
                                if (serviceMessageList[i].HashCode == msgHash)
                                {
                                    serviceMessageList[i].Add(msg);
                                    found = true;
                                    break;
                                }
                            }

                            if (!found)
                            {
                                HashList<ServiceMessage> hList = new HashList<ServiceMessage>(msgHash);
                                hList.Add(msg);
                                serviceMessageList.Add(hList);

                            }
                        }
                    }

                    //Create brand new Partial Data object and read from there
                    HTTPPartialData pData = new HTTPPartialData(partialData.HandlerSocket);
                    pData.HandlerSocket.BeginReceive(pData.Buffer, ReadCallback, pData);


                }
                else
                {
                    //Read/Expect more data                    
                    partialData.HandlerSocket.BeginReceive(partialData.Buffer, ReadCallback, partialData);
                }
            }
            catch (Exception ex)
            {
                Diags.LogSocketException(ex);
            }


        }

        /// <summary>
        /// Polls incoming messages and processes them.
        /// </summary>
        /// <remarks>
        /// Incoming requests are stored in a HashList for the request's session resource.
        /// This method polls the collection of HashLists in a round-robin fashion to ensure fairness across user requests.
        /// 
        /// The method runs continously and should be called from a dedicated (background) thread.
        /// </remarks>
        private void RunRequestsPoller()
        {
            const int SleepTimeOut = 1; //milliseconds

            while (true) //Loop forever
            {
                bool gotoSleep = false;
                bool queueDiscarded = false;
                ServiceMessage msg = null;

                lock (syncServiceMessage)
                {
                    if (serviceMessageList.Count == 0)
                    {
                        gotoSleep = true;
                    }
                    else
                    {
                        //Detect session contention here by detecting when a user queue is really long
                        if (serviceMessageList[serviceMessagePointer].Count > MaxUserMessageQueueBacklog)
                        {
                            Diags.LogContentionDetected("Length of message queue " + serviceMessageList[serviceMessagePointer][0].Resource + " exceeds MaxUserMessageQueueBacklog " + MaxUserMessageQueueBacklog, "Entire queue will be discarded");

                            //Discard that queue
                            serviceMessageList.RemoveAt(serviceMessagePointer);
                            if (serviceMessagePointer == serviceMessageList.Count) // outside boundary
                            {
                                serviceMessagePointer = 0;
                            }

                            queueDiscarded = true;
                        }
                        else
                        {

                            msg = serviceMessageList[serviceMessagePointer][0];
                            serviceMessageList[serviceMessagePointer].RemoveAt(0);

                            if (serviceMessageList[serviceMessagePointer].Count == 0)
                            {
                                serviceMessageList.RemoveAt(serviceMessagePointer);
                                if (serviceMessagePointer == serviceMessageList.Count) // outside boundary
                                {
                                    serviceMessagePointer = 0;
                                }
                            }
                            else
                            {
                                if (serviceMessagePointer == serviceMessageList.Count - 1) //At end of list
                                {
                                    serviceMessagePointer = 0;
                                }
                                else
                                {
                                    serviceMessagePointer++;
                                }
                            }
                        }


                    }
                }

                if (gotoSleep)
                {
                    Thread.Sleep(SleepTimeOut); //sleep for specified time
                }
                else if (!queueDiscarded)
                {
                    ProcessMessage(msg);
                }

            }
        }


        /// <summary>
        /// Processes high priority messaging timeouts
        /// </summary>
        /// <remarks>
        /// This method calls time-out actions for:
        /// 1. Expected transfers (that didn't come through)
        /// 2. Asynchronous replies that didn't respond on time.
        /// 
        /// The time-out actions are time critical and may be queued on the threadpool so as not to
        /// block the next time-out action.
        /// The method runs continously and should be called from a dedicated (background) thread.
        /// </remarks>
        private void RunMessageTimeoutProcessor()
        {
            const int SleepTimeOut = 10; //milliseconds

            while (true) //Loop forever
            {
                bool gotoSleep = true;

                #region Check for timed out expected transfers
                {
                    string oldestKey;
                    if (DictionaryCleaner<string, List<AsyncResultActions<string>>>.IsOldestExpired(expectedTransfers, DateTime.UtcNow, out oldestKey))
                    {
                        gotoSleep = false; //prevent thread from sleeping because there may be more items waiting to be scavenged

                        ThreadPool.QueueUserWorkItem(delegate(object not_used) { CallExpectedTransferTimeoutActions(oldestKey); });

                    }

                }

                #endregion

                #region Check for Timed-out Async Replies
                {
                    AsyncResultActions<ServiceSocket> calls;
                    if (DictionaryCleaner<ServiceSocket, AsyncResultActions<ServiceSocket>>.RemoveOldestIfExpired(asyncRequests, DateTime.UtcNow, out calls))
                    {
                        gotoSleep = false; //prevent thread from sleeping because there may be more items waiting to be scavenged                           
                        calls.ThreadPoolQueueTimeoutAction();

                    }
                }

                #endregion

                if (gotoSleep)
                {
                    Thread.Sleep(SleepTimeOut); //sleep for specified time
                }

            }
        }

        /// <summary>
        /// Cleans up low priority expired items
        /// </summary>
        /// <remarks>
        /// This method deletes expired elements from:
        /// 1. The session dictionary.
        /// 2. List of recently initiated network queries.
        /// 3. List of recently received network queries.
        /// 4. List of recently transferred sessions.
        /// 
        /// Cleaning these lists is not time-critical but are freed up regularly to free memory.
        /// The method runs continously and should be called from a dedicated (background) thread.
        /// </remarks>
        private void RunCleanupProcessor()
        {
            const int SleepTimeOut = 1000; //milliseconds
            DateTime startTime = DateTime.UtcNow;

            while (true) //Loop forever
            {
                bool gotoSleep = true;

                #region Flush Expired Session Dictionary Entries
                sessDict.Sweep();
                #endregion

                #region Check for expired initiated queries
                {
                    if (DictionaryCleaner<Guid, object>.RemoveOldestIfExpired(queriesInitiated, DateTime.UtcNow)) gotoSleep = false;
                }
                #endregion

                #region Check for expired received queries
                {
                    if (DictionaryCleaner<int, object>.RemoveOldestIfExpired(queriesReceived, DateTime.UtcNow)) gotoSleep = false;
                }
                #endregion

                #region Check for expired transfers sent
                {
                    if (DictionaryCleaner<string, object>.RemoveOldestIfExpired(sentTransfers, DateTime.UtcNow)) gotoSleep = false;
                }
                #endregion

                //take a compulsory nap if after 5 seonds this thread haven't napped yet 'cos this thread can get really busy
                if (gotoSleep || DateTime.UtcNow - startTime > new TimeSpan(0, 0, 5))
                {
                    Thread.Sleep(SleepTimeOut); //sleep for specified time
                    startTime = DateTime.UtcNow;
                }

            }
        }


        /// <summary>
        /// Polls connections for inactivity and reconnects disconnected peers.
        /// </summary>
        /// <remarks>
        /// This method polls connections and discards stale connections.
        /// It pings peers every 10 seconds.
        /// It checks for and connects unconnected peers every 30 seconds.
        /// 
        /// The method runs continously and should be called from a dedicated (background) thread.
        /// </remarks>
        private void RunConnectionPoller()
        {
            const int SleepTimeOut = 1000; //milliseconds
            TimeSpan staleTimeout = new TimeSpan(0, 0, 30); // 30 seconds time out
            TimeSpan peerConnectInterval = new TimeSpan(0, 0, 30); // 30 seconds time out
            TimeSpan pingInterval = new TimeSpan(0, 0, 10); // 10 seconds time out
            DateTime lastPingTime = DateTime.UtcNow;
            DateTime lastPeerConnectTime = DateTime.UtcNow;

            while (true) //Loop forever
            {
                ServiceSocket[] peersSnap, connSnap;
                
                #region Ping peers
                if (DateTime.UtcNow - lastPingTime > pingInterval)
                {
                    //Get snapshot of peers list
                    peersSnap = LivePeers;

                    //Send pings
                    foreach (ServiceSocket peer in peersSnap)
                    {
                        PingMessage.Send(peer, ServerIP);
                    }

                    lastPingTime = DateTime.UtcNow;
                }
                #endregion

                #region Poll Live peers
                //Get a snapshot of the peers list

                peersSnap = LivePeers;

                //iterate through snapshot and look for stale connections
                foreach (ServiceSocket sock in peersSnap)
                {
                    if (!sock.IsConnected)
                    {
                        sock.Close();

                        //Remove the live peer from the list
                        lock (syncLivePeers)
                        {
                            livePeers.Remove(sock);
                        }

                        //Remove the endpoint tracker from the dictionary
                        lock (syncLivePeerEndPointTracker)
                        {
                            livePeerEndPointTracker.Remove(sock);
                        }

                    }
                    else if (DateTime.UtcNow - sock.ReferenceTime > staleTimeout)
                    {
                        //Connection is stale
                        Diags.LogDisconnectingSocket(sock.RemoteIP, sock.FromPeerListener, "Connection is stale");

                        sock.Close(); 

                        //Remove the live peer from the list
                        lock (syncLivePeers)
                        {
                            livePeers.Remove(sock);
                        }

                        //Remove the endpoint tracker from the dictionary
                        lock (syncLivePeerEndPointTracker)
                        {
                            livePeerEndPointTracker.Remove(sock);
                        }

                    }
                }
                #endregion

                #region Poll standing incoming connections

                //Get a snapshot of the connections list
                
                lock (syncConnections)
                {
                    connSnap = connections.ToArray();
                }

                //iterate through snapshot and look for stale connections
                foreach (ServiceSocket sock in connSnap)
                {
                    if (!sock.IsConnected)
                    {
                        sock.Close();

                        //Remove the connection from the list
                        lock (syncConnections)
                        {
                            connections.Remove(sock);
                        }

                    }
                    else if (DateTime.UtcNow - sock.ReferenceTime > staleTimeout)
                    {
                        //TODO: ENHANCEMENT: Do not disconnect web server client if it's waiting for a response

                        //Connection is stale
                        Diags.LogDisconnectingSocket(sock.RemoteIP, sock.FromPeerListener, "Connection is stale");
                        sock.Close(); 

                        //Remove the connection from the list
                        lock (syncConnections)
                        {
                            connections.Remove(sock);
                        }
                    }
                }

                #endregion

                #region Connect unconnected peers
                if (DateTime.UtcNow - lastPeerConnectTime > peerConnectInterval)
                {
                    //Get snapshot of peers list
                    peersSnap = LivePeers;

                    List<ServerSettings.HostEndPoint> unConnected = new List<ServerSettings.HostEndPoint>(settings.Peers);

                    //look for connected endpoints and remove them from this new list
                    foreach (ServiceSocket peer in peersSnap)
                    {
                        ServerSettings.HostEndPoint connectedEndPoint;
                        if(livePeerEndPointTracker.TryGetValue(peer,out connectedEndPoint ))
                        {
                            unConnected.Remove(connectedEndPoint);
                        }
                    }

                    //Connect to unconnected endpoints if the number of connections already in progress is less than the endpoints
                    if (connectingPeersCount < unConnected.Count)
                    {
                        foreach (ServerSettings.HostEndPoint endPoint in unConnected)
                        {
                            ConnectPeer(endPoint);
                        }
                    }

                    lastPeerConnectTime = DateTime.UtcNow;
                }
                #endregion

                Thread.Sleep(SleepTimeOut); //sleep for specified time


            }
        }

        /// <summary>
        /// Calls all Timeout Actions attached to an expected transfer
        /// </summary>
        /// <param name="Key">The timed-out Session Resource Key</param>
        private void CallExpectedTransferTimeoutActions(string Key)
        {
            try
            {
                List<AsyncResultActions<string>> calls;
                bool removed = false;
                lock (syncExpectedTransfers)
                {
                    if (expectedTransfers.TryGetValue(Key, out calls))
                    {
                        //Now remove the item from the list
                        if (expectedTransfers.Remove(Key))
                        {
                            removed = true;
                        }
                    }
                }

                if (removed)
                {
                    if (calls.Count <= MaxTransferEndedActionBackLog)
                    {
                        //Call all timeout actions in the calls list

                        foreach (AsyncResultActions<string> call in calls)
                        {
                            call.InvokeTimeoutAction();
                        }
                    }
                    else
                    {
                        Diags.LogContentionDetected(Key, "On Timeout: Actions waiting for incoming transfer exceeded " + MaxTransferEndedActionBackLog + ". All Actions will be ignored.");
                    }

                }
            }
            catch (Exception ex)
            {
                Diags.LogApplicationError("Error in CallExpectedTimeoutActions(" + Key + ")", ex);
            }
        }

        /// <summary>
        /// Calls all Received Actions attached to an expected transfer
        /// </summary>
        /// <param name="Key">The Received Session Resource Key</param>
        internal void CallExpectedTransferReceivedActions(string Key)
        {
            List<AsyncResultActions<string>> calls;
            bool removed = false;
            lock (syncExpectedTransfers)
            {
                if (expectedTransfers.TryGetValue(Key, out calls))
                {
                    //Now remove the item from the list
                    if (expectedTransfers.Remove(Key))
                    {
                        removed = true;
                    }
                }
            }

            if (removed)
            {

                if (calls.Count <= MaxTransferEndedActionBackLog)
                {
                    //Execute all success/found actions in the calls list

                    foreach (AsyncResultActions<string> call in calls)
                    {
                        call.InvokeResult1Action(); //Result1 is the success action
                    }
                }
                else
                {
                    Diags.LogContentionDetected(Key, "On Received: Actions waiting for incoming transfer exceeded " + MaxTransferEndedActionBackLog + ". All Actions will be ignored.");
                }

            }
        }

        /// <summary>
        /// Processes a received message
        /// </summary>
        /// <param name="Message">Message to process</param>
        private void ProcessMessage(ServiceMessage Message)
        {

            Diags.LogNewMessage(Message);

            try
            {
                Message.Process();
            }
            catch (Exception ex)
            {
                Diags.LogMessageError(Message, ex);
            }

        }

        /// <summary>
        /// Starts the server
        /// </summary>
        public void Start()
        {

            if (!settings.StandaloneMode)
            {
                // Start Listening on Peer Socket
                peerListener = ServiceSocket.Listen(settings.PeerPort, AcceptCallback);

                if (peerListener == null)
                    throw new ApplicationException("Unable to listen on Peer port. Another process may already be listening on this port");

            }


            // Start Listening on Web Server Socket
            wsListener = ServiceSocket.Listen(settings.WebserverPort, AcceptCallback);

            if (wsListener == null)
                throw new ApplicationException("Unable to listen on Web server port. Another process may already be listening on this port");



            //Connect to peers
            foreach (ServerSettings.HostEndPoint endPoint in settings.Peers)
            {
                ConnectPeer(endPoint);
            }

            //Start Messages Pollers
            for (int i = 0; i < Environment.ProcessorCount * CPUMessageProcessorMuliplier; i++)
            {
                Thread requestsPoller = new Thread(RunRequestsPoller);
                requestsPoller.Name = "Message Processor " + (i + 1);
                requestsPoller.IsBackground = true;
                requestsPoller.Start();
            }

            //Start Thread that services high priority time outs namely timeouts on HTTP requests and expected transfers that never showed up
            Thread scavenger1 = new Thread(RunMessageTimeoutProcessor);
            scavenger1.Name = "Message Timeout processor";
            scavenger1.IsBackground = true;
            scavenger1.Start();

            //Start Thread that services lower priority time outs like expired sessions, and recently initiated and received queries
            Thread scavenger2 = new Thread(RunCleanupProcessor);
            scavenger2.Name = "Cleanup";
            scavenger2.IsBackground = true;
            scavenger2.Start();


#if !DISABLE_CONNECTION_MANAGEMENT //Set this symbol when performing complex debugs, because it's harder to debug when the peer is constantly pinging and stuff

            //If StandaloneMode = false, Start a thread that pings all permanent peers (incoming and outgoing) every 15 seconds
            //and also initiates connections to unconnected peers every 30 seconds
            if (!settings.StandaloneMode)
            {
                Thread connectionPoller = new Thread(RunConnectionPoller);
                connectionPoller.Name = "Cleanup";
                connectionPoller.IsBackground = true;
                connectionPoller.Start();
            }

#endif

        }

        /// <summary>
        /// Stops the server. initiates the shutdown process
        /// </summary>
        public void Stop()
        {

            if (isstopping) return; //Already shutting down

            Diags.LogShuttingdownMessage();

            //Set IsStoping property to true
            isstopping = true;

            //Close web server socket
            try
            {
                wsListener.Close();
            }
            catch { }


            //Transfer out all sessions to neighboring peers
            ShutdownTransferSessions();

            //Try again -- some session transfers may have failed and returned back to this peer (and not picked up by another transferring connection)
            //This can happen if an export was already in progress when the shutdown started and then later failed or if the last transferring socket had a problem with the transfer
            ShutdownTransferSessions();

            //Wait two seconds for internal messages to fade
            Thread.Sleep(2000);

            //Close peer listening socket
            try
            {
                peerListener.Close();
            }
            catch { }


            //Close all live peer connections

            //Get a snapshot of the peers list
            ServiceSocket[] snap = LivePeers;

            //iterate through snapshot and close connections
            foreach (ServiceSocket sock in snap)
            {
                sock.Close();
            }

            //Close all other standing connections

            //Get a snapshot of the connections list            
            lock (syncConnections)
            {
                snap = connections.ToArray();
            }

            //iterate through snapshot and close connections
            foreach (ServiceSocket sock in snap)
            {
                sock.Close();
            }


        }
        #endregion

        #region Shutdown Transfer methods

        /// <summary>
        /// Transfers all sessions to neighboring peers due to a shut down
        /// </summary>
        private void ShutdownTransferSessions()
        {
            //TODO: ENHANCEMENT: for peers that don't have any peers in settings, 
            //they should get a list of live peers to transfer session to.
            //Even peers with dead peers can use this list
            //Peers will learn about the true host of their neighbors from the host line in 
            //ping message therefore ping requests must have the correct host

            shutdownKeys = sessDict.Keys;
            shutdownPeers = new List<ServerSettings.HostEndPoint>();
            shutdownKeyEndPointTracker = new Dictionary<string, ServerSettings.HostEndPoint>();
            if (!settings.StandaloneMode && settings.Peers.Count > 0 && shutdownKeys.Count > 0)
            {
                //Kickstart the transfer process for each peer
                foreach (ServerSettings.HostEndPoint neighbor in settings.Peers)
                {
                    string key = DequeueShutdownSessionKey();

                    if (key != null)
                    {
                        lock (syncShutdownPeers)
                        {
                            shutdownPeers.Add(neighbor);
                        }

                        lock (syncShutdownKeyEndPointTracker)
                        {
                            shutdownKeyEndPointTracker[key] = neighbor;
                        }

                        StartFirstShutdownTransfer(key, neighbor);

                    }
                    else
                    {
                        break; //no session key left in queue
                    }
                }

                int peerCount, keyCount, exportCount;
                //Loop until keys are all gone OR valid peers are all gone
                do
                {
                    //Get peer count and key count and exports

                    lock (syncShutdownPeers)
                    {
                        peerCount = shutdownPeers.Count;
                    }
                    lock (syncShutdownKeys)
                    {
                        keyCount = shutdownKeys.Count;
                    }
                    lock (syncActiveExports)
                    {
                        exportCount = activeExports.Count;
                    }

                    Thread.Sleep(500); //half a second to allow ongoing transfers complete
                } while (exportCount > 0 && (peerCount > 0 || keyCount > 0));

            }
        }

        /// <summary>
        /// Initiates the first transfer due to a shutdown for a neighboring peer
        /// </summary>
        /// <param name="Resource">The session resource key</param>
        /// <param name="EndPoint">The peer end point</param>
        private void StartFirstShutdownTransfer(string Resource, ServerSettings.HostEndPoint EndPoint)
        {
            //state object used by shutdown methods are in an object array
            //object[0] = NewConnection (bool)
            //object[1] = if (NewConnection) IPHostEntry else PeerConnection 
            //object[2] = Resource

            object[] state = new object[3];
            state[0] = true;
            state[1] = EndPoint;
            state[2] = Resource;

            //Check if the requested session is here and begin transfer
            SessionActionResult res;
            try
            {
                res = sessDict.BeginExport(Resource, CompleteShutdownTransfer, state);
            }
            catch (Exception ex)
            {
                //reinsert key to list
                lock (syncShutdownKeys)
                {
                    shutdownKeys.Add(Resource);
                }

                //Something went wrong, so end export immediately
                Diags.Fail("Error in BeginExport .... " + ex.Message + "\r\n\r\n" + " .... Ending Export.\r\n");

                List<AsyncResultActions<string>> calls = RemoveActiveExport(Resource);
                sessDict.EndExport(Resource, false);
                if (calls != null) ShutdownCallExportEndedActions(calls);

            }

        }

        /// <summary>
        /// Starts another transfer on a connected transfer socket
        /// </summary>
        /// <param name="Resource">The session resource</param>
        /// <param name="PeerSocket">The peer transfer socket</param>
        private void StartNextShutdownTransfer(string Resource, ServiceSocket PeerSocket)
        {
            //context used by shutdown methods are in an object array
            //object[0] = NewConnection (bool)
            //object[1] = if (NewConnection) IPHostEntry else PeerConnection 
            //object[2] = Resource

            object[] state = new object[3];
            state[0] = false;
            state[1] = PeerSocket;
            state[2] = Resource;

            //Check if the requested session is here and begin transfer
            SessionActionResult res;
            try
            {
                res = sessDict.BeginExport(Resource, CompleteShutdownTransfer, state);
            }
            catch (Exception ex)
            {
                //reinsert key to list
                lock (syncShutdownKeys)
                {
                    shutdownKeys.Add(Resource);
                }

                //Something went wrong, so end export immediately
                Diags.Fail("Error in BeginExport .... " + ex.Message + "\r\n\r\n" + " .... Ending Export.\r\n");

                List<AsyncResultActions<string>> calls = RemoveActiveExport(Resource);
                sessDict.EndExport(Resource, false);
                if (calls != null) ShutdownCallExportEndedActions(calls);

            }

        }

        /// <summary>
        /// Completes the transfer due to a shutdown.
        /// Called by SessionDictionary.BeginExport if session was found and read
        /// </summary>
        /// <param name="Session">Session</param>
        /// <param name="StateObject">State object passed by SessionDictionary.BeginExport</param>
        private void CompleteShutdownTransfer(ISessionObject Session, object StateObject)
        {
            //Get resource/session key
            string resource = (string)((object[])StateObject)[2];

            //Declare Anonymous delegates
            const int sentTransferExpiryTime = 2; // 2 seconds is sufficient for a broadcast to traverse half a reasonable network
            Action<ServiceSocket> successAction = delegate(ServiceSocket transferSock)
                {
                    //Add this transfer to list of recently transferred sessions and have it expire in 2 seconds
                    SentTransfers.Add(DateTime.UtcNow + new TimeSpan(0, 0, sentTransferExpiryTime), resource, null);

                    ShutdownTransferSuccess(transferSock, resource);
                    Diags.LogTransferSuccess(resource);
                };

            Action<ServiceSocket> failedAction = delegate(ServiceSocket transferSock)
                {
                    ShutdownTransferFailure(transferSock, resource);
                    Diags.LogTransferFailed(resource, string.Empty);
                };

            Action<ServiceSocket> alreadyExistsAction = delegate(ServiceSocket transferSock)
                {
                    //Add this transfer to list of recently transferred sessions and have it expire in 2 seconds
                    SentTransfers.Add(DateTime.UtcNow + new TimeSpan(0, 0, sentTransferExpiryTime), resource, null);

                    ShutdownTransferSuccess(transferSock, resource);
                    Diags.LogTransferFailed(resource, "Resource already exists in remote peer -- deleted local copy");
                };

            Action<ServiceSocket> peerShuttingDownAction = delegate(ServiceSocket transferSock)
                {
                    ShutdownTransferFailure(transferSock, resource);
                    Diags.LogTransferFailed(resource, "Peer is shutting down");
                };

            WaitCallback timeoutAction = delegate(object transferSock)
                {
                    //This anonymous method can be called directly from a background thread so make sure it's exception-safe
                    try
                    {
                        ShutdownTransferFailure((ServiceSocket)transferSock, resource);
                        Diags.LogTransferFailed(resource, "Timed out");
                    }
                    catch (Exception ex)
                    {
                        Diags.LogApplicationError("TimeoutAction delegate error in CompleteShutdownTransfer", ex);
                    }
                };


            //Get Response information
            ISessionResponseInfo response = Session.CreateResponseInfo();

            NewActiveExport(resource); //create an entry in the exports list for this export

            if ((bool)((object[])StateObject)[0])
            {
                //New connection
                ServerSettings.HostEndPoint endpoint = (ServerSettings.HostEndPoint)((object[])StateObject)[1];
                TransferSession(endpoint, resource, response, Session.Data, successAction, failedAction, alreadyExistsAction, peerShuttingDownAction, timeoutAction);

            }
            else
            {
                //Standing connection
                ServiceSocket peer = (ServiceSocket)((object[])StateObject)[1];
                TransferSession(peer, resource, response, Session.Data, successAction, failedAction, alreadyExistsAction, peerShuttingDownAction, timeoutAction);
            }

        }

        /// <summary>
        /// Handles a successful transfer during a shutdown
        /// </summary>
        /// <param name="TransferringSocket">The transferring socket</param>
        /// <param name="Resource">The session resource key</param>
        private void ShutdownTransferSuccess(ServiceSocket TransferringSocket, string Resource)
        {
            if (TransferringSocket.CheckConnection())
            {
                //Begin the next transfer
                string key = DequeueShutdownSessionKey();

                if (key != null)
                {

                    lock (syncShutdownKeyEndPointTracker)
                    {
                        //Set the original endpoint for the successful resource transfer to the new transfer                        
                        shutdownKeyEndPointTracker[key] = shutdownKeyEndPointTracker[Resource];
                        //then remove the tracker for the previous request
                        shutdownKeyEndPointTracker.Remove(Resource);

                    }

                    StartNextShutdownTransfer(key, TransferringSocket);
                }
                else
                {
                    //Remove this peer
                    RemoveFromShutdownPeers(Resource);

                    //Disconnect
                    TransferringSocket.Close();
                }

            }
            else
            {
                //Remove this peer
                RemoveFromShutdownPeers(Resource);

                //Disconnect
                TransferringSocket.Close();

            }

            List<AsyncResultActions<string>> calls = RemoveActiveExport(Resource);
            SessionTable.EndExport(Resource, true);

            if (calls != null) ShutdownCallExportEndedActions(calls);

        }

        /// <summary>
        /// Handles a failed transfer during a shutdown
        /// </summary>
        /// <param name="TransferringSocket">The transferring socket</param>
        /// <param name="Resource">The session resource key</param>
        private void ShutdownTransferFailure(ServiceSocket TransferringSocket, string Resource)
        {

            //reinsert key to list
            lock (syncShutdownKeys)
            {
                shutdownKeys.Add(Resource);
            }

            //remove this peer from list of shutdown peers
            RemoveFromShutdownPeers(Resource);

            List<AsyncResultActions<string>> calls = RemoveActiveExport(Resource);
            SessionTable.EndExport(Resource, false);

            if (TransferringSocket.IsConnected)
            {
                Diags.LogDisconnectingPeer(TransferringSocket.RemoteIP);
                TransferringSocket.Close();

            }

            if (calls != null) ShutdownCallExportEndedActions(calls);

        }

        /// <summary>
        /// Calls any attached export ended Actions after a resource transfer has completed
        /// </summary>
        /// <param name="Actions">List of Actions to call</param>
        private static void ShutdownCallExportEndedActions(List<AsyncResultActions<string>> Actions)
        {
            if (Actions == null) return;

            //Call all actions in the action list
            foreach (AsyncResultActions<string> call in Actions)
            {
                call.InvokeResult1Action();
            }
        }

        /// <summary>
        /// Removes the peer transferring the specified session key from the list of shutdown transfer peers
        /// </summary>
        /// <param name="SessionKey">The session key</param>
        private void RemoveFromShutdownPeers(string SessionKey)
        {
            lock (syncShutdownPeers)
            {
                //Remove this peer from the list of shutdown peers

                ServerSettings.HostEndPoint peerEndPoint;
                lock (syncShutdownKeyEndPointTracker)
                {
                    peerEndPoint = shutdownKeyEndPointTracker[SessionKey];
                }

                if (shutdownPeers.Count > 0)
                {
                    shutdownPeers.Remove(peerEndPoint);
                }
            }
        }

        /// <summary>
        /// Dequeues the next session key from the shutdown transfer list
        /// </summary>
        /// <returns>Session key</returns>
        private string DequeueShutdownSessionKey()
        {
            string key = null;
            lock (syncShutdownKeys)
            {
                if (shutdownKeys.Count > 0)
                {
                    key = shutdownKeys[0];
                    shutdownKeys.Remove(key);
                }

            }
            return key;
        }



        #endregion

        #region Peer Connect/Callbacks

        /// <summary>
        /// Intiates a connection to a peer
        /// </summary>
        /// <param name="endPoint">The peer endpoint</param>
        private void ConnectPeer(ServerSettings.HostEndPoint endPoint)
        {
            if (!settings.StandaloneMode)
            {
                ServiceSocket peerSock = new ServiceSocket(true);

                Interlocked.Increment(ref connectingPeersCount);
                lock (syncLivePeerEndPointTracker)
                {
                    livePeerEndPointTracker[peerSock] = endPoint;
                }

                Diags.LogConnectingPeer(endPoint.ToString());

                peerSock.BeginConnect(endPoint.Host, endPoint.Port, PeerConnectCallback, peerSock);


            }
        }

        /// <summary>
        /// Callback method on connecting a peer
        /// </summary>
        /// <param name="ar">AsyncResult object obtained from BeginConnect</param>
        private void PeerConnectCallback(IAsyncResult ar)
        {
            ServiceSocket handler = (ServiceSocket)ar.AsyncState;
            handler.ReferenceTime = DateTime.UtcNow;
            handler.EndConnect(ar);

            if (!handler.IsConnected)
            {
                Diags.LogErrorConnectingPeer();
                handler.Close();
                lock (syncLivePeerEndPointTracker)
                {
                    livePeerEndPointTracker.Remove(handler);
                }
                Interlocked.Decrement(ref connectingPeersCount);
                return;
            }

            //Check if this peer is connected to the peer and if so disconnect.
            bool alreadyConnected;
            lock (syncLivePeers)
            {
                if (livePeers.Count > 0)
                {
                    alreadyConnected = livePeers.Find(delegate(ServiceSocket socket)
                    {
                        bool match;
                        try
                        {
                            match = socket.RemoteIP == handler.RemoteIP;
                        }
                        catch { return false; }
                        return match;
                    }) != null;
                }
                else
                {
                    alreadyConnected = false;
                }
            }

            if (alreadyConnected)
            {
                handler.Close();
                return;
            }

            HTTPPartialData partialData = new HTTPPartialData(handler);
            handler.BeginReceive(partialData.Buffer, ReadCallback, partialData);

            if (settings.AuthenticatePeers)
            {
                BeginAuthRequest.Send(handler, this, PeerConnectAuthSuccess, PeerConnectAuthFailed, PeerConnectAuthTimeout, new TimeSpan(0, 0, PeerConnectionTimeout));
            }
            else
            {
                PeerConnectAuthSuccess(handler);
            }

        }

        /// <summary>
        /// Callback method if a peer connect authentication is successful
        /// </summary>
        /// <param name="socket">ServiceSocket object</param>
        private void PeerConnectAuthSuccess(ServiceSocket socket)
        {
            NewLivePeer(socket);
            PingMessage.Send(socket,ServerIP);
            Interlocked.Decrement(ref connectingPeersCount);
        }

        /// <summary>
        /// Callback method if a peer connect authentication failed
        /// </summary>
        /// <param name="socket">ServiceSocket object</param>
        private void PeerConnectAuthFailed(ServiceSocket socket)
        {
            PeerConnectAuthTimeout(socket);
        }

        /// <summary>
        /// Callback method if a peer connect authentication times out
        /// </summary>
        /// <param name="socket">ServiceSocket object</param>
        /// <remarks>
        /// This method can be called directly from a background thread -- so make sure it's exception-safe
        /// </remarks>
        private void PeerConnectAuthTimeout(object socket)
        {
            //This method can be called directly from a background thread -- so make sure it's exception-safe
            try
            {
                ServiceSocket sock = (ServiceSocket)socket;
                if (sock.IsConnected)
                {
                    Diags.LogDisconnectingPeer(sock.RemoteIP);
                    sock.Abort();
                }
                lock (syncLivePeerEndPointTracker)
                {
                    livePeerEndPointTracker.Remove(sock);
                }
                Interlocked.Decrement(ref connectingPeersCount);
            }
            catch (Exception ex)
            {
                Diags.LogApplicationError("Error in PeerConnectAuthTimeout method", ex);
            }

        }

        #endregion

        #region Transfer Connect/ Anonymous callbacks

        /// <summary>
        /// Callback method on connecting to a peer for a transfer
        /// </summary>
        /// <param name="ar">AsyncResult object obtained from BeginConnect</param>
        private void TransferConnectCallback(IAsyncResult ar)
        {
            ServiceSocket handler = (ServiceSocket)((object[])ar.AsyncState)[0];
            string resourceKey = (string)((object[])ar.AsyncState)[1];
            SessionResponseInfo sessionInfo = (SessionResponseInfo)((object[])ar.AsyncState)[2];
            byte[] data = (byte[])((object[])ar.AsyncState)[3];
            Action<ServiceSocket> successAction = (Action<ServiceSocket>)((object[])ar.AsyncState)[4];
            Action<ServiceSocket> failedAction = (Action<ServiceSocket>)((object[])ar.AsyncState)[5];
            Action<ServiceSocket> alreadyExistsAction = (Action<ServiceSocket>)((object[])ar.AsyncState)[6];
            Action<ServiceSocket> peerShuttingDownAction = (Action<ServiceSocket>)((object[])ar.AsyncState)[7];
            System.Threading.WaitCallback timeoutAction = (System.Threading.WaitCallback)((object[])ar.AsyncState)[8];

            handler.EndConnect(ar);

            if (!handler.IsConnected)
            {
                Diags.LogErrorConnectingPeer();
                handler.Close();

                //Call the session transfer failed action
                if (failedAction != null) failedAction(handler);
                return;
            }

            HTTPPartialData partialData = new HTTPPartialData(handler);
            handler.BeginReceive(partialData.Buffer, ReadCallback, partialData);

            TransferSession(handler, resourceKey, sessionInfo, data, successAction, failedAction, alreadyExistsAction, peerShuttingDownAction, timeoutAction);

        }

        /// <summary>
        /// Initiates a session transfer to a peer
        /// </summary>
        /// <param name="endPoint">The peer endpoint to connect to</param>
        /// <param name="ResourceKey">The Session Resource key</param>
        /// <param name="SessionInfo">The Session information</param>
        /// <param name="Data">The Session data</param>
        /// <param name="SuccessAction">Action to call, if session was sucessfully transferred</param>
        /// <param name="FailAction">Action to call, if transfer failed</param>
        /// <param name="AlreadyExistsAction">Action to call, if recipient peer already has this session</param>
        /// <param name="PeerShuttingDownAction">Action to call, if recipient peer is shutting down</param>
        /// <param name="TimeoutAction">Action to call if transfer times out</param>
        internal void TransferSession(ServerSettings.HostEndPoint endPoint, string ResourceKey, ISessionResponseInfo SessionInfo, byte[] Data,
             Action<ServiceSocket> SuccessAction, Action<ServiceSocket> FailAction, Action<ServiceSocket> AlreadyExistsAction, Action<ServiceSocket> PeerShuttingDownAction, System.Threading.WaitCallback TimeoutAction)
        {
            if (!settings.StandaloneMode)
            {
                ServiceSocket peerSock = new ServiceSocket(true);
                Diags.LogConnectingSessionTransferPeer(endPoint.ToString());
                peerSock.BeginConnect(
                    endPoint.Host, endPoint.Port, TransferConnectCallback,
                    new object[9] { peerSock, ResourceKey, SessionInfo, Data,
                        SuccessAction,FailAction,AlreadyExistsAction,PeerShuttingDownAction, TimeoutAction}
                    );
            }
        }

        /// <summary>
        /// Initiates a session transfer to a standing peer connection
        /// </summary>
        /// <param name="ConnectedSocket">The connected socket</param>
        /// <param name="ResourceKey">The Session Resource key</param>
        /// <param name="SessionInfo">The Session information</param>
        /// <param name="Data">The Session data</param>
        /// <param name="SuccessAction">Action to call, if session was sucessfully transferred</param>
        /// <param name="FailedAction">Action to call, if transfer failed</param>
        /// <param name="AlreadyExistsAction">Action to call, if recipient peer already has this session</param>
        /// <param name="PeerShuttingDownAction">Action to call, if recipient peer is shutting down</param>
        /// <param name="TimeoutAction">Action to call if transfer times out</param>
        internal void TransferSession(ServiceSocket ConnectedSocket, string ResourceKey, ISessionResponseInfo SessionInfo, byte[] Data,
            Action<ServiceSocket> SuccessAction, Action<ServiceSocket> FailedAction, Action<ServiceSocket> AlreadyExistsAction, Action<ServiceSocket> PeerShuttingDownAction, System.Threading.WaitCallback TimeoutAction)
        {
            if (settings.AuthenticatePeers && !ConnectedSocket.IsAuthenticated)
            {
                Diags.LogTransferringSession(ResourceKey, ConnectedSocket.RemoteIP);

                BeginAuthRequest.Send
                    (
                        ConnectedSocket, this,

                        //Authentication succeeded delegate
                        delegate(ServiceSocket socket)
                        {
                            //Send the Set Transfer message
                            SetTransferRequest.Send(socket, this, ResourceKey, SessionInfo, Data,
                                SuccessAction, FailedAction, AlreadyExistsAction, PeerShuttingDownAction, TimeoutAction, new TimeSpan(0, 0, 0, 0, settings.NetworkQueryTimeout));
                        },

                        //Authentication failed delegate
                        delegate(ServiceSocket socket)
                        {
                            if (socket.IsConnected)
                            {
                                Diags.LogDisconnectingPeer(socket.RemoteIP);
                                socket.Abort();
                            }

                            //Call the session transfer failed action
                            if (FailedAction != null) FailedAction(socket);
                        },

                        //Authentication timed-out delegate
                        delegate(object state)
                        {
                            //This anonymous method can be called directly from a background thread so make sure it's exception-safe

                            ServiceSocket socket = (ServiceSocket)state;
                            if (socket.IsConnected)
                            {
                                Diags.LogDisconnectingPeer(socket.RemoteIP);
                                socket.Abort();
                            }

                            //Call the session transfer timeout action
                            if (TimeoutAction != null) TimeoutAction(socket);
                        },
                    //So as not to hold up any request that may want access to the transferring resource
                    //keep the timeout low by setting it to the network query timeout
                        new TimeSpan(0, 0, 0, 0, settings.NetworkQueryTimeout)
                    );
            }
            else
            {
                //Skip authentication and send request
                SetTransferRequest.Send(ConnectedSocket, this, ResourceKey, SessionInfo, Data,
                    SuccessAction, FailedAction, AlreadyExistsAction, PeerShuttingDownAction, TimeoutAction, new TimeSpan(0, 0, 0, 0, settings.NetworkQueryTimeout));
            }
        }

        #endregion

    }

    /// <summary>
    /// A helper class used to remove expired items from a DateSortedDictionary
    /// </summary>
    /// <typeparam name="TKey">The type of the DateSortedDictionary's key</typeparam>
    /// <typeparam name="TValue">The type of the DateSortedDictionary's value</typeparam>
    public static class DictionaryCleaner<TKey, TValue>
    {
        /// <summary>
        /// Checks if the oldest item in the dictionary is earlier than the reference date
        /// </summary>
        /// <param name="Dict">The dictionary</param>
        /// <param name="RefDate">The reference date</param>
        /// <param name="OldestKey">Key of the oldest item</param>
        /// <returns>True if oldest item is earlier than reference date. Otherwise, false</returns>
        internal static bool IsOldestExpired(DateSortedDictionary<TKey, TValue> Dict, DateTime RefDate, out TKey OldestKey)
        {
            bool result = false;
            OldestKey = default(TKey);

            TKey oldestKey = Dict.OldestKey;

            if (oldestKey != null)
            {

                //get the timestamp
                DateTime timeStamp;
                if (Dict.TryGetTimeStamp(oldestKey, out timeStamp))
                {
                    if (RefDate > timeStamp)
                    {
                        //Has expired
                        result = true;
                        OldestKey = oldestKey;
                    }
                }

            }

            return result;

        }

        /// <summary>
        /// Removes the oldest item in the dictionary if it's time stamp is earlier than the reference date
        /// </summary>
        /// <param name="Dict">The dictionary</param>
        /// <param name="RefDate">The reference date</param>
        /// <param name="RemovedItem">The removed item</param>
        /// <returns>True if item was removed. Otherwise, false</returns>
        internal static bool RemoveOldestIfExpired(DateSortedDictionary<TKey, TValue> Dict, DateTime RefDate, out TValue RemovedItem)
        {
            RemovedItem = default(TValue);
            TKey oldestKey;
            if (IsOldestExpired(Dict, RefDate, out oldestKey))
            {
                TValue value;
                if (Dict.TryGetValue(oldestKey, out value))
                {
                    if (Dict.Remove(oldestKey))
                    {
                        RemovedItem = value;
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Removes the oldest item in the dictionary if it's time stamp is earlier than the reference date
        /// </summary>
        /// <param name="Dict">The dictionary</param>
        /// <param name="RefDate">The reference date</param>
        /// <returns>True if item was removed. Otherwise, false</returns>
        internal static bool RemoveOldestIfExpired(DateSortedDictionary<TKey, TValue> Dict, DateTime RefDate)
        {
            TValue not_used;
            return RemoveOldestIfExpired(Dict, RefDate, out not_used);
        }
    }

    /// <summary>
    /// Represents a factory object used to construct the appropriate ServiceMessage from a complete HTTPPartialData object
    /// </summary>
    public class MessageFactory
    {
        StateServer service;

        /// <summary>
        /// Initializes a new instance of the MessageFactory class
        /// </summary>
        /// <param name="Service">Instance of the state server</param>
        public MessageFactory(StateServer Service)
        {
            service = Service;
        }

        /// <summary>
        /// Initializes the right instance of a class derived from ServiceMessage based on the contents of the HTTPPartialData objec
        /// </summary>
        /// <param name="Data">The HTTPPartialData object</param>
        /// <returns>An instance of a class derived from ServiceMessage</returns>
        public ServiceMessage CreateFrom(HTTPPartialData Data)
        {

            //First identify the type of message
            Classifier msgClass = new Classifier(Data, service);

            //Then create it
            return msgClass.Create();


        }

        /// <summary>
        /// Classifies a HTTPMessage and identifies the true message, to aid the construction of the right derived message type
        /// </summary>
        private class Classifier : HTTPMessage
        {

            HTTPPartialData data;
            StateServer service;

            /// <summary>
            /// Initializes a new instance of the Classifier class
            /// </summary>
            /// <param name="Data">The data to identify</param>
            /// <param name="Service">The state server instance</param>
            internal Classifier(HTTPPartialData Data, StateServer Service)
                : base(Data)
            {
                data = Data;
                service = Service;
            }

            /// <summary>
            /// Initializes an instance of a class derived from ServiceMessage object based on the information parsed from its contents
            /// </summary>
            /// <returns>An instance of the specific class derived from ServiceMessage</returns>
            internal ServiceMessage Create()
            {

                if (verb == null || verb.Type == HTTPMessageType.Unknown)
                {
                    //BadMessage
                    return new BadMessage(data, service);
                }
                else if (verb.Type == HTTPMessageType.Request)
                {
                    //Identify request type
                    if (verb.RequestMethod == HTTPMethod.RequestMethods.Get
                        && headers["EXCLUSIVE"] != null
                        && headers["EXCLUSIVE"].ToUpperInvariant() == "ACQUIRE")
                    {
                        //GetExclusiveRequest
                        return new GetExclusiveRequest(data, service);
                    }
                    else if (verb.RequestMethod == HTTPMethod.RequestMethods.Get
                        && headers["EXCLUSIVE"] != null
                        && headers["EXCLUSIVE"].ToUpperInvariant() == "RELEASE")
                    {
                        //ReleaseExclusiverequest
                        return new ReleaseExclusiveRequest(data, service);
                    }
                    else if (verb.RequestMethod == HTTPMethod.RequestMethods.Get
                   && headers["EXCLUSIVE"] != null
                   && headers["EXCLUSIVE"].ToUpperInvariant() == "TRANSFER")
                    {
                        //GetTranferRequest
                        return new GetTransferMessage(data, service);
                    }
                    else if (verb.RequestMethod == HTTPMethod.RequestMethods.Get
                            && verb.Resource.ToUpperInvariant() == @"\PING")
                    {
                        //PingRequest
                        return new PingMessage(data, service);
                    }
                    else if (verb.RequestMethod == HTTPMethod.RequestMethods.Get
                   && verb.Resource.ToUpperInvariant() == @"\AUTH" && headers["AUTHORIZATION"] != null)
                    {
                        //FinishAuthRequest
                        return new CompleteAuthRequest(data, service);
                    }
                    else if (verb.RequestMethod == HTTPMethod.RequestMethods.Get
                       && verb.Resource.ToUpperInvariant() == @"\AUTH")
                    {
                        //StartAuthRequest
                        return new BeginAuthRequest(data, service);
                    }
                    else if (verb.RequestMethod == HTTPMethod.RequestMethods.Get)
                    {
                        //GetRequest
                        return new GetRequest(data, service);
                    }
                    else if (verb.RequestMethod == HTTPMethod.RequestMethods.Put
                      && headers["EXCLUSIVE"] != null
                      && headers["EXCLUSIVE"].ToUpperInvariant() == "TRANSFER")
                    {
                        //SetTransferRequest
                        return new SetTransferRequest(data, service);
                    }
                    else if (verb.RequestMethod == HTTPMethod.RequestMethods.Put)
                    {
                        //SetRequest
                        return new SetRequest(data, service);
                    }
                    else if (verb.RequestMethod == HTTPMethod.RequestMethods.Delete)
                    {
                        //RemoveRequest
                        return new RemoveRequest(data, service);
                    }
                    else if (verb.RequestMethod == HTTPMethod.RequestMethods.Head)
                    {
                        //ResetTimeoutRequest
                        return new ResetTimeoutRequest(data, service);
                    }
                    else
                    {
                        //UnknownRequest
                        return new UnknownRequest(data, service);
                    }

                }
                else
                {
                    //Identify Responses
                    switch (verb.ResponseCode)
                    {
                        case OKResponse.Code:
                            if (headers["SERVER"] != null)
                            {
                                //PING Reply peer message
                                return new PingReplyMessage(data, service);
                            }
                            else
                            {
                                //OKResponse
                                return new OKResponse(data, service);
                            }

                        case BadRequestResponse.Code:
                            //BadRequestResponse
                            return new BadRequestResponse(data, service);

                        case UnauthorizedResponse.Code:
                            //UnauthorizedResponse
                            return new UnauthorizedResponse(data, service);

                        case NotFoundResponse.Code:
                            //NotFoundResponse
                            return new NotFoundResponse(data, service);

                        case LockedResponse.Code:
                            //LockedResponse
                            return new LockedResponse(data, service);

                        case ServiceUnavailableResponse.Code:
                            //ServiceUnavailable
                            return new ServiceUnavailableResponse(data, service);

                        case PreconditionFailedResponse.Code:
                            //PreconditionFailedResponse
                            return new PreconditionFailedResponse(data, service);

                        default:
                            //UnknownResponse
                            return new UnknownResponse(data, service);

                    }

                }
            }
        }





    }

    /// <summary>
    /// Represents a complete transmittable message
    /// </summary>
    public class ResponseData
    {

        byte[] rawData;
        Type messageType;
        object tag;

        /// <summary>
        /// Initializes a new instance of the ResponseData class
        /// </summary>
        /// <param name="RawData">The actual raw data to be transmitted</param>
        /// <param name="MessageType">The Type of the Message to be transmitted</param>
        public ResponseData(byte[] RawData, Type MessageType)
        {
            messageType = MessageType;
            rawData = RawData;
            tag = null;
        }
        
        /// <summary>
        /// Gets or sets a tag object for any purpose.
        /// This property is useful to set an associated object to be referenced later
        /// </summary>
        public object Tag
        {
            get { return tag; }
            set { tag = value; }
        }

        /// <summary>
        /// Gets the response data
        /// </summary>
        public byte[] Data
        {
            get { return rawData; }
        }

        /// <summary>
        /// Gets the Type of the response
        /// </summary>
        public Type ResponseType
        {
            get { return messageType; }
        }


        /// <summary>
        /// Clears the response data
        /// </summary>
        public void ClearData()
        {
            rawData = null;
        }

    }

    /// <summary>
    /// Represents several actions that are invokeable based on the result of an asynchronous operation
    /// </summary>
    /// <typeparam name="T">The type of the state object passed to actions</typeparam>
    public class AsyncResultActions<T>
    {
        T state;
        Action<T> result1Action;
        Action<T> result2Action;
        Action<T> result3Action;
        Action<T> result4Action;
        WaitCallback timeoutAction;

        /// <summary>
        /// Initializes a new instance of the AsyncResultActions class
        /// </summary>
        /// <param name="State">The state object passed to Actions</param>
        public AsyncResultActions(T State)
        {
            state = State;
        }

        /// <summary>
        /// Gets or sets the state object passed when invoking actions
        /// </summary>
        public T State
        {
            get { return state; }
            set { state = value; }
        }

        /// <summary>
        /// Gets or sets the Result1 action
        /// </summary>
        public Action<T> Result1Action
        {
            get { return result1Action; }
            set { result1Action = value; }
        }

        /// <summary>
        /// Gets or sets the Result2 action
        /// </summary>
        public Action<T> Result2Action
        {
            get { return result2Action; }
            set { result2Action = value; }
        }

        /// <summary>
        /// Gets or sets the Result3 action
        /// </summary>
        public Action<T> Result3Action
        {
            get { return result3Action; }
            set { result3Action = value; }
        }

        /// <summary>
        /// Gets or sets the Result4 action
        /// </summary>
        public Action<T> Result4Action
        {
            get { return result4Action; }
            set { result4Action = value; }
        }

        /// <summary>
        /// Gets or sets the Timeout action
        /// </summary>
        public WaitCallback TimeoutAction
        {
            get { return timeoutAction; }
            set { timeoutAction = value; }
        }

        /// <summary>
        /// Queues the Timeout Action on the thread pool
        /// </summary>
        public void ThreadPoolQueueTimeoutAction()
        {
            if (timeoutAction != null)
            {
                ThreadPool.QueueUserWorkItem(timeoutAction, state);
            }
        }

        /// <summary>
        /// Calls the Result1 action
        /// </summary>
        public void InvokeResult1Action()
        {
            if (result1Action != null)
            {
                result1Action(state);
            }
        }

        /// <summary>
        /// Calls the Result2 action
        /// </summary>
        public void InvokeResult2Action()
        {
            if (result2Action != null)
            {
                result2Action(state);
            }
        }

        /// <summary>
        /// Calls the Result3 action
        /// </summary>
        public void InvokeResult3Action()
        {
            if (result3Action != null)
            {
                result3Action(state);
            }
        }

        /// <summary>
        /// Calls the Result4 Action
        /// </summary>
        public void InvokeResult4Action()
        {
            if (result4Action != null)
            {
                result4Action(state);
            }
        }

        /// <summary>
        /// Calls the Timeout Action
        /// </summary>
        public void InvokeTimeoutAction()
        {
            if (timeoutAction != null)
            {
                timeoutAction(state);
            }
        }

    }

    /// <summary>
    /// Represents the configured options in the server's configuration file
    /// </summary>
    public class ServerSettings
    {
        int webserverPort;
        int peerPort;
        bool authenticatePeers;
        bool encryptPeerData;
        bool standaloneMode;
        int maxForwards;
        int netQueryTimeout;
        List<HostEndPoint> peers = new List<HostEndPoint>();

        /// <summary>
        /// Initializes a new instance of the ServerSettings class
        /// </summary>
        public ServerSettings()
        {
            System.Collections.Specialized.NameValueCollection AppSettings = ConfigurationManager.AppSettings;


            try
            {
                webserverPort = int.Parse(AppSettings["WebserverPort"]);
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Error reading WebserverPort configuration setting", ex);
            }

            try
            {
                peerPort = int.Parse(AppSettings["PeerPort"]);
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Error reading PeerPort configuration setting", ex);
            }

            try
            {
                maxForwards = int.Parse(AppSettings["MaxForwards"]);
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Error reading MaxForwards configuration setting", ex);
            }

            if (maxForwards < 0) maxForwards = 0;

            try
            {
                netQueryTimeout = (int)(float.Parse( AppSettings["NetworkQueryTimeout"] ) * 1000);
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Error reading NetworkQueryTimeout configuration setting", ex);
            }

            if (netQueryTimeout <= 0) netQueryTimeout = 1000; //Default to 1 second


            try
            {
                authenticatePeers = bool.Parse(AppSettings["AuthenticatePeers"]);
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Error reading AuthenticatePeers configuration setting", ex);
            }

            try
            {
                encryptPeerData = bool.Parse(AppSettings["EncryptPeerData"]);
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Error reading EncryptPeerData configuration setting", ex);
            }

            if (!authenticatePeers)
            {
                encryptPeerData = false;
            }

            try
            {
                standaloneMode = bool.Parse(AppSettings["StandaloneMode"]);
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Error reading StandaloneMode configuration setting", ex);
            }

            System.Collections.Hashtable peerTable;
            try
            {
                peerTable = (System.Collections.Hashtable)ConfigurationManager.GetSection("Peers");

                foreach (string endpoint in peerTable.Values)
                {
                    string[] add = endpoint.Split(new char[] { ':' });
                    string host;
                    int port;

                    if (add.Length == 1)
                    {
                        host = add[0];
                        port = peerPort;
                    }
                    else if (add.Length == 2)
                    {
                        host = add[0];
                        port = int.Parse(add[1]);
                    }
                    else
                    {
                        throw new ApplicationException("Invalid Host address in Peers collection");
                    }

                    if (!standaloneMode)
                    {
                        peers.Add(new HostEndPoint(host, port));
                    }

                }
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Error reading Peers configuration setting", ex);
            }

            //Check that PeerPassword value exists, but don't store it
            if (ConfigurationManager.AppSettings["PeerPassword"] == null || ConfigurationManager.AppSettings["PeerPassword"] == string.Empty)
            {
                throw new ApplicationException("Error reading PeerPassword configuration setting");
            }


        }

        /// <summary>
        /// Gets the port on which web servers (or other clients) connect to
        /// </summary>
        public int WebserverPort
        {
            get { return webserverPort; }
        }

        /// <summary>
        /// Gets the port on which peers connect to
        /// </summary>
        public int PeerPort
        {
            get { return peerPort; }
        }

        /// <summary>
        /// Gets a value indicating whether this peer must authenticate connecting peers
        /// </summary>
        public bool AuthenticatePeers
        {
            get { return authenticatePeers; }
        }

        /// <summary>
        /// Gets a value indicating whether this peer encrypts data sent to other peers 
        /// and if this peer will only accept encrypted data from other peers
        /// </summary>
        public bool EncryptPeerData
        {
            get { return encryptPeerData; }
        }

        /// <summary>
        /// Gets the StandaloneMode setting
        /// </summary>
        public bool StandaloneMode
        {
            get { return standaloneMode; }
        }

        /// <summary>
        /// Gets the MaxForwards setting
        /// </summary>
        public int MaxForwards
        {
            get { return maxForwards; }
        }

        /// <summary>
        /// Gets the NetworkQueryTimeout setting in milliseconds
        /// </summary>
        public int NetworkQueryTimeout
        {
            get { return netQueryTimeout; }
        }

        /// <summary>
        /// Gets the list of end points of configured peers
        /// </summary>
        public List<HostEndPoint> Peers
        {
            get { return peers; }
        }

        /// <summary>
        /// Gets a setting by its name
        /// </summary>
        /// <param name="name">The name of the setting</param>
        /// <returns>The setting value</returns>
        public string this[string name]
        {
            get { return ConfigurationManager.AppSettings[name]; }

        }

        /// <summary>
        /// Represents a network endpoint as a textual host and a port number
        /// </summary>
        public class HostEndPoint
        {

            public string Host;
            public int Port;
            
            /// <summary>
            /// Initializes a new instance of the HostEndPoint class
            /// </summary>
            /// <param name="Host">The textual endpoint host</param>
            /// <param name="Port">The port number</param>
            public HostEndPoint(string Host, int Port)
            {
                this.Host = Host;
                this.Port = Port;
            }

            /// <summary>
            /// Parses the provided string endpoint for a host and port number
            /// </summary>
            /// <param name="EndPoint">The string endpoint to parse</param>
            /// <param name="Host">The parsed host</param>
            /// <param name="Port">The parsed port number</param>
            public static void Parse(string EndPoint, out string Host, out int? Port)
            {
                string key, value;
                GetKeyValue(EndPoint, ':', out key, out value);

                Host = key;
                Port = null;
                int v;
                if (int.TryParse(value, out v))
                {
                    Port = v;
                }

            }

            public override string ToString()
            {
                return Host + ":" + Port;
            }

            /// <summary>
            /// Parses a string for a Key and a Value
            /// </summary>
            /// <param name="Text">The text to parse</param>
            /// <param name="Delimiter">Delimiter seperating key and value</param>
            /// <param name="Key">Key</param>
            /// <param name="Value">Value</param>
            private static void GetKeyValue(string Text, char Delimiter, out string Key, out string Value)
            {
                if (Text == null) throw new ArgumentNullException("Text");

                int index = Text.IndexOf(Delimiter);

                if (index < 1)
                {
                    Key = Text;
                    Value = string.Empty;
                    return;
                }

                Key = Text.Substring(0, index);
                if (Key.Length == Text.Length)
                {
                    Value = string.Empty;
                }
                else
                {
                    Value = Text.Substring(index + 1);
                }
            }

        }

    }


    /// <summary>
    /// Represents a strongly typed list of objects that are associated with a single hash code.
    /// </summary>
    /// <remarks>
    /// This class is useful in a collection. Each HashList in the collection will have elements associated with a hashcode.
    /// </remarks>
    /// <typeparam name="T">The type of elements in the list</typeparam>
    public class HashList<T> : List<T>
    {
        int hashcode;

        /// <summary>
        /// Initializes a new instance of the HashList class
        /// </summary>
        /// <param name="HashCode">The associated hash code</param>
        public HashList(int HashCode)
            : base()
        {
            hashcode = HashCode;
        }

        /// <summary>
        /// Gets the hash code value associated with this list
        /// </summary>
        public int HashCode
        {
            get
            {
                return hashcode;
            }
        }

    }


}
