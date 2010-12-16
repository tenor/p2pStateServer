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
using System.Text;
using System.Collections.Generic;
using System.Collections.Specialized;

namespace P2PStateServer
{
    /// <summary>
    /// Represents a HTTP message
    /// </summary>
    public abstract class HTTPMessage
    {
        /// <summary>
        /// The socket that sent the message
        /// </summary>
        protected ServiceSocket socket;

        /// <summary>
        /// The headers collection of the message
        /// </summary>
        protected NameValueCollection headers = new NameValueCollection();

        /// <summary>
        /// The first line in a HTTP message
        /// </summary>
        protected string requestStatusLine = string.Empty;

        /// <summary>
        /// Indicates whether the message has an error
        /// </summary>
        protected bool isError;

        /// <summary>
        /// The body of the HTTP message
        /// </summary>
        protected byte[] body = null;

        /// <summary>
        /// The host field of the message
        /// </summary>
        protected string host;

        /// <summary>
        /// The parsed verb line of the HTTP message
        /// </summary>
        protected HTTPMethod verb;

        /// <summary>
        /// Initializes a new instance of the HTTPMessage class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public HTTPMessage(HTTPPartialData HTTPData)
        {
            if (HTTPData.IsError)
            {
                throw new ArgumentException("HTTP Partial data has an error", "HTTPData");
            }

            if (!HTTPData.IsComplete)
            {
                throw new ArgumentException("HTTP Partial data is not complete", "HTTPData");
            }

            socket = HTTPData.HandlerSocket;
            byte[][] lines = HTTPData.Lines;

            if (lines.Length == 0)
            {
                isError = true;
            }
            else
            {
                requestStatusLine = Encoding.UTF8.GetString(lines[0], 0, lines[0].Length - 2); //compensate for CRLF
            }

            //Get HTTP Method Information
            try
            {
                verb = new HTTPMethod(requestStatusLine);
            }
            catch
            {
                isError = true;
                verb = null;
            }

            //Get Headers
            for (int i = 1; i < lines.Length; i++)
            {
                byte[] line = lines[i];
                if (line.Length > 2) //skip CRLF-only lines
                {
                    int index = Array.IndexOf(line, (byte)58);//':' character

                    if (index < 1)
                    {
                        isError = true;
                        continue;
                    }

                    string name = Encoding.UTF8.GetString(line, 0, index);
                    string value = string.Empty;

                    if (index < (line.Length - 3)) //compensate for CR and LF
                    {
                        value = Encoding.UTF8.GetString(line, index + 1, line.Length - (index + 3));
                    }


                    headers.Add(name.Trim().ToUpperInvariant(), value.Trim());
                }

            }

            //Get Body Data
            body = HTTPData.Content == null ? new byte[0] { } : HTTPData.Content;

            //Pickup Host
            host = headers["HOST"];
            if (host == null && verb.Type == HTTPMessageType.Request)
            {
                isError = true;
            }

            //look for Content-Length and compare it with body length

            string cLen = headers["CONTENT-LENGTH"] ;
            if (cLen == null || cLen.Trim() == string.Empty)
            {
                if (body.Length != 0) isError = true;
            }
            else
            {
                int v;
                if (int.TryParse(cLen, out v))
                {
                    if (v != body.Length) isError = true;
                }
                else
                {
                    isError = true;
                }

            }
            

        }

    }

    /// <summary>
    /// Represents a message originating from a peer, state server or client (web server)
    /// </summary>
    public abstract class ServiceMessage : HTTPMessage
    {
        /// <summary>
        /// The maximum value a Lockcookie can have
        /// </summary>
        protected const uint MAX_LockCookieValue = 2147483646; 
        
        /// <summary>
        /// The message time-out value
        /// </summary>
        protected int? timeout;

        /// <summary>
        /// The message lock cookie value
        /// </summary>
        protected uint? lockCookie;

        /// <summary>
        /// An instance of the state server
        /// </summary>
        protected StateServer service;

        private object tag;

        /// <summary>
        /// Initializes a new instance of the ServiceMessage class
        /// </summary>
        /// <param name="HTTPData">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public ServiceMessage(HTTPPartialData HTTPData, StateServer Service)
            : base(HTTPData)
        {

            service = Service;

            //Get other information
            timeout = null;

            if (headers["TIMEOUT"] != null)
            {
                int v;
                int.TryParse(headers["TIMEOUT"], out v);
                timeout = v;
            }

            lockCookie = null;
            if (headers["LOCKCOOKIE"] != null)
            {
                uint v;
                uint.TryParse(headers["LOCKCOOKIE"], out v);
                lockCookie = v;
            }

            int plainTextSize = -1;
            bool encrypted  = false;
            if (headers["CONTENT-TYPE"] != null)
            {
                string[] directives = headers["CONTENT-TYPE"].Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);

                if(directives[0].Trim().ToUpperInvariant() == @"APPLICATION/X-ENCRYPTED") encrypted = true;
                foreach (string directive in directives)
                {
                    if (directive.Trim().ToUpperInvariant().StartsWith("PLAINTEXT-LENGTH"))
                    {
                        if (!int.TryParse(directive.Trim().Substring(16).Replace("=", string.Empty).Trim(), out plainTextSize))
                        {
                            isError = true;
                        }
                    }
                }

                if(encrypted && plainTextSize < 0) isError = true; 
            }


            if (!isError)
            {
                if (socket.IsAuthenticated && service.Settings.EncryptPeerData)
                {
                    if (body.Length > 0 )
                    {
                        if (!encrypted)
                        {
                            Diags.LogMessageUnprotectedError(this);
                            isError = true;
                        }
                        else
                        {
                            try
                            {
                                body = service.Authenticator.Unprotect(body, socket.SessionKey, plainTextSize);
                            }
                            catch (Exception ex)
                            {
                                Diags.LogMessageContentCipherError(this, ex);
                                isError = true;
                            }
                        
                        }
                    }
                }
                else
                {
                    if (encrypted)
                    {
                        Diags.LogMessageProtectedError(this);
                        isError = true;
                    }
                }
            }


        }

        /// <summary>
        /// When overriden in a derived class, processes the message.
        /// </summary>
        public abstract void Process();

        /// <summary>
        ///  Validates a message
        /// </summary>
        /// <returns>True, if message is valid. False, if not</returns>
        protected virtual bool Validate()
        {
            return !isError;
        }

        /// <summary>
        /// Removes quotes from a string if the string is surrounded by quotes
        /// </summary>
        /// <param name="value">Quoted/Unquoted string</param>
        /// <returns>Unquoted string</returns>
        protected string Unquote(string value)
        {
            if (value == null) throw new ArgumentNullException("value");

            value = value.Trim();

            if (value.StartsWith("\"") && value.EndsWith("\""))
            {
                if (value.Length == 2) return string.Empty;
                return value.Substring(1, value.Length - 2); //remove quotes
            }

            return value;
        }

        /// <summary>
        /// Gets the Timeout header value in minutes of the message
        /// </summary>
        public virtual int? Timeout
        {
            get { return timeout; }
        }

        /// <summary>
        /// Gets the Lock-cookie header value of the message
        /// </summary>
        public virtual uint? LockCookie
        {
            get { return lockCookie; }
        }

        /// <summary>
        /// Gets the HTTP Host header value of the message
        /// </summary>
        public virtual string Host
        {
            get { return host; }
        }

        /// <summary>
        /// Gets a value indicating whether there is an error in this message.
        /// </summary>
        public virtual bool IsError
        {
            get { return isError; }
        }

        /// <summary>
        /// Gets the data (message body) associated with this message
        /// </summary>
        public virtual byte[] Data
        {
            get { return body; }
        }

        /// <summary>
        /// Gets the URI associated with this message. Mostly Useful for service requests
        /// </summary>
        public virtual string Resource
        {
            get { return verb.Resource; }
        }

        /// <summary>
        /// Gets or sets an object designated as a tag, for any purpose
        /// </summary>
        public object Tag
        {
            get { return tag; }
            set { tag = value; }
        }

        /// <summary>
        /// Gets the message source IP address
        /// </summary>
        public string Source
        {
            get
            {
                return socket.RemoteIP;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the source of this message is connected to the state server (as at the last I/O operation)
        /// </summary>
        public virtual bool SourceIsConnected
        {
            get
            {
                return socket.IsConnected;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the source of this message is a peer
        /// </summary>
        public virtual bool SourceIsPeer
        {
            get
            {
                return socket.FromPeerListener;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the source of this message has been authenticated
        /// </summary>
        public virtual bool SourceIsAuthenticated
        {
            get
            {
                return socket.IsAuthenticated;
            }
        }

        /// <summary>
        /// Parses a string for a Key and a Value
        /// </summary>
        /// <param name="Text">The text to parse</param>
        /// <param name="Delimiter">Delimiter seperating key and value</param>
        /// <param name="Key">Key</param>
        /// <param name="Value">Value</param>
        protected static void GetKeyValue(string Text, char Delimiter, out string Key, out string Value)
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

        /// <summary>
        /// Verifies the supplied data is in valid Base64 format
        /// </summary>
        /// <param name="Data">Data to verify</param>
        /// <returns>True, if data is valid Base64. Otherwise, false</returns>
        protected static bool IsValidBase64(string Data)
        {
            try
            {
                Convert.FromBase64String(Data);
                return true;
            }
            catch
            {
                return false;
            }
        }




    }

    /// <summary>
    /// Represents a ServiceResponse message
    /// </summary>
    /// <remarks>
    /// The ServiceResponse class represents a response message from a peer to another or from a state server to a client (web server) in response to a request.
    /// Response messages should be derived from the ServiceRequest class.
    /// </remarks>
    public abstract class ServiceResponse : ServiceMessage
    {

        /// <summary>
        /// The version of the state server that sent the response
        /// </summary>
        protected string aspNetVersion;

        /// <summary>
        /// The response ActionFlags value
        /// </summary>
        protected string actionFlags;

        /// <summary>
        /// Initializes a new instance of the ServiceResponse class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public ServiceResponse(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
            actionFlags = headers["ACTIONFLAGS"];
            aspNetVersion = headers["X-ASPNET-VERSION"];
        }

        /// <summary>
        /// Validates a ServiceResponse message
        /// </summary>
        /// <returns>True, if response is valid. Otherwise, false</returns>
        protected override bool Validate()
        {
            if (!base.Validate() || !SourceIsPeer) //message has error or message is not from peer (all responses are from peers)
            {
                //Abort connection
                socket.Abort();
                return false;
            }

            //Check last message sent
            ResponseData[] sentMsgs = socket.SentMessages;
            if (sentMsgs != null && sentMsgs.Length > 0 && sentMsgs[sentMsgs.Length - 1].ResponseType.IsSubclassOf(typeof(ServiceResponse))) 
            {
                //Last Sent Message should be a Request or nothing at all
                //Abort connection
                socket.Abort();
                return false;                
            }

            return true;
        }

        /// <summary>
        /// Processes an unexpected/bad response.
        /// This method also calls the Failure event for BeginAuthRequest\CompleteAuthRequest and SetTransferRequest
        /// </summary>
        protected void ProcessFailureResponse()
        {
            ResponseData[] sentMsgs = socket.SentMessages;
            if (sentMsgs != null && sentMsgs.Length > 0)
            {
                Type lastMsg = sentMsgs[sentMsgs.Length - 1].ResponseType;

                if (lastMsg == typeof(BeginAuthRequest) || lastMsg == typeof(CompleteAuthRequest) || lastMsg == typeof(SetTransferRequest))
                {
                    //Last sent message was a BeginAuthRequest or a CompleteAuthRequest or a SetTransferRequest

                    //Look for the scavenger's reference object for the original BeginAuth/CompleteAuth/SetTransfer request
                    //if the object is still valid, then call the method to tell the original request that things didn't go well
                    AsyncResultActions<ServiceSocket> calls;
                    if (service.AsyncRequests.TryGetValue(socket, out calls))
                    {
                        if (service.AsyncRequests.Remove(socket))
                        {
                            calls.InvokeResult2Action(); //Result2 is the failure result
                            return;
                        }
                    }

                    return; //Async operation has already been handled
                }

            }

            //I don't know why I'm receiving this

            //abort connection
            socket.Abort();
        }

        /// <summary>
        /// Gets the ActionFlags header value
        /// </summary>
        public string ActionFlags
        {
            get { return actionFlags; }
        }

        /// <summary>
        /// Gets the AspNetVersion header value which indicates the state server version
        /// </summary>
        public string AspNetVersion
        {
            get { return aspNetVersion; }
        }
    }

    /// <summary>
    /// Represents a PeerMessage message
    /// </summary>
    /// <remarks>
    /// The PeerMessage class represents a peer-to-peer message.
    /// PeerMessages can be sent at anytime and are not required to be responded to.
    /// Peer messages should be derived from the ServiceRequest class.
    /// </remarks>
    public abstract class PeerMessage : ServiceMessage
    {
        /// <summary>
        /// The maximum number of times the message is to be forwarded
        /// </summary>
        /// <remarks>
        /// This field is decremented by one before been forwarded by a peer
        /// </remarks>
        protected uint? maxForwards;

        /// <summary>
        /// The peer message's unique identifier on the network
        /// </summary>
        protected Guid? id;

        /// <summary>
        /// Identifies a peer message broadcast. 
        /// </summary>
        /// <remarks>
        /// A peer message can be re-broadcast several times and so have different broadcast IDs.
        /// </remarks>
        protected Guid broadcastID;

        /// <summary>
        /// Initializes a new instance of the PeerMessage class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public PeerMessage(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
            maxForwards = null;
            if (headers["MAX-FORWARDS"] != null)
            {
                uint v;
                uint.TryParse(headers["MAX-FORWARDS"], out v);
                maxForwards = v;
            }

            id = null;
            if (headers["X-ID"] != null)
            {
                try
                {
                    id = new Guid(headers["X-ID"]);
                }
                catch
                {
                    id = null;
                }
                 
            }

            if (headers["X-BROADCAST-ID"] != null)
            {
                try
                {
                    broadcastID = new Guid(headers["X-BROADCAST-ID"].Trim());
                }
                catch
                { isError = true; }
            }
            else
            {
                broadcastID = Guid.Empty;
            }


        }

        /// <summary>
        /// When overriden in a derived class, forwards this peerMessage message
        /// </summary>
        public abstract void Forward();
        
        /// <summary>
        /// Gets the unique identifier for this message
        /// </summary>
        public Guid? ID
        {
            get { return id; }
        }

        /// <summary>
        /// Gets or sets the MaxForwards header value which is decremented each time it is forwarded.
        /// A value of zero indicates that this message should not be forwarded.
        /// </summary>
        public uint? MaxForwards
        {
            get { return maxForwards; }
            set { maxForwards = value; }
        }


    }

    /// <summary>
    /// Represents a ServiceRequest message
    /// </summary>
    /// <remarks>
    /// The ServiceRequest class represents a request message from a peer to another or from a client to a state server.
    /// Request messages should be derived from the ServiceRequest class.
    /// </remarks>
    public abstract class ServiceRequest : ServiceMessage
    {
        /// <summary>
        /// The request ExtraFlags value
        /// </summary>
        protected string extraFlags;

        /// <summary>
        /// The time out datestamp for a network query
        /// </summary>
        protected DateTime? queryTimeout = null;

        /// <summary>
        /// When overriden in a derived class, Generates an appropriate ResponseData object for this message, filled with supplied data
        /// </summary>
        /// <param name="ResponseType">The Type of the Response message</param>
        /// <param name="ResponseMessage">The HTTP response reason phrase</param>
        /// <param name="ResponseInfo">The session response information</param>
        /// <param name="Content">The response data</param>
        /// <returns>A filled ResponseData object</returns>
        protected abstract ResponseData BuildResponse(Type ResponseType, string ResponseMessage, ISessionResponseInfo ResponseInfo, byte[] Content);

        /// <summary>
        /// Initializes a new instance of the ServiceRequest class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public ServiceRequest(HTTPPartialData Data, StateServer Service) : base(Data,Service)
        {
            extraFlags = headers["EXTRAFLAGS"];

            //ExtraFlags only accepts 0 and 1 -- if any other value is set, set it to null
            if (extraFlags != null)
            {
                extraFlags = extraFlags.Trim();
                if (extraFlags != "0" && extraFlags != "1")
                {
                    extraFlags = null;
                }
            }
        }

        /// <summary>
        /// Gets the ExtraFlags header value
        /// </summary>
        public string ExtraFlags
        {
            get { return extraFlags; }
        }

        /// <summary>
        /// Sends a reply to the source of this request
        /// </summary>
        /// <param name="Response">The response data</param>
        public virtual void Reply(ResponseData Response)
        {            
            socket.Send(Response);
            Diags.LogReply(this, Response);
        }

        /// <summary>
        /// Validates a ServiceRequest message
        /// </summary>
        /// <returns>True if message is valid. Otherwise, false</returns>
        protected override bool Validate()
        {
            if( base.Validate() == false) return false;

            //Check last message sent
            ResponseData[] sentMsgs = socket.SentMessages;
            if (sentMsgs != null && sentMsgs.Length > 0 && sentMsgs[sentMsgs.Length - 1].ResponseType.IsSubclassOf(typeof(ServiceRequest))) 
            {
                //Last Sent Message should be a Response or nothing at all
                //Abort connection
                socket.Abort();
                return false;
            }

            return true;
        }

        /// <summary>
        /// Generates a raw response message data 
        /// </summary>
        /// <param name="Headers">The HTTP Headers (includes first line)</param>
        /// <param name="Content">The Content (message body)</param>
        /// <param name="AppendContent">Specifies whether the content is to be included in the generated message</param>
        /// <param name="EncryptContent">Specifies whether the content is to be encrypted</param>
        /// <param name="Authenticator">The Authenticator object</param>
        /// <param name="SessionKey">The session encryption key</param>
        /// <returns>Response message data</returns>
        protected static byte[] MergeResponseData(StringBuilder Headers, byte[] Content, bool AppendContent, bool EncryptContent, SHA256_AESAuthenticator Authenticator, byte[] SessionKey)
        {
            byte[] content;

            if (!AppendContent || Content == null)
            {
                content = new byte[0];
            }
            else
            {
                content = Content;
            }

            if (AppendContent && EncryptContent && content.Length > 0)
            {
                int originalSize = content.Length;
                content = Authenticator.Protect(content, SessionKey);
                Headers.AppendFormat("Content-Type: application/x-encrypted; plaintext-length={0}\r\n", originalSize);
            }
            
            Headers.AppendFormat("Content-Length: {0}\r\n\r\n",content.Length);


            byte[] headers = Encoding.UTF8.GetBytes(Headers.ToString());

            byte[] rawdata;
            if (AppendContent && content.Length != 0)
            {                
                rawdata = new byte[headers.Length + content.Length];
                Array.Copy(headers, 0, rawdata, 0, headers.Length);
                Array.Copy(content, 0, rawdata, headers.Length, content.Length);
            }
            else
            {
                rawdata = headers;
            }

            headers = null;
            return rawdata;
        }

        /// <summary>
        /// Initiates a network query for a session
        /// </summary>
        /// <returns>True if the network query was initiated. Otherwise, false</returns>
        protected bool QueryNetwork()
        {
            //Broadcast a GetTransferMessage which will call Process() when the session is returned
            //and replies with a NotFound response after the broadcast times out
            return QueryNetwork(delegate(object not_used) { Reply(BuildResponse(typeof(NotFoundResponse), null, null, null)); });
        }

        /// <summary>
        /// Initiates a network query for a session
        /// </summary>
        /// <param name="TimeoutHandler">The Action that is called when the query times out</param>
        /// <returns>True if the network query was initiated. Otherwise, false</returns>
        protected bool QueryNetwork(System.Threading.WaitCallback TimeoutHandler)
        {

            ServiceSocket[] peers = service.LivePeers;
            if (!service.Settings.StandaloneMode && peers.Length > 0)
            {

                if (queryTimeout == null)
                {
                    queryTimeout = DateTime.UtcNow + new TimeSpan(0, 0, service.Settings.NetworkQueryTimeout);
                }

                //Log P2P Querying Network
                Diags.LogQueryingNetwork(Resource);

                //Create a new guid as the message id
                Guid msgID = Guid.NewGuid();

                //Add new query to Queries Initiated list (with one minute expiry)
                service.QueriesInitiated.Add(DateTime.UtcNow + new TimeSpan(0, 1, 0), msgID, null);

                //To get Origin Host: Get the LocalIP of the connecting socket + Port of peer listening socket
                string originEndPoint;
                {
                    string localhost;
                    int? localport;
                    ServerSettings.HostEndPoint.Parse(socket.LocalIP, out localhost, out localport);
                    originEndPoint = new ServerSettings.HostEndPoint(localhost, service.Settings.PeerPort).ToString();
                }

                //Broadcast a GetTransferMessage which will call Process() when the session is returned
                //and processes TimeoutHandler delegate when the broadcast times out
                GetTransferMessage.Broadcast
                    (originEndPoint ,new List<ServiceSocket>(peers), service, Resource, msgID, service.Settings.MaxForwards, Guid.Empty, queryTimeout.Value,
                        delegate(string key) { Process(); }, //Found delegate simply reprocesses the request
                        delegate (object key) //Timeout delegate calls the time-out handler
                        {
                            Diags.LogNetworkQueryTimeout(Resource);
                            TimeoutHandler(key);
                        }
                    );

                return true;
            }
            else
            {
                return false;
            }
        }

    }

    /// <summary>
    /// Represents the UnknownRequest message.
    /// </summary>
    /// <remarks>
    /// This class represents a message that could not be classified as either a request or a response.
    /// </remarks>
    public class BadMessage : ServiceMessage
    {
        /// <summary>
        /// Initializes a new instance of the BadMessage class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public BadMessage(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            //abort connection
            socket.Abort();
        }
    }

    /// <summary>
    /// Represents the UnknownRequest message.
    /// </summary>
    /// <remarks>
    /// This class represents a message that was classified as a request, but could not be identified.
    /// </remarks>
    public class UnknownRequest : ServiceRequest
    {
        /// <summary>
        /// Initializes a new instance of the UnknownRequest class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public UnknownRequest(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            //abort connection
            socket.Abort();
        }

        /// <summary>
        /// Generates an appropriate ResponseData object for this message, filled with supplied data
        /// </summary>
        /// <param name="ResponseType">The Type of the Response message</param>
        /// <param name="ResponseMessage">The HTTP response reason phrase</param>
        /// <param name="ResponseInfo">The session response information</param>
        /// <param name="Content">The response data</param>
        /// <returns>A filled ResponseData object</returns>
        protected override ResponseData BuildResponse(Type ResponseType, string ResponseMessage, ISessionResponseInfo ResponseInfo, byte[] Content)
        {
            throw new NotImplementedException("The UnknownRequest.BuildResponse method is not implemented.");
        }
    }

    /// <summary>
    /// Represents the UnknownResponse message.
    /// </summary>
    /// <remarks>
    /// This class represents a message that was classified as a response, but could not be identified.
    /// </remarks>
    public class UnknownResponse : ServiceResponse
    {
        /// <summary>
        /// Initializes a new instance of the UnknownResponse class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public UnknownResponse(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            //same processing as BadRequestResponse
            if (!Validate())
            {
                Diags.LogIgnoredMessage(this, "Message is not valid");
                return;
            }

            ProcessFailureResponse();
            
        }
    }

    /// <summary>
    /// Represents the GetExclusiveRequest message.
    /// </summary>
    /// <remarks>
    /// This message is sent from a client (web server) to a state server to request 
    /// session data non-exclusively.
    /// This message is only transmitted from client to state server.
    /// </remarks>
    public class GetRequest : ServiceRequest
    {
        short exportCount = 0;

        /// <summary>
        /// Initializes a new instance of the GetRequest class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public GetRequest(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
            //Validate 
            if (!isError)
            {
                //This message requires a resource
                if (verb.Resource == string.Empty)
                {
                    isError = true;
                }
            }

        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!SourceIsConnected) return;
            if (!Validate())
            {
                Reply(BuildResponse(typeof(BadRequestResponse), null, null, null));
                return;
            }
            if (SourceIsPeer)
            {
                //This message cannot come from a peer
                Reply(BuildResponse(typeof(BadRequestResponse), "Request is not on Webserver port", null, null));
                return;
            }

            switch (service.SessionTable.Read(Resource, CompleteReadRequest, this))
            {
                case SessionActionResult.NotFound:
                    //Not found                
                    if (QueryNetwork())
                    {
                        return;
                    }
                    else
                    {
                        Reply(BuildResponse(typeof(NotFoundResponse), null, null, null));
                        return;

                    }


                case SessionActionResult.Exporting:
                    if (exportCount > 1)
                    {
                        //This can occur on a rare occasion
                        Diags.LogContentionDetected("GetRequest Export is trying for the second time","Message Ignored");
                        return;
                    }
                    //Already exporting -- try this request after export is complete
                    service.AppendActiveExportEndedEvent(Resource, (delegate(string not_used) { Process(); }));
                    exportCount++;
                    return;

            }
        }

        /// <summary>
        /// Called by the SessionDictionary.Read method to complete processing the request, 
        /// if the requested session was found and read
        /// </summary>
        /// <param name="Session">The read session object</param>
        /// <param name="StateObject">The state object passed from the SessionDictionary.Read method</param>
        private void CompleteReadRequest(ISessionObject Session, object StateObject)
        {
            ServiceMessage msg = (ServiceMessage)StateObject;

            if (Session.IsLocked)
            {
                Reply(BuildResponse(typeof(LockedResponse), null, Session.CreateResponseInfo(), null));
                return;
            }
            else
            {

                Reply( BuildResponse(typeof(OKResponse), null, Session.CreateResponseInfo(), Session.Data));

                if (Session.ExtraFlags != -1) Session.ExtraFlags = -1; //Disable extraflags
            }

        }


        /// <summary>
        /// Generates an appropriate ResponseData object for this message, filled with supplied data
        /// </summary>
        /// <param name="ResponseType">The Type of the Response message</param>
        /// <param name="ResponseMessage">The HTTP response reason phrase</param>
        /// <param name="ResponseInfo">The session response information</param>
        /// <param name="Content">The response data</param>
        /// <returns>A filled ResponseData object</returns>
        protected override ResponseData BuildResponse(Type ResponseType, string ResponseMessage, ISessionResponseInfo ResponseInfo, byte[] Content)
        {
            StringBuilder sb = new StringBuilder();
            bool appendContent = false;

            if(ResponseType == typeof(OKResponse))
            {
                OKResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion, ResponseInfo);
                appendContent = true;
            }
            else if(ResponseType == typeof(NotFoundResponse))
            {
                NotFoundResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else if (ResponseType == typeof(LockedResponse))
            {
                LockedResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion, ResponseInfo);
            }
            else if (ResponseType == typeof(BadRequestResponse))
            {
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else
            {
                Diags.Fail("ASSERTION Failed -- unexpected response type: " + ResponseType.Name + " at " + new System.Diagnostics.StackTrace().ToString() + "\r\n");
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            
            return new ResponseData(MergeResponseData(sb, Content, appendContent, socket.IsAuthenticated && service.Settings.EncryptPeerData,service.Authenticator,socket.SessionKey ), ResponseType);
        }

    }

    /// <summary>
    /// Represents the GetExclusiveRequest message.
    /// </summary>
    /// <remarks>
    /// This message is sent from a client (web server) to a state server to request 
    /// session data exclusively.
    /// This message is only transmitted from client to state server.
    /// </remarks>
    public class GetExclusiveRequest : ServiceRequest
    {

        short exportCount = 0;

        /// <summary>
        /// Initializes a new instance of the GetExclusiveRequest class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public GetExclusiveRequest(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
            //Validate 
            if (!isError)
            {
                //This message requires a resource
                if (verb.Resource == string.Empty)
                {
                    isError = true;
                }
            }

        }


        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {

            if (!SourceIsConnected) return;
            if (!Validate())
            {
                Reply(BuildResponse(typeof(BadRequestResponse), null, null, null));
                return;
            }
            if (SourceIsPeer)
            {
                //This message cannot come from a peer
                Reply(BuildResponse(typeof(BadRequestResponse), "Request is not on Webserver port", null, null));
                return;
            }

            switch (service.SessionTable.Read(Resource, CompleteExclusiveReadRequest, this))
            {
                case SessionActionResult.NotFound:

                    //Not found                
                    if (QueryNetwork())
                    {
                        return;
                    }
                    else
                    {
                        Reply(BuildResponse(typeof(NotFoundResponse), null, null, null));
                        return;

                    }


                case SessionActionResult.Exporting:

                    if (exportCount > 1)
                    {
                        //This can occur on a rare occasion
                        Diags.LogContentionDetected("GetExclusiveRequest Export is trying for the second time", "Message Ignored");
                        return;
                    }
                    //Already exporting -- try this request after export is complete
                    service.AppendActiveExportEndedEvent(Resource, (delegate(string not_used) { Process(); }));
                    exportCount++;
                    return;

            }
        }


        /// <summary>
        /// Generates an appropriate ResponseData object for this message, filled with supplied data
        /// </summary>
        /// <param name="ResponseType">The Type of the Response message</param>
        /// <param name="ResponseMessage">The HTTP response reason phrase</param>
        /// <param name="ResponseInfo">The session response information</param>
        /// <param name="Content">The response data</param>
        /// <returns>A filled ResponseData object</returns>
        protected override ResponseData BuildResponse(Type ResponseType, string ResponseMessage, ISessionResponseInfo ResponseInfo, byte[] Content)
        {
            StringBuilder sb = new StringBuilder();
            bool appendContent = false;

            if(ResponseType == typeof(OKResponse))
            {
                OKResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion, ResponseInfo);
                appendContent = true;
            }
            else if(ResponseType == typeof(NotFoundResponse))
            {
                NotFoundResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else if (ResponseType == typeof(LockedResponse))
            {
                LockedResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion, ResponseInfo);
            }
            else if (ResponseType == typeof(BadRequestResponse))
            {
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else
            {
                Diags.Fail("ASSERTION Failed -- unexpected response type: " + ResponseType.Name + " at " + new System.Diagnostics.StackTrace().ToString() + "\r\n");
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }

            return new ResponseData(MergeResponseData(sb, Content, appendContent, socket.IsAuthenticated && service.Settings.EncryptPeerData,service.Authenticator,socket.SessionKey ), ResponseType);
        }




        /// <summary>
        /// Called by the SessionDictionary.Read() method to complete processing the request, 
        /// if the requested session was found and read
        /// </summary>
        /// <param name="Session">The read session object</param>
        /// <param name="StateObject">The state object passed from the SessionDictionary.Read() method</param>
        private void CompleteExclusiveReadRequest(ISessionObject Session, object StateObject)
        {

            ServiceMessage msg = (ServiceMessage)StateObject;

            if (Session.IsLocked)
            {

                Reply(BuildResponse(typeof(LockedResponse), null, Session.CreateResponseInfo(), null));
                return;

            }
            else
            {

                if (socket.CheckConnection()) //This request locks up sessions so make sure connection is still valid before locking/responding
                {
                    Session.Lock();

                    //Increment LockCookie until it reaches the maximum LockCookie value;
                    Session.LockCookie++;
                    if (Session.LockCookie > MAX_LockCookieValue)
                    {
                        Session.LockCookie = 2; //Roll over
                    }

                    Reply(BuildResponse(typeof(OKResponse), null, Session.CreateResponseInfo(), Session.Data));

                    if (Session.ExtraFlags != -1) Session.ExtraFlags = -1; //Disable extraflags
                }
                else
                {
                    Diags.LogIgnoredMessage(this, "Connection was dropped");
                }
            }



        }

    }

    /// <summary>
    /// Represents the GetTransferMessage message
    /// </summary>
    /// <remarks>
    /// The GetTransferMessage is broadcast to all connected peers when a peer wishes 
    /// to receive a session resource from the network. The message is in turn forwarded to other peers that
    /// receive the message until tthe message traverses the network.
    /// If a peer receives this message and has the requested session resource, it proceeds to transfer 
    /// the session resource to the peer that originated the broadcast.
    /// 
    /// This message is only transmitted between peers.
    /// </remarks>
    public class GetTransferMessage : PeerMessage
    {
        private short exportCount = 0;

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!Validate())
            {
                Diags.LogIgnoredMessage(this, "Message is not valid");
                return;
            }

            if (!SourceIsPeer || (!SourceIsAuthenticated && service.Settings.AuthenticatePeers))
            {
                Diags.LogIgnoredMessage(this, "Unauthenticated source");
                return;
            }

            //Did I originate this message?
            if(service.QueriesInitiated.ContainsKey(id.Value))
            {
            //Yes
                //Is this the original broadcast (been bounced back)? -- if so leave
                if (broadcastID == Guid.Empty)
                {
                    Diags.LogIgnoredMessage(this, "Broadcast originated by me");
                    return;
                }
                
                //Have I seen this rebroadcast before -- if so leave
                if (service.QueriesReceived.ContainsKey(GetHashCode()))
                {
                    Diags.LogIgnoredMessage(this, "Rebroadcast was previously processed");
                    return;
                }

                //Add this message to the messages received list
                service.QueriesReceived.Add(DateTime.UtcNow + new TimeSpan(0, 1, 0),GetHashCode(),null);

                ////Check if I somehow mysteriously have this session
                if(service.SessionTable.Read(Resource, null,null) == SessionActionResult.NotFound)
                {   //Not Found -- forward message to peers

                    Forward();
                }
                else
                {  //Found -- this session may have arrived a split second as the original message was been forwarded so Process original request
                    service.CallExpectedTransferReceivedActions(Resource);
                }

                return;
            }
            else
            {
            //No
                //Have I seen this message broadcast before (Msg-ID + Broadcast-ID) -- if so leave
                if (service.QueriesReceived.ContainsKey(GetHashCode()))
                {
                    Diags.LogIgnoredMessage(this, "Broadcast was previously processed");
                    return;
                }

                //Add this message to the messages received list
                service.QueriesReceived.Add(DateTime.UtcNow + new TimeSpan(0, 1, 0), GetHashCode(), null);

                //Check if the requested session is here and begin transfer
                SessionActionResult res;
                try
                {
                    res = service.SessionTable.BeginExport(Resource, CompleteTransferRequest, this);
                }
                catch(Exception ex)
                {
                    //Something went wrong, so end export immediately
                    Diags.Fail("Error in BeginExport .... " + ex.Message + "\r\n\r\n" + " .... Ending Export.\r\n");

                    List<AsyncResultActions<string>> calls = service.RemoveActiveExport(Resource);
                    service.SessionTable.EndExport(Resource, false);
                    if (calls != null) CallExportEndedActions(calls);
                    

                    //rethrow exception
                    throw;                    
                }

                //session was not found
                if (res == SessionActionResult.NotFound)
                {
                    //If the requested session was recently transferred out by this peer then rebroadcast this message
                    if (service.SentTransfers.ContainsKey(Resource))
                    {
                        //I may have sent this session to a peer after that peer forwarded this message, so rebroadcast
                        service.SentTransfers.Remove(Resource);
                        Rebroadcast();
                    }
                    else
                    {
                        //Forward to peers
                        Forward();
                    }
                }
                else if (res == SessionActionResult.Exporting)
                {
                    if (exportCount > 1)
                    {
                        //This should NEVER occur because the ExportEndedAcation doesn't call Process() i'm keeping this clause just in case the Rebroadcast() delegate is changed to Process()
                        Diags.LogContentionDetected("GetTransferMessage Export is trying for the second time","Message Ignored");
                        return;
                    }

                    //This session is already been exported so queue a rebroadcast after the session is done exporting

                    //NOTE: There is a chance that the export will fail and this peer will still have the sought session.
                    //While it is possible to have the Export Ended Action to call process() again and catch this situation, 
                    //The chance that the transfer will fail is slim and it's a bad idea because if GetTransferMessages 
                    //are queued, they can start another Export which will lead other queued export ended actions to wait again.
                    //so it's safer to assume the export succeeded and simply rebroadcast.

                    //TODO: ENHANCEMENT: If this becomes an issue, one way to deal with this is to have a seperate queue for GetTransfermessages which will
                    //be called after all actions in the regular queue have been called. In this case the Contention detection code above
                    //will legitimately catch multiple exports in which case the message should just be ignored.

                    service.AppendActiveExportEndedEvent(Resource, delegate(string not_used) { Rebroadcast(); });
                    exportCount++;
 
                }
                return;
            }

        }

        /// <summary>
        /// Called by the SessionDictionary.BeginExport method to complete processing the request, 
        /// if the requested session was found and read
        /// </summary>
        /// <param name="Session">The read session</param>
        /// <param name="StateObject">The state object passed from the SessionDictionary.BeginExport method</param>
        private void CompleteTransferRequest(ISessionObject Session, object StateObject)
        {
            ISessionResponseInfo response = Session.CreateResponseInfo();
           
            //Get the endpoint for the host to connect to
            string remoteHost;
            int? remotePort;
            ServerSettings.HostEndPoint.Parse(Host,out remoteHost,out remotePort);
            if(!remotePort.HasValue) remotePort = service.Settings.PeerPort;

            const int sentTransferExpiryTime = 2; // 2 seconds is sufficient for a broadcast to traverse half a reasonable network

            service.NewActiveExport(Resource); //create an entry in the exports list for this export

            service.TransferSession(new ServerSettings.HostEndPoint(remoteHost.Trim(), remotePort.Value), Resource, response, Session.Data,
                //SuccessAction
                delegate(ServiceSocket transferSock)
                {
                    //Add this transfer to list of recently transferred sessions and have it expire in 15 seconds
                    service.SentTransfers.Add(DateTime.UtcNow + new TimeSpan(0, 0, sentTransferExpiryTime), Resource, null);

                    TransferSuccess(transferSock);
                    Diags.LogTransferSuccess(Resource);
                },

                //FailedAction
                delegate(ServiceSocket transferSock)
                {
                    TransferFailure(transferSock);
                    Diags.LogTransferFailed(Resource, string.Empty);
                },

                //AlreadyExistsAction
                delegate(ServiceSocket transferSock)
                {
                    //Add this transfer to list of recently transferred sessions and have it expire in 15 seconds
                    service.SentTransfers.Add(DateTime.UtcNow + new TimeSpan(0, 0, sentTransferExpiryTime), Resource, null);

                    TransferSuccess(transferSock);
                    Diags.LogTransferFailed(Resource, "Resource already exists in remote peer -- deleted local copy");
                },

                //PeerShuttingDownAction
                delegate(ServiceSocket transferSock)
                {
                    TransferFailure(transferSock);
                    Diags.LogTransferFailed(Resource, "Peer is shutting down");
                },

                //TimeoutAction                
                delegate(object transferSock)
                {
                    //This anonymous method can be called directly from a background thread so make sure its exception-safe
                    try
                    {
                        TransferFailure((ServiceSocket)transferSock);
                        Diags.LogTransferFailed(Resource, "Timed out");
                    }
                    catch (Exception ex)
                    {
                        Diags.LogApplicationError( "TimeoutAction delegate error in CompleteTransferRequest", ex);
                    }
                }); 
                

        }

        /// <summary>
        /// Ends a successful session transfer
        /// </summary>
        /// <param name="TransferringSocket">The ServiceSocket over which the session data was being transferred</param>
        private void TransferSuccess(ServiceSocket TransferringSocket)
        {

            List<AsyncResultActions<string>> calls = service.RemoveActiveExport(Resource);
            service.SessionTable.EndExport(Resource, true);

            if (TransferringSocket.IsConnected)
            {
                Diags.LogDisconnectingPeer(TransferringSocket.RemoteIP);
                TransferringSocket.Close();

            }

            if (calls != null) CallExportEndedActions(calls);

        }

        /// <summary>
        /// Ends a failed Session Transfer
        /// </summary>
        /// <param name="TransferringSocket">The ServiceSocket over which the session data was being transferred</param>
        private void TransferFailure(ServiceSocket TransferringSocket)
        {
            List<AsyncResultActions<string>> calls = service.RemoveActiveExport(Resource);
            service.SessionTable.EndExport(Resource, false);

            if (TransferringSocket.IsConnected)
            {
                Diags.LogDisconnectingPeer(TransferringSocket.RemoteIP);
                TransferringSocket.Close();

            }

            if (calls != null) CallExportEndedActions(calls);
            
        }

        /// <summary>
        /// Initializes a new instance of the GetTransferMessage class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public GetTransferMessage(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {

            //Validate 
            if (!isError)
            {
                //This message requires a resource, a maxForwards and an ID
                if (verb.Resource == string.Empty || maxForwards == null || id == null)
                {
                    isError = true;
                }
            }
        }

        /// <summary>
        /// Sends a GetTransferMessage to a list of ServiceSockets and queues an Action to be called if the 
        /// requested session is transferred to this peer, and another Action to be called if no session is
        /// transferred after a set time.
        /// </summary>
        /// <param name="OriginHost">The Host name of the peer that originally initiated this message</param>
        /// <param name="sockets">List of target ServiceSockets</param>
        /// <param name="Service">Instance of state server</param>
        /// <param name="SessionKey">The requested session URI</param>
        /// <param name="MessageID">The unique message identifier</param>
        /// <param name="MaxForwards">The maximum number of nodes to forward the message to. This field is decremented by one for each forward</param>
        /// <param name="BroadcastID">The broadcast identifier. Used by peers to identify different broadcasts of the same message</param>
        /// <param name="TimeoutStamp">The Time in UTC, at which point the message query is considered timed out</param>
        /// <param name="FoundAction">The Action to be called if the requested session is transferred to this peer</param>
        /// <param name="TimeoutAction">The Action to be called if the requested session is not transferred to this peer after the TimeoutStamp time</param>
        public static void Broadcast(string OriginHost, List<ServiceSocket> sockets, StateServer Service, string SessionKey, 
            Guid MessageID, int MaxForwards, Guid BroadcastID, DateTime TimeoutStamp,
            Action<string> FoundAction, System.Threading.WaitCallback TimeoutAction )
        {
            if (sockets.Count == 0 || MaxForwards < 0) return;

            if (FoundAction != null && TimeoutAction != null)
            {
                if (!Service.NewExpectedTransfer(SessionKey, FoundAction, TimeoutAction, TimeoutStamp))
                {
                    //There's no point broadcasting another GetTransferMessage since an Action has done this earlier
                    return;
                }
            }

            string msgID = MessageID.ToString("N");

            string format;
            if (BroadcastID != Guid.Empty)
            {
                format = "GET {0} HTTP/1.1\r\nHost: {1}\r\nX-ID: {2}\r\nExclusive: transfer\r\nX-Broadcast-ID: {3}\r\nMax-Forwards: {4}\r\n\r\n";
            }
            else
            {
                format = "GET {0} HTTP/1.1\r\nHost: {1}\r\nX-ID: {2}\r\nExclusive: transfer\r\nMax-Forwards: {4}\r\n\r\n";
            }


            byte[] formatted = Encoding.UTF8.GetBytes(String.Format(format, SessionKey, OriginHost, msgID, BroadcastID.ToString("N"), MaxForwards));

            //send message to all sockets in sockets list
            foreach (ServiceSocket socket in sockets)
            {
                ResponseData rdata = new ResponseData(formatted, typeof(GetTransferMessage));
                socket.Send(rdata);
                Diags.LogSend(socket, rdata);
            }

        }

        /// <summary>
        /// Sends a GetTransferMessage to a list of ServiceSockets
        /// </summary>
        /// <param name="OriginHost">The Host name of the peer that originally initiated this message</param>
        /// <param name="sockets">List of target ServiceSockets</param>
        /// <param name="Service">Instance of state server</param>
        /// <param name="SessionKey">The requested session URI</param>
        /// <param name="MessageID">The unique message identifier</param>
        /// <param name="MaxForwards">The maximum number of nodes to forward the message to. This field is decremented by one for each forward</param>
        /// <param name="BroadcastID">The broadcast identifier. Used by peers to identify different broadcasts of the same message.</param>
        public static void Broadcast(string OriginHost, List<ServiceSocket> sockets, StateServer Service, string SessionKey,
            Guid MessageID, int MaxForwards, Guid BroadcastID)
        {
            Broadcast(OriginHost ,sockets, Service, SessionKey, MessageID, MaxForwards, BroadcastID, DateTime.MinValue, null, null);
        }


        /// <summary>
        /// Forwards this message to other peers on the network
        /// </summary>
        /// <seealso cref="Rebroadcast"/>
        public override void Forward()
        {

            //Shorten MaxForwards if it exceeds the set maxforwards
            if (maxForwards.HasValue && maxForwards.Value > service.Settings.MaxForwards) maxForwards = (uint)service.Settings.MaxForwards;

            List<ServiceSocket> forwardList = new List<ServiceSocket>();
            ServiceSocket[] peers = service.LivePeers;

            foreach (ServiceSocket peer in peers)
            {
                if (peer != socket)
                    forwardList.Add(peer);
            }

            if (maxForwards.HasValue && maxForwards.Value > 0 && ID.HasValue && forwardList.Count > 0)
            {
                Diags.LogForwardingNetworkQuery(Resource);
                Broadcast(Host.Trim(),forwardList, service, Resource, ID.Value, (int)maxForwards.Value - 1,broadcastID);
            }
        }

        /// <summary>
        /// Rebroadcasts this message across the network.
        /// Rebroadcasts are different from Forwards because they have a different broadcast id and are also sent to the originating peer
        /// </summary>
        /// <seealso cref="Forward"/>
        public void Rebroadcast()
        {

            List<ServiceSocket> forwardList = new List<ServiceSocket>(service.LivePeers); //rebroadcasts goes to all peers including peer that sent this message

            if (ID.HasValue && forwardList.Count > 0)
            {
                Diags.LogRebroadcastingNetworkQuery(Resource);
                Guid rebroadCastid = Guid.NewGuid();
                service.QueriesReceived.Add(DateTime.UtcNow + new TimeSpan(0, 1, 0), GetMergedHashCode(id.Value, rebroadCastid), null);
                Broadcast(Host.Trim(), forwardList, service, Resource, ID.Value, service.Settings.MaxForwards, rebroadCastid);
            }
        }


        public override bool Equals(object obj)
        {

            if (obj == null || GetType() != obj.GetType())
            {
                return false;
            }
            return base.Equals(obj);
        }

        public override int GetHashCode()
        {
            if (!id.HasValue) return base.GetHashCode();
            return GetMergedHashCode(id.Value, broadcastID);
        }


        /// <summary>
        /// Gets a hashcode value based on the combination of the message's ID and RebroadcastID
        /// </summary>
        /// <param name="MessageID">The Message ID</param>
        /// <param name="BroadcastID">The Message Broadcast ID</param>
        /// <returns>The hashcode value</returns>
        private static int GetMergedHashCode(Guid MessageID, Guid BroadcastID)
        {
            byte[] composite = new byte[256];
            MessageID.ToByteArray().CopyTo(composite, 0);
            BroadcastID.ToByteArray().CopyTo(composite, 128);

            //merge composite into a single guid by calculating hash
            //always create a brand new hash algorithm for use in a muli-threaded environment
            System.Security.Cryptography.HashAlgorithm hashAlg = System.Security.Cryptography.MD5.Create();
            Guid newUnique = new Guid( hashAlg.ComputeHash(composite));

            hashAlg = null;

            //return the new Guid's hashcode
            return newUnique.GetHashCode();
            
            
        }

        /// <summary>
        /// Calls a list of Actions waiting to be processed after a session transfer is complete
        /// </summary>
        /// <param name="Actions">List of Actions to call</param>
        private static void CallExportEndedActions(List<AsyncResultActions<string>> Actions)
        {
            if (Actions == null) return;

            //Call all actions in the action list
            foreach (AsyncResultActions<string> call in Actions)
            {
                call.InvokeResult1Action();
            }
        }

    }


    /// <summary>
    /// Represents the PingMessage message
    /// </summary>
    /// <remarks>
    /// The PingMessage is sent from one peer to another for two reasons:
    /// 1. As a keep-alive mechanism.
    /// 2. To inform the recipient peer that he sending peer is a permanent peer connection that should be included 
    /// when the recipient peer is forwarding or broadcasting GetTransfer messages.
    /// This message can only be transmitted between peers.
    /// </remarks>
    public class PingMessage : PeerMessage
    {
        /// <summary>
        /// Initializes a new instance of the PingMessage class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public PingMessage(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {

        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!Validate())
            {
                Diags.LogIgnoredMessage(this, "Message is not valid");
                return;
            }
            if (!SourceIsPeer || (!SourceIsAuthenticated && service.Settings.AuthenticatePeers))
            {
                Diags.LogIgnoredMessage(this, "Unauthenticated source");
                return;
            }

            service.NewLivePeer(socket);

            //Send a PingReply Message
            PingReplyMessage.Send(socket, service.ASPNETVersion);
        }

        /// <summary>
        /// Sends a PingMessage message to a specified ServiceSocket
        /// </summary>
        /// <param name="socket">The target ServiceSocket</param>
        public static void Send(ServiceSocket socket)
        {
            ResponseData rdata = new ResponseData(Encoding.UTF8.GetBytes("GET \\PING HTTP/1.1\r\nHost: " + socket.LocalIP + "\r\nContent-Length: 0\r\n\r\n"), typeof(PingMessage));
            
            socket.Send(rdata);
            Diags.LogSend(socket, rdata);
        }

        /// <summary>
        /// Forward the message to connected peers
        /// </summary>
        public override void Forward()
        {
           //Do nothing
           //Pings are not forwarded so do nothing
        }
    }

    /// <summary>
    /// Represents the PingReplyMessage message
    /// </summary>
    /// <remarks>
    /// The PingReplyMessage is sent in response to a PingMessage
    /// This message is only used as a keep-alive mechanism and serves no other purpose.
    /// This message can only be transmitted between peers.
    /// </remarks>
    public class PingReplyMessage : PeerMessage
    {
        /// <summary>
        /// Initializes a new instance of the PingReplyMessage class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public PingReplyMessage(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {

        }

        /// <summary>
        /// Forward the message to connected peers
        /// </summary>
        public override void Forward()
        {
            //Do nothing
            //Ping replies are not forwarded so do nothing
        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!Validate())
            {
                Diags.LogIgnoredMessage(this, "Message is not valid");
                return;
            }
            //Do nothing, this message only serves as a keep-alive mechanism
        }

        /// <summary>
        /// Sends a PingReplyMessage message to a specified ServiceSocket
        /// </summary>
        /// <param name="socket">The target ServiceSocket</param>
        /// <param name="ASPNETVersion">The state server version</param>
        public static void Send(ServiceSocket socket, string ASPNETVersion)
        {
            ResponseData rdata = new ResponseData(Encoding.UTF8.GetBytes("200 OK\r\nX-AspNet-Version: " + ASPNETVersion + "\r\nServer: State Service Peer\r\nContent-Length: 0\r\n\r\n"), typeof(PingReplyMessage));
            
            socket.Send(rdata);
            Diags.LogSend(socket, rdata);

        }
}

    /// <summary>
    /// Represents the BeginAuthRequest message
    /// </summary>
    /// <remarks>
    /// The BeginAuthRequest message is sent to initiate the authentication process.
    /// 
    /// The authentication process is outlined below:
    /// 
    /// 1. Peer A  --- BeginAuthRequest ---)        Peer B (Peer A wishes to authenticate with Peer B)
    /// 2. Peer A  (--- UnauthorizedResponse ----   Peer B (Peer B sends a challenge to Peer A)
    /// 3. Peer A  --- CompleteAuthRequest --)      Peer B (Peer A calculates the digest and includes a challenge to Peer B)
    /// 4. Peer A  (--- OKResponse ---              Peer B (Peer B verifies Peer A's digest, authenticates Peer A and send digest for Peer A's challenge)
    /// 5. Peer A                                   Peer B (peer A verifies Peer B's digest and authenticates peer B)
    /// 
    /// If Peer B cannot verify Peer A's digest at step 4, Peer B sends an UnauthorizedResponse.
    /// If Peer A cannot verify Peer B's digest at step 5. Peer A disconnects the connection.
    /// As always, if Peer B stops responding at anytime, the authentication process times out at Peer A.
    /// 
    /// This message is only transmitted between peers.
    /// </remarks>
    /// <seealso cref="CompleteAuthRequest"/>
    public class BeginAuthRequest : ServiceRequest
    {
        /// <summary>
        /// Initializes a new instance of the BeginAuthRequest class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public BeginAuthRequest(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {

        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!SourceIsConnected) return;
            if (!Validate())
            {
                Reply(BuildResponse(typeof(BadRequestResponse), null, null, null));
                return;
            }
            if (!SourceIsPeer)
            {
                //This message can only come from a peer
                Reply(BuildResponse(typeof(BadRequestResponse), "Request is not on peer port", null, null));
                return;
            }

            //Reply AUTH request with Unauthorized (401)
            Reply(BuildResponse(typeof(UnauthorizedResponse), null, null, null));

        }

        /// <summary>
        /// Generates an appropriate ResponseData object for this message, filled with supplied data
        /// </summary>
        /// <param name="ResponseType">The Type of the Response message</param>
        /// <param name="ResponseMessage">The HTTP response reason phrase</param>
        /// <param name="ResponseInfo">The session response information</param>
        /// <param name="Content">The response data</param>
        /// <returns>A filled ResponseData object</returns>
        protected override ResponseData BuildResponse(Type ResponseType, string ResponseMessage, ISessionResponseInfo ResponseInfo, byte[] Content)
        {
            StringBuilder sb = new StringBuilder();
            bool appendContent = false;
            string requestedNonce = service.Authenticator.GetNewChallenge();

            if (ResponseType == typeof(UnauthorizedResponse))
            {             
                UnauthorizedResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion, requestedNonce, service.Authenticator.Realm, service.Authenticator.HashAlgorithmName );

            }
            else if (ResponseType == typeof(BadRequestResponse))
            {
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else
            {
                Diags.Fail("ASSERTION Failed -- unexpected response type: " + ResponseType.Name + " at " + new System.Diagnostics.StackTrace().ToString() + "\r\n");
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);                
            }

            ResponseData rdata = new ResponseData(MergeResponseData(sb, Content, appendContent, socket.IsAuthenticated && service.Settings.EncryptPeerData, service.Authenticator, socket.SessionKey), ResponseType);
            rdata.Tag = requestedNonce;
            return rdata;
        }

        //Timeout action needs to be very short as it can be chained in a long call list of time out actions
        /// <summary>
        /// Sends a BeginAuthRequest message to a specified ServiceSocket
        /// </summary>
        /// <param name="socket">The target ServiceSocket</param>
        /// <param name="Service">The state server instance</param>
        /// <param name="SuccessAction">The Action to call if the message was accepted</param>
        /// <param name="FailAction">The Action to call if the message transmission failed or was refused</param>
        /// <param name="TimeoutAction">The Action to call if the transfer timed out This Action's processing time should be very short because a long list of Timeout actions can be daisy-chained and called one after the other</param>
        /// <param name="Timeout">The timeout time span</param>
        public static void Send(ServiceSocket socket, StateServer Service, Action<ServiceSocket> SuccessAction, Action<ServiceSocket> FailAction, System.Threading.WaitCallback TimeoutAction, TimeSpan Timeout)
        {

            ResponseData rdata = new ResponseData(Encoding.UTF8.GetBytes("GET \\AUTH HTTP/1.1\r\nHost: " + socket.LocalIP + "\r\n\r\n"), typeof(BeginAuthRequest));

            //Create new AsyncResultActions object to hold delegates for actions based on the outcome of the call
            AsyncResultActions<ServiceSocket> asyncResults = new AsyncResultActions<ServiceSocket>(socket);
            asyncResults.Result1Action = SuccessAction;
            asyncResults.Result2Action = FailAction;
            asyncResults.TimeoutAction = TimeoutAction;

            Service.AsyncRequests.Add(DateTime.UtcNow + Timeout, socket, asyncResults); 
                        
            socket.Send(rdata);
            Diags.LogSend(socket, rdata);
        }

    }

    /// <summary>
    /// Represents the CompleteAuthRequest message
    /// </summary>
    /// <remarks>
    /// The CompleteAuthRequest message is sent after a peer to finish the second half of the authentication process.
    /// 
    /// The authentication process is outlined below:
    /// 
    /// 1. Peer A  --- BeginAuthRequest ---)        Peer B (Peer A wishes to authenticate with Peer B)
    /// 2. Peer A  (--- UnauthorizedResponse ----   Peer B (Peer B sends a challenge to Peer A)
    /// 3. Peer A  --- CompleteAuthRequest --)      Peer B (Peer A calculates the digest and includes a challenge to Peer B)
    /// 4. Peer A  (--- OKResponse ---              Peer B (Peer B verifies Peer A's digest, authenticates Peer A and send digest for Peer A's challenge)
    /// 5. Peer A                                   Peer B (peer A verifies Peer B's digest and authenticates peer B)
    /// 
    /// If Peer B cannot verify Peer A's digest at step 4, Peer B sends an UnauthorizedResponse.
    /// If Peer A cannot verify Peer B's digest at step 5. Peer A disconnects the connection.
    /// As always, if Peer B stops responding at anytime, the authentication process times out at peer A.
    /// 
    /// This message is only transmitted between peers.
    /// </remarks>
    /// <seealso cref="BeginAuthRequest"/>
    public class CompleteAuthRequest : ServiceRequest
    {

        protected string username = null;
        protected string realm = null;
        protected string qop = null;
        protected string nonce = null;
        protected int ncount = 0;
        protected string cnonce = null;
        protected string response = null;
        protected string uri = null;
        protected string algorithm = null;


        string clientDigest = null;

        /// <summary>
        /// Initializes a new instance of the CompleteAuthRequest class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public CompleteAuthRequest(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
            string www_auth = headers["AUTHORIZATION"];

            if (www_auth != null)
            {
                //Split comma-delimited directives
                string[] directives = www_auth.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                //first check for and remove 'Digest' from the first line
                if (directives.Length > 0 && directives[0].Trim().ToUpperInvariant().StartsWith("DIGEST"))
                {
                    directives[0] = directives[0].Trim().Substring(6); //remove digest word

                    //Read realm, qop and nonce
                    foreach (string line in directives)
                    {
                        string key, value;
                        GetKeyValue(line, '=', out key, out value);

                        switch (key.ToUpperInvariant().Trim())
                        {
                            case "USERNAME":
                                username = Unquote(value).Trim();
                                break;

                            case "REALM":
                                realm = Unquote(value).Trim();
                                break;

                            case "QOP":
                                qop = Unquote(value).Trim();
                                break;

                            case "NONCE":                                                             
                                nonce = Unquote(value).Trim();
                                if (!IsValidBase64(nonce)) nonce = null;
                                break;

                            case "CNONCE":
                                cnonce = Unquote(value).Trim();
                                if (!IsValidBase64(cnonce)) cnonce = null;
                                break;

                            case "URI":
                                uri = Unquote(value);
                                break;

                            case "RESPONSE":                                    
                                response = Unquote(value).Trim();
                                if (!IsValidBase64(response)) response = null;
                                break;

                            case "NC":
                                Int32.TryParse(Unquote(value),System.Globalization.NumberStyles.HexNumber,null, out ncount);
                                break;

                            case "ALGORITHM":
                                algorithm = Unquote(value).Trim();
                                break;


                        }

                        
                    }

                }


            }

            //Validate
            if (!isError)
            {
                //This message requires username, realm, qop, nonce, cnonce, response and uri
                if (username == null || qop == null || nonce == null || cnonce == null || realm == null || response == null || uri == null)
                {
                    isError = true;
                }
            }

        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!SourceIsConnected) return;
            if (!Validate())
            {
                Reply(BuildResponse(typeof(BadRequestResponse), null, null, null));
                return;
            }
            if (!SourceIsPeer)
            {
                //This message can only come from a peer
                Reply(BuildResponse(typeof(BadRequestResponse), "Request is not on peer port", null, null));
                return;
            }

            //Check if last message sent was a 401
            ResponseData[] sentMsgs = socket.SentMessages;
            if (sentMsgs != null && sentMsgs.Length > 0 && sentMsgs[sentMsgs.Length - 1].ResponseType == typeof(UnauthorizedResponse))
            {
                //Check if the realm and nonce on this message matches the requested nonce
                if (realm == service.Authenticator.Realm && (string)sentMsgs[sentMsgs.Length - 1].Tag == nonce)
                {
                    //Verify Server Response Digest
                    string expectedResponse = service.Authenticator.GetServerResponseDigest(algorithm, username, realm, nonce, ncount, cnonce, qop, uri);
                    if (expectedResponse == response)
                    {
                        //Generate Client Response Digest
                        clientDigest = service.Authenticator.GetClientResponseDigest(this.algorithm, this.username, this.realm, this.nonce, this.ncount, this.cnonce, this.qop, this.uri);

                        //Flag socket as authenticated
                        socket.SessionKey = service.Authenticator.GetSessionKey(this.username, this.realm, this.nonce, this.cnonce);

                        //Reply with OK with Authentication-Info header
                        Reply(BuildResponse(typeof(OKResponse), null, null, null));

                        //Return
                        return;
                    }
                }

                Diags.LogPeerAuthenticationFailed("Authentication token mismatch in CompleteAuthRequest.Process()",socket.RemoteIP);
                //Reply with another 401 "Unauthorized" response
                Reply(BuildResponse(typeof(UnauthorizedResponse), null, null, null));

            }
            else
            {
                
                //I don't know why I'm receiving this message, so respond with a bad message
                Reply(BuildResponse(typeof(BadRequestResponse), null, null, null));
            }

        }

        /// <summary>
        /// Generates an appropriate ResponseData object for this message, filled with supplied data
        /// </summary>
        /// <param name="ResponseType">The Type of the Response message</param>
        /// <param name="ResponseMessage">The HTTP response reason phrase</param>
        /// <param name="ResponseInfo">The session response information</param>
        /// <param name="Content">The response data</param>
        /// <returns>A filled ResponseData object</returns>
        protected override ResponseData BuildResponse(Type ResponseType, string ResponseMessage, ISessionResponseInfo ResponseInfo, byte[] Content)
        {
            StringBuilder sb = new StringBuilder();
            bool appendContent = false;
            string requestedNonce = service.Authenticator.GetNewChallenge();

            if (ResponseType == typeof(OKResponse))
            {
                OKResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion, cnonce, clientDigest);
            }
            else if (ResponseType == typeof(UnauthorizedResponse))
            {
                UnauthorizedResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion, requestedNonce, service.Authenticator.Realm, service.Authenticator.HashAlgorithmName);

            }
            else if (ResponseType == typeof(BadRequestResponse))
            {
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else
            {
                Diags.Fail("ASSERTION Failed -- unexpected response type: " + ResponseType.Name + " at " + new System.Diagnostics.StackTrace().ToString() + "\r\n");
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);

            }

            return new ResponseData(MergeResponseData(sb, Content, appendContent, socket.IsAuthenticated && service.Settings.EncryptPeerData,service.Authenticator,socket.SessionKey ), ResponseType);            
        }

        /// <summary>
        /// Gets the value of the username field in the Authorization Request header according to RFC 2617
        /// </summary>
        public virtual string Username
        {
            get { return username; }
        }

        /// <summary>
        /// Gets the value of the realm field in the Authorization Request header according to RFC 2617
        /// </summary>
        public virtual string Realm
        {
            get { return realm; }
        }

        /// <summary>
        /// Gets the value of the message-qop field in the Authorization Request header according to RFC 2617
        /// </summary>
        public virtual string QoP
        {
            get { return qop; }
        }

        /// <summary>
        /// Gets the value of the nonce field in the Authorization Request header according to RFC 2617
        /// </summary>
        public virtual string Nonce
        {
            get { return nonce; }
        }

        /// <summary>
        /// Gets the value of the nonce-count field in the Authorization Request header according to RFC 2617
        /// </summary>
        public virtual int NonceCount
        {
            get { return ncount; }
        }

        /// <summary>
        /// Gets the value of the algorithm field in the Authorization Request header according to RFC 2617
        /// </summary>
        public virtual string Algorithm
        {
            get { return algorithm; }
        }

        /// <summary>
        /// Gets the value of the cnonce field in the Authorization Request header according to RFC 2617
        /// </summary>
        public virtual string ClientNonce
        {
            get { return cnonce; }
        }

        /// <summary>
        /// Gets the value of the response field in the Authorization Request header according to RFC 2617
        /// </summary>
        public virtual string Response
        {
            get { return response; }
        }

        /// <summary>
        /// Gets the value of the digest-uri field in the Authorization Request header according to RFC 2617
        /// </summary>
        public virtual string URI
        {
            get { return uri; }
        }

        /// <summary>
        /// Sends a CompleteAuthRequest message to a specified ServiceSocket.
        /// </summary>
        /// <param name="Nonce">The nonce field value in the Authorization Request Header, according o RFC 2617</param>
        /// <param name="ClientNonce">The cnonce field value in the Authorization Request Header, according o RFC 2617</param>
        /// <param name="ServerDigest">The response field value in the Authorization Request Header, according o RFC 2617</param>
        /// <param name="ClientDigest">The calculated Client Digest</param>
        /// <param name="SessionKey">The calculated data encryption session key</param>
        /// <param name="MachineName">The computer's name. Used as the username field value in the Authorization Request Header, according to RFC 2617</param>
        /// <param name="Algorithm">The algorithm field value in the Authorization Request Header, according o RFC 2617</param>
        /// <param name="Realm">The realm field value in the Authorization Request Header, according o RFC 2617</param>
        /// <param name="socket">The target ServiceSocket</param>
        public static void Send(string Nonce, string ClientNonce, string ServerDigest, string ClientDigest, byte[] SessionKey, string MachineName, string Algorithm, string Realm, ServiceSocket socket)
        {
            string msg = string.Format("GET \\AUTH HTTP/1.1\r\nHost: {0}\r\nAuthorization: Digest username = \"{1}\", realm=\"{2}\" , nonce=\"{3}\", uri =\"\\AUTH\",qop=\"auth\",nc=1,cnonce=\"{4}\" ,response=\"{5}\",algorithm=\"{6}\"\r\n\r\n"
            , socket.LocalIP, MachineName, Realm, Nonce, ClientNonce, ServerDigest, Algorithm);

            /*
             * SAMPLE:
             * 
                GET \AUTH
                Host: localhost
                Authorization: Digest username = "networkname", realm="state_service@PC-2" , nonce="NjMzODI1MzkyOTQ2NDA2MjUwOjE2ZjMwOTUx", uri ="\AUTH",qop="auth",nc=1,cnonce="NjMzODI1MzY5NzQ2ODc1MDAwOjcwZGQ0YWM5" ,response="10e10310780d80460c30f403801703f08b08c0d606807905c06d0140d70ff08e06404c0b30150130a501b0210720fa02",algorithm="SHA-256"
             * 
             */


            string[] refobject = new string[3];

            /*      Reference object is an object array:        
             * 
             *        Array[0] = cnonce
                      Array[1] = clientdigest
                      Array[2] = sessionkey 
             * 
             */

            refobject[0] = ClientNonce;
            refobject[1] = ClientDigest;
            refobject[2] = Convert.ToBase64String(SessionKey);

            ResponseData data = new ResponseData(Encoding.UTF8.GetBytes(msg), typeof(CompleteAuthRequest));
            data.Tag = refobject;

            socket.Send(data);
            Diags.LogSend(socket, data);
        }


    }


    /// <summary>
    /// Represents the SetRequest message
    /// </summary>
    /// <remarks>
    /// The SetRequest is sent by a client (web server) to a state server to store or update session data.
    /// This message is only sent from a client to a state server.
    /// </remarks>
    public class SetRequest : ServiceRequest
    {
        private bool networkSearched = false;

        /// <summary>
        /// Initializes a new instance of the SetRequest class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public SetRequest(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
            if (lockCookie == null) lockCookie = 0; //set 0 as default lock-cookie value

            //Validate
            if (!isError)
            {
                //This message requires a resource and a lock cookie
                if (verb.Resource == string.Empty || lockCookie == null )
                {
                    isError = true;
                }
            }

        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!SourceIsConnected) return;
            if (!Validate())
            {
                Reply(BuildResponse(typeof(BadRequestResponse), null, null, null));
                return;
            }
            if (SourceIsPeer)
            {
                //This message cannot come from a peer (the setTransferRequest can)
                Reply(BuildResponse(typeof(BadRequestResponse), "Request is not on Webserver port", null, null));
                return;
            }

            SessionResponseInfo lockedSessionInfo;

            if (extraFlags == "1") //INSERT-ONLY FLAG
            {
                //Attempt an insert-only
                switch (service.SessionTable.Add(Resource, new SessionObject(this), service.Settings.StandaloneMode || networkSearched, out lockedSessionInfo))
                {
                    case SessionActionResult.NotFound:
                        
                        if (!QueryNetwork(delegate(object not_used) {networkSearched = true; Process(); })) //Search the network but make it call this.Process() when the broadcast times out
                        {
                            //Add it forcefully
                            networkSearched = true;
                            Process();
                        }
                        break;
                    default:
                        //Reply with an OK even if the request did not succeed
                        Reply(BuildResponse(typeof(OKResponse), null, null, null));
                        break;

                }


            }
            else
            {

                switch (service.SessionTable.Update(Resource, new SessionObject(this), service.Settings.StandaloneMode || networkSearched, out lockedSessionInfo))
                {
                    case SessionActionResult.NotFound:

                        if (!QueryNetwork(delegate(object not_used) { networkSearched = true; Process(); })) //Search the network but make it call this.Process() when the broadcast times out
                        {
                            //Add it forcefully
                            networkSearched = true;
                            Process();
                        }
                        break;

                    case SessionActionResult.Exporting:
                        //currently exporting -- try this request after export is complete
                        service.AppendActiveExportEndedEvent(Resource, (delegate(string not_used) { Process(); }));
                        break;

                    case SessionActionResult.OK:
                        Reply(BuildResponse(typeof(OKResponse), null, null, null));
                        break;

                    case SessionActionResult.Locked:
                        Reply(BuildResponse(typeof(LockedResponse), null, lockedSessionInfo, null));
                        break;

                    default:
                        Reply(BuildResponse(typeof(BadRequestResponse), null, null, null));
                        break;
                }
            }

        }

        /// <summary>
        /// Generates an appropriate ResponseData object for this message, filled with supplied data
        /// </summary>
        /// <param name="ResponseType">The Type of the Response message</param>
        /// <param name="ResponseMessage">The HTTP response reason phrase</param>
        /// <param name="ResponseInfo">The session response information</param>
        /// <param name="Content">The response data</param>
        /// <returns>A filled ResponseData object</returns>
        protected override ResponseData BuildResponse(Type ResponseType, string ResponseMessage, ISessionResponseInfo ResponseInfo, byte[] Content)
        {
            StringBuilder sb = new StringBuilder();
            bool appendContent = false;

            if(ResponseType == typeof(OKResponse))
            {
                OKResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion, 0);                    
            }
            else if (ResponseType == typeof(LockedResponse))
            {
                LockedResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion, ResponseInfo);
            }
            else if (ResponseType == typeof(BadRequestResponse))
            {
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else
            {
                Diags.Fail("ASSERTION Failed -- unexpected response type: " + ResponseType.Name + " at " + new System.Diagnostics.StackTrace().ToString() + "\r\n");
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }

            return new ResponseData(MergeResponseData(sb, Content, appendContent, socket.IsAuthenticated && service.Settings.EncryptPeerData,service.Authenticator,socket.SessionKey ), ResponseType);
        }
    }

    /// <summary>
    /// Represents the SetTransferRequest message.
    /// </summary>
    /// <remarks>
    /// The SetTransferRequest message is sent by a peer to transfer a session resource to another peer.
    /// This message is only transmitted between peers.
    /// </remarks>
    public class SetTransferRequest : ServiceRequest
    {
        DateTime lastModified;
        DateTime? lockDate;
        TimeSpan? lockAge;

        /// <summary>
        /// Initializes a new instance of the SetTransferRequest class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public SetTransferRequest(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {

            lastModified = DateTime.MinValue;
            if (headers["LAST-MODIFIED"] != null)
            {
                long v;
                if (long.TryParse(headers["LAST-MODIFIED"], out v))
                {
                    try
                    {
                        lastModified = new DateTime(v);
                    }
                    catch
                    {
                        lastModified = DateTime.MinValue;
                    }
                }
            }

            lockDate = null;
            if (headers["LOCKDATE"] != null)
            {
                long v;
                if (long.TryParse(headers["LOCKDATE"], out v))
                {
                    try
                    {
                        lockDate = new DateTime(v);
                    }
                    catch
                    {
                        lockDate = null;
                    }
                }
            }

            lockAge = null;
            if (headers["LOCKAGE"] != null)
            {
                int v;
                if (int.TryParse(headers["LOCKAGE"], out v))
                {
                    try
                    {
                        lockAge = new TimeSpan(0,0,v);
                    }
                    catch
                    {
                        lockAge = null;
                    }
                }
            }

            //Validate 
            if (!isError)
            {
                //This message requires a resource + modified date
                if (verb.Resource == string.Empty || lastModified == DateTime.MinValue)
                {
                    isError = true;
                }

                //Lockdate + LockCookie + LockAge must be set if any is set
                if ((((lockDate == null) && (lockCookie == null) && (lockAge == null)) ^
                    ((lockDate == null) || (lockCookie == null) || (lockAge == null))) == true)
                {
                    isError = true;
                }

                //LockCookie must be valid
                if (lockCookie.HasValue && LockCookie.Value > MAX_LockCookieValue) isError = true;
            }

        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!SourceIsConnected) return;
            if (!Validate())
            {
                Reply(BuildResponse(typeof(BadRequestResponse), null, null, null));
                return;
            }
            if (!SourceIsPeer)
            {
                //This message can only come from peer port
                Reply(BuildResponse(typeof(BadRequestResponse), "Request is not on peer port", null, null));
                return;
            }
            if (!SourceIsAuthenticated && service.Settings.AuthenticatePeers)
            {                
                Reply(BuildResponse(typeof(UnauthorizedResponse), null,null,null));
                return;
            }

            //Check if service is shutting down
            if (service.IsStopping)
            {
                Reply(BuildResponse(typeof(ServiceUnavailableResponse), null, null, null));
                return;
            }

            SessionResponseInfo lockedSessionInfo;
            switch (service.SessionTable.Add(Resource, new SessionObject(this), true, out lockedSessionInfo))
            {
                case SessionActionResult.OK:

                    Diags.LogNetworkTransferredResource(Resource);

                    //Get reference object for this request and call all found delegates attached to it
                    service.CallExpectedTransferReceivedActions(Resource);

                    Reply(BuildResponse(typeof(OKResponse), null, null, null));
                    break;

                case SessionActionResult.AlreadyExists:
                case SessionActionResult.Exporting:
                    Reply(BuildResponse(typeof(PreconditionFailedResponse), null, null, null));
                    break;                    

                default:
                    Reply(BuildResponse(typeof(BadRequestResponse),null,null,null));
                    break;
            }

        }

        /// <summary>
        /// Generates an appropriate ResponseData object for this message, filled with supplied data
        /// </summary>
        /// <param name="ResponseType">The Type of the Response message</param>
        /// <param name="ResponseMessage">The HTTP response reason phrase</param>
        /// <param name="ResponseInfo">The session response information</param>
        /// <param name="Content">The response data</param>
        /// <returns>A filled ResponseData object</returns>
        protected override ResponseData BuildResponse(Type ResponseType, string ResponseMessage, ISessionResponseInfo ResponseInfo, byte[] Content)
        {            

            StringBuilder sb = new StringBuilder();
            bool appendContent = false;

            if (ResponseType == typeof(OKResponse))
            {
                OKResponse.AppendResponse(sb,ResponseMessage,service.ASPNETVersion,0);

            }
            else if (ResponseType == typeof(UnauthorizedResponse))
            {
                UnauthorizedResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion, service.Authenticator.GetNewChallenge(), service.Authenticator.Realm, service.Authenticator.HashAlgorithmName);
            }
            else if (ResponseType == typeof(BadRequestResponse))
            {
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else if (ResponseType == typeof(ServiceUnavailableResponse))
            {
                ServiceUnavailableResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else if (ResponseType == typeof(PreconditionFailedResponse))
            {
                PreconditionFailedResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else
            {
                Diags.Fail("ASSERTION Failed -- unexpected response type: " + ResponseType.Name + " at " + new System.Diagnostics.StackTrace().ToString() + "\r\n");
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }

            return new ResponseData(MergeResponseData(sb, Content, appendContent, socket.IsAuthenticated && service.Settings.EncryptPeerData,service.Authenticator,socket.SessionKey ), ResponseType);
        }


        /// <summary>
        /// Sends a SetTransferRequest message to a specified ServiceSocket
        /// </summary>
        /// <param name="socket">The target ServiceSocket</param>
        /// <param name="Service">The state server instance</param>
        /// <param name="Resource">The URI associated with the message</param>
        /// <param name="SessionInfo">The Session information used to populate fields in the message</param>
        /// <param name="Data">The message data</param>
        /// <param name="SuccessAction">The Action to call if the message was accepted</param>
        /// <param name="FailAction">The Action to call if the message transmission failed or was refused</param>
        /// <param name="AlreadyExistsAction">The Action to call if the recipient peer already has the URI</param>
        /// <param name="PeerShuttingDownAction">The Action to call if the recipient peer is shutting down</param>
        /// <param name="TimeoutAction">The Action to call if the transfer timed out. This Action's processing time should be very short because a long list of Timeout actions can be daisy-chained and called one after the other</param>
        /// <param name="Timeout">The timeout time span</param>
        public static void Send(ServiceSocket socket, StateServer Service, string Resource, ISessionResponseInfo SessionInfo,
            byte[] Data, Action<ServiceSocket> SuccessAction, Action<ServiceSocket> FailAction, Action<ServiceSocket> AlreadyExistsAction, Action<ServiceSocket> PeerShuttingDownAction, System.Threading.WaitCallback TimeoutAction, TimeSpan Timeout)
        {
            StringBuilder headers = new StringBuilder();

            headers.AppendFormat("PUT {0} HTTP/1.1\r\nHost: {1}\r\n", Resource, socket.LocalIP);

            if (SessionInfo.LockDateInTicks != DateTime.MinValue.Ticks)
            {
                headers.AppendFormat("LockDate: {0}\r\nLockAge: {1}\r\nLockCookie: {2}\r\n", SessionInfo.LockDateInTicks, SessionInfo.LockAgeInSeconds, SessionInfo.LockCookie);
            }

            headers.AppendFormat("X-If-None-Exists: true\r\nExclusive: transfer\r\nTimeout: {0}\r\nExtraFlags: {1}\r\nLast-Modified: {2}\r\n", SessionInfo.Timeout, SessionInfo.ActionFlags, SessionInfo.UpdateDateInTicks);

            ResponseData rdata = new ResponseData(
                MergeResponseData(headers, Data, true, Service.Settings.EncryptPeerData, Service.Authenticator, socket.SessionKey),
                typeof(SetTransferRequest)
            );

            //Create new AsyncResultActions object to hold delegates for actions based on the outcome of the call
            AsyncResultActions<ServiceSocket> asyncResults = new AsyncResultActions<ServiceSocket>(socket);
            asyncResults.Result1Action = SuccessAction;
            asyncResults.Result2Action = FailAction;
            asyncResults.Result3Action = AlreadyExistsAction;
            asyncResults.Result4Action = PeerShuttingDownAction;
            asyncResults.TimeoutAction = TimeoutAction;

            Service.AsyncRequests.Add(DateTime.UtcNow + Timeout, socket, asyncResults);

            socket.Send(rdata);

            Diags.LogSend(socket, rdata);
        }

        /// <summary>
        /// Gets the Last Modified date header value
        /// </summary>
        public DateTime LastModified
        {
            get { return lastModified; }
        }

        /// <summary>
        /// Gets the LockDate header value
        /// </summary>
        public DateTime? LockDate
        {
            get { return lockDate; }
        }

    }

    /// <summary>
    /// Represents the ReleaseExclusiveRequest message.
    /// </summary>
    /// <remarks>
    /// This message is sent from a client (web server) to a state server to request 
    /// that a session be unlocked.
    /// This message is only transmitted from client to state server.
    /// </remarks>
    public class ReleaseExclusiveRequest : ServiceRequest
    {
        short exportCount = 0;

        /// <summary>
        /// Initializes a new instance of the ReleaseExclusiveRequest class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public ReleaseExclusiveRequest(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
            //Validate
            if (!isError)
            {
                //This message requires a resource and a lock cookie
                if (verb.Resource == string.Empty || lockCookie == null )
                {
                    isError = true;
                }
            }

        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!SourceIsConnected) return;
            if (!Validate())
            {
                Reply(BuildResponse(typeof(BadRequestResponse), null, null, null));
                return;
            }
            if (SourceIsPeer)
            {
                //This message cannot come from a peer
                Reply(BuildResponse(typeof(BadRequestResponse), "Request is not on Webserver port", null, null));
                return;
            }

            switch (service.SessionTable.Read(Resource, CompleteReleaseRequest, this))
            {
                case SessionActionResult.NotFound:

                    //Not found                
                    if (QueryNetwork())
                    {
                        return;
                    }
                    else
                    {
                        Reply(BuildResponse(typeof(NotFoundResponse), null, null, null));
                        return;

                    }

                case SessionActionResult.Exporting:

                    //Curently exporting -- try this request after export is complete
                    if (exportCount > 1)
                    {
                        //This can occur on a rare occasion
                        Diags.LogContentionDetected("ReleaseExclusiveRequest Export is trying for the second time", "Message Ignored");
                        return;
                    }
                    service.AppendActiveExportEndedEvent(Resource, (delegate(string not_used) { Process(); }));
                    exportCount++;
                    return;

            }
        }

        /// <summary>
        /// Generates an appropriate ResponseData object for this message, filled with supplied data
        /// </summary>
        /// <param name="ResponseType">The Type of the Response message</param>
        /// <param name="ResponseMessage">The HTTP response reason phrase</param>
        /// <param name="ResponseInfo">The session response information</param>
        /// <param name="Content">The response data</param>
        /// <returns>A filled ResponseData object</returns>
        protected override ResponseData BuildResponse(Type ResponseType, string ResponseMessage, ISessionResponseInfo ResponseInfo, byte[] Content)
        {
            StringBuilder sb = new StringBuilder();
            bool appendContent = false;

            if (ResponseType == typeof(OKResponse))
            {
                OKResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion, ResponseInfo == null ? 0 : ResponseInfo.ActionFlags);
            }
            else if (ResponseType == typeof(NotFoundResponse))
            {
                NotFoundResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else if (ResponseType == typeof(LockedResponse))
            {
                LockedResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion, ResponseInfo);
            }
            else if (ResponseType == typeof(BadRequestResponse))
            {
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else
            {
                Diags.Fail("ASSERTION Failed -- unexpected response type: " + ResponseType.Name + " at " + new System.Diagnostics.StackTrace().ToString() + "\r\n");
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }

            return new ResponseData(MergeResponseData(sb, Content, appendContent, socket.IsAuthenticated && service.Settings.EncryptPeerData,service.Authenticator,socket.SessionKey ), ResponseType);
        }

        /// <summary>
        /// Called by the SessionDictionary.Read() method to complete processing the request,
        /// if the requested session was found and read
        /// </summary>
        /// <param name="Session">The read session object</param>
        /// <param name="StateObject">The state object passed from the SessionDictionary.Read() method</param>
        private void CompleteReleaseRequest(ISessionObject Session, object StateObject)
        {
            ServiceMessage msg = (ServiceMessage)StateObject;

            //check if LockCookies match
            if (Session.IsLocked)
            {
                if (!Session.UnLock(LockCookie.Value))
                {
                    //Reply with Locked response
                    Reply(BuildResponse(typeof(LockedResponse), null, Session.CreateResponseInfo(), null));
                    return;
                }
            }

            //Reply with OK response
            Reply(BuildResponse(typeof(OKResponse), null, Session.CreateResponseInfo(), null));

            if(Session.ExtraFlags != -1) Session.ExtraFlags = -1; //Disable extraflags

        }

    }

    /// <summary>
    /// Represents the RemoveRequest message.
    /// </summary>
    /// <remarks>
    /// This message is sent from a client (web server) to a state server to request 
    /// the deletion of a session.
    /// This message is only transmitted from client to state server.
    /// </remarks>
    public class RemoveRequest : ServiceRequest
    {
        short exportCount = 0;

        /// <summary>
        /// Initializes a new instance of the RemoveRequest class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public RemoveRequest(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
            if (lockCookie == null) lockCookie = 0; //set 0 as default lock-cookie value

            //Validate
            if (!isError)
            {
                //This message requires a resource and a lock cookie
                if (verb.Resource == string.Empty || lockCookie == null )
                {
                    isError = true;
                }
            }

        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!SourceIsConnected) return;
            if (!Validate())
            {
                Reply(BuildResponse(typeof(BadRequestResponse), null, null, null));
                return;
            }
            if (SourceIsPeer)
            {
                //This message cannot come from a peer
                Reply(BuildResponse(typeof(BadRequestResponse), "Request is not on Webserver port", null, null));
                return;
            }

            SessionResponseInfo lockedSessionInfo;
            switch (service.SessionTable.Remove(Resource, LockCookie.Value,out lockedSessionInfo))
            {
                case SessionActionResult.OK:
                    Reply(BuildResponse(typeof(OKResponse),null,null,null));
                    break;

                case SessionActionResult.NotFound:
                    //Not found                
                    if (QueryNetwork())
                    {
                        return;
                    }
                    else
                    {
                        Reply(BuildResponse(typeof(NotFoundResponse), null, null, null));
                        return;

                    }

                case SessionActionResult.Exporting:
                    //Curently exporting -- try this request after export is complete
                    if (exportCount > 1)
                    {
                        //This can occur on a rare occasion
                        Diags.LogContentionDetected("RemoveRequest Export is trying for the second time","Mesasage Ignored");
                        return;
                    }
                    //Already exporting -- try this request after export is complete
                    service.AppendActiveExportEndedEvent(Resource, (delegate(string not_used) { Process(); }));
                    exportCount++;
                    break;
                
                case SessionActionResult.Locked:
                    Reply(BuildResponse(typeof(LockedResponse),null,lockedSessionInfo,null));
                    break;

                default:
                    Reply(BuildResponse(typeof(BadRequestResponse),null,null,null));
                    break;
            }

        }

        /// <summary>
        /// Generates an appropriate ResponseData object for this message, filled with supplied data
        /// </summary>
        /// <param name="ResponseType">The Type of the Response message</param>
        /// <param name="ResponseMessage">The HTTP response reason phrase</param>
        /// <param name="ResponseInfo">The session response information</param>
        /// <param name="Content">The response data</param>
        /// <returns>A filled ResponseData object</returns>
        protected override ResponseData BuildResponse(Type ResponseType, string ResponseMessage, ISessionResponseInfo ResponseInfo, byte[] Content)
        {
            StringBuilder sb = new StringBuilder();
            bool appendContent = false;

            if (ResponseType == typeof(OKResponse))
            {
                OKResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion, 0);
            }
            else if (ResponseType == typeof(NotFoundResponse))
            {
                NotFoundResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else if (ResponseType == typeof(LockedResponse))
            {
                LockedResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion, ResponseInfo);
            }
            else if (ResponseType == typeof(BadRequestResponse))
            {
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else
            {
                Diags.Fail("ASSERTION Failed -- unexpected response type: " + ResponseType.Name + " at " + new System.Diagnostics.StackTrace().ToString() + "\r\n");
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }

            return new ResponseData(MergeResponseData(sb, Content, appendContent, socket.IsAuthenticated && service.Settings.EncryptPeerData,service.Authenticator,socket.SessionKey ), ResponseType);
        }
    }

    /// <summary>
    /// Represents the ResetTimeoutRequest message.
    /// </summary>
    /// <remarks>
    /// This message is sent from a client (web server) to a state server to request an extension to the
    /// expiration time of a session.
    /// This message is only transmitted from client to state server.
    /// </remarks>
    public class ResetTimeoutRequest : ServiceRequest
    {
        short exportCount = 0;

        /// <summary>
        /// Initializes a new instance of the ResetTimeoutRequest class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public ResetTimeoutRequest(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
            //Validate 
            if (!isError)
            {
                //This message requires a resource
                if (verb.Resource == string.Empty)
                {
                    isError = true;
                }
            }

        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {

            if (!SourceIsConnected) return;
            if (!Validate())
            {
                Reply(BuildResponse(typeof(BadRequestResponse), null, null, null));
                return;
            }
            if (SourceIsPeer)
            {
                //This message cannot come from a peer
                Reply(BuildResponse(typeof(BadRequestResponse), "Request is not on Webserver port", null, null));
                return;
            }

            switch (service.SessionTable.Read(Resource, CompleteResetTimeoutRequest, this))
            {
                case SessionActionResult.NotFound:

                    //Not found                
                    if (QueryNetwork())
                    {
                        return;
                    }
                    else
                    {
                        Reply(BuildResponse(typeof(NotFoundResponse), null, null, null));
                        return;

                    }

                case SessionActionResult.Exporting:

                    if (exportCount > 1)
                    {
                        //This can occur on a rare occasion
                        Diags.LogContentionDetected("ResetTimeoutRequest Export is trying for the second time","Message Ignored");
                        return;
                    }
                    //Already exporting -- try this request after export is complete
                    service.AppendActiveExportEndedEvent(Resource, (delegate(string not_used) { Process(); }));
                    exportCount++;
                    return;

            }
        }

        /// <summary>
        /// Called by the SessionDictionary.Read() method to complete processing the request, 
        /// if the requested session was found and read
        /// </summary>
        /// <param name="Session">The read session object</param>
        /// <param name="StateObject">The state object passed from the SessionDictionary.Read() method</param>
        private void CompleteResetTimeoutRequest(ISessionObject Session, object StateObject)
        {
            ServiceMessage msg = (ServiceMessage)StateObject;

            Session.ResetTimeout();
            Reply(BuildResponse(typeof(OKResponse), null, Session.CreateResponseInfo(), null));

        }

        /// <summary>
        /// Generates an appropriate ResponseData object for this message, filled with supplied data
        /// </summary>
        /// <param name="ResponseType">The Type of the Response message</param>
        /// <param name="ResponseMessage">The HTTP response reason phrase</param>
        /// <param name="ResponseInfo">The session response information</param>
        /// <param name="Content">The response data</param>
        /// <returns>A filled ResponseData object</returns>
        protected override ResponseData BuildResponse(Type ResponseType, string ResponseMessage, ISessionResponseInfo ResponseInfo, byte[] Content)
        {
            StringBuilder sb = new StringBuilder();
            bool appendContent = false;

            if (ResponseType == typeof(OKResponse))
            {
                OKResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion, 0);
            }
            else if (ResponseType == typeof(NotFoundResponse))
            {
                NotFoundResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else if (ResponseType == typeof(BadRequestResponse))
            {
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }
            else
            {
                Diags.Fail("ASSERTION Failed -- unexpected response type: " + ResponseType.Name + " at " + new System.Diagnostics.StackTrace().ToString() + "\r\n");
                BadRequestResponse.AppendResponse(sb, ResponseMessage, service.ASPNETVersion);
            }

            return new ResponseData(MergeResponseData(sb, Content, appendContent, socket.IsAuthenticated && service.Settings.EncryptPeerData,service.Authenticator,socket.SessionKey ), ResponseType);
        }
    }

    /// <summary>
    /// Represents the OKResponse message
    /// </summary>
    /// <remarks>
    /// This message is sent by a state server to a client (web server) or from one peer to another
    /// to indicate that the requested action was successful.
    /// This message is transmitted from state server to client or between peers.
    /// </remarks>
    public class OKResponse : ServiceResponse
    {
        //Authentication-Info header fields
        protected string authInfo_qop = null;
        protected string authInfo_rspauth = null;
        protected string authInfo_cnonce = null;
        protected int authInfo_ncount = 0;

        /// <summary>
        /// Initializes a new instance of the OKResponse class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public OKResponse(HTTPPartialData Data, StateServer Service) : base(Data,Service)
        {
            string auth_info = headers["AUTHENTICATION-INFO"];

            if (auth_info != null)
            {
                //Split comma-delimited directives
                string[] directives = auth_info.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                //Read rspauth, qop, cnonce and ncount
                foreach (string line in directives)
                {

                    string key, value;
                    GetKeyValue(line, '=', out key, out value);

                    switch (key.ToUpperInvariant().Trim())
                    {
                        case "RSPAUTH":                                
                            authInfo_rspauth = Unquote(value).Trim();
                            if (!IsValidBase64(authInfo_rspauth)) authInfo_rspauth = null;
                            break;

                        case "QOP":
                            authInfo_qop = Unquote(value).Trim();
                            break;

                        case "CNONCE":                                
                            authInfo_cnonce = Unquote(value).Trim();
                            if (!IsValidBase64(authInfo_cnonce)) authInfo_cnonce = null;
                            break;

                        case "NC":
                            Int32.TryParse(Unquote(value), System.Globalization.NumberStyles.HexNumber, null, out authInfo_ncount);
                            break;
                    }

                }
                
            }


            //Validate
            if (!isError)
            {
                //If there is an authentication-info header and the rspauth, qop, or cnonce directive is missing, 
                //then there is an error.
                if (auth_info != null && (authInfo_rspauth == null || authInfo_cnonce == null || authInfo_qop == null))
                {
                    isError = true;
                }
            }


        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!Validate())
            {
                Diags.LogIgnoredMessage(this, "Message is not valid");
                return;
            }

            //Check if this peer initiated an \AUTH request
            ResponseData[] sentMsgs = socket.SentMessages;
            if (sentMsgs != null && sentMsgs.Length > 0)
            {
                Type lastMsgType = sentMsgs[sentMsgs.Length - 1].ResponseType;
                if (lastMsgType == typeof(CompleteAuthRequest))
                {
                    //Remove reference object for this request from scavenger's list
                    AsyncResultActions<ServiceSocket> calls;
                    if (service.AsyncRequests.TryGetValue(socket, out calls))
                    {
                        if (service.AsyncRequests.Remove(socket))
                        {
                            if (authInfo_rspauth != null)
                            {
                                //String Array in reference tag is:
                                //slot[0] = cnonce
                                //slot[1] = client digest
                                //slot[3] = sessionkey

                                //Verify Client response digest
                                if (((string[])sentMsgs[sentMsgs.Length - 1].Tag)[0] == authInfo_cnonce
                                    && ((string[])sentMsgs[sentMsgs.Length - 1].Tag)[1] == authInfo_rspauth)
                                {

                                    //Flag socket as authenticated
                                    socket.SessionKey = Convert.FromBase64String(((string[])sentMsgs[sentMsgs.Length - 1].Tag)[2]);

                                    calls.InvokeResult1Action(); //Result1 is the success result

                                    //Return
                                    return;
                                }
                            }

                            //Authentication failed
                            Diags.LogPeerAuthenticationFailed("Verification of client response failed in OKResponse.Process()",socket.RemoteIP);
                            
                            socket.Abort();

                            //Call the 'failure' method for the original request that initiated the authentication process
                            calls.InvokeResult2Action(); //Result2 is failure

                            return;
                        }
                    }

                    return; //this async operation has already been handled

                }
                else if (lastMsgType == typeof(SetTransferRequest))
                {
                    //Remove reference object for this request from scavenger's list
                    AsyncResultActions<ServiceSocket> calls;
                    if (service.AsyncRequests.TryGetValue(socket, out calls))
                    {
                        if (service.AsyncRequests.Remove(socket))
                        {
                            //Call the 'Success' method for the original request that initiated the transfer
                            calls.InvokeResult1Action(); //Result1 is the Success action
                            return;
                        }
                    }

                    return; //This async operation was previously handled

                }

            }

            //I don't know why I'm receiving this

            //Abort connection
            socket.Abort();

 
        }

        public const int Code = 200;

        public const string DefaultMessage = "OK";
        
        /// <summary>
        /// Appends the raw response data to a string builder.
        /// Used to reply to all messages except CompleteAuthRequest, GetExclusiveRequest and GetRequest messages
        /// </summary>
        /// <param name="sb">The StringBuilder to append data to</param>
        /// <param name="Message">The response reason phrase</param>
        /// <param name="ASPNETVersion">The state server version</param>
        /// <param name="ActionFlags">Action flags value</param>
        internal static void AppendResponse(StringBuilder sb, string Message, string ASPNETVersion, int ActionFlags)
        {
            sb.AppendFormat("{0} {1}\r\nX-AspNet-Version: {2}\r\n", Code.ToString(), Message == string.Empty ? DefaultMessage : Message ?? DefaultMessage, ASPNETVersion);
            if (ActionFlags > 0)
            {
                sb.AppendFormat("ActionFlags: {0}\r\n", ActionFlags);
            }
            sb.AppendFormat("Cache-Control: private\r\n");
        }

        /// <summary>
        /// Appends the raw response data to a string builder.
        /// Used to reply to CompleteAuthRequest messages
        /// </summary>
        /// <param name="sb">The StringBuilder to append data to</param>
        /// <param name="Message">The response reason phrase</param>
        /// <param name="ASPNETVersion">The state server version</param>
        /// <param name="ClientNonce">The cnonce field value in the Authentication-Info Header, according to RFC 2617</param>
        /// <param name="ResponseDigest">The rspauth field value in the Authentication-Info Header, according to RFC 2617</param>
        internal static void AppendResponse(StringBuilder sb, string Message, string ASPNETVersion, string ClientNonce, string ResponseDigest)
        {
            if (ClientNonce == null || ResponseDigest == null)
            {
                AppendResponse(sb, Message, ASPNETVersion, 0);
                return;
            }

            sb.AppendFormat("{0} {1}\r\nX-AspNet-Version: {2}\r\n", Code.ToString(), Message == string.Empty ? DefaultMessage : Message ?? DefaultMessage, ASPNETVersion);
            sb.AppendFormat("Authentication-Info: qop=\"auth\",rspauth=\"{0}\",cnonce=\"{1}\",nc={2}\r\n",ResponseDigest,ClientNonce,1);

        }


        /// <summary>
        /// Appends the raw response data to a string builder.
        /// Used to reply to GetExclusiveRequest and GetRequest messages
        /// </summary>
        /// <param name="sb">The StringBuilder to append data to</param>
        /// <param name="Message">The response reason phrase</param>
        /// <param name="ASPNETVersion">The state server version</param>
        /// <param name="ResponseInfo">The session response info</param>
        internal static void AppendResponse(StringBuilder sb, string Message, string ASPNETVersion, ISessionResponseInfo ResponseInfo)
        {
            if (ResponseInfo == null)
            {
                AppendResponse(sb, Message, ASPNETVersion, ResponseInfo == null ? 0 : ResponseInfo.ActionFlags);
                return;
            }

            sb.AppendFormat("{0} {1}\r\nX-AspNet-Version: {2}\r\n", Code.ToString(), Message == string.Empty ? DefaultMessage : Message ?? DefaultMessage, ASPNETVersion);
            if (ResponseInfo.ActionFlags > 0)
            {
                sb.AppendFormat("ActionFlags: {0}\r\n", ResponseInfo.ActionFlags);
            }

            if (ResponseInfo.LockDateInTicks != DateTime.MinValue.Ticks)
            {
                //this session was locked
                sb.AppendFormat("LockCookie: {0}\r\n", ResponseInfo.LockCookie);
            }
            
            sb.AppendFormat("Timeout: {0}\r\nCache-Control: private\r\n", ResponseInfo.Timeout);

        }




    }

    /// <summary>
    /// Represents the BadRequestResponse message
    /// </summary>
    /// <remarks>
    /// This message is sent by a state server to a client (web server) or from one peer to another
    /// to indicate that the requested action could not be performed due to an error.
    /// This message is transmitted from state server to client or between peers.
    /// </remarks>
    public class BadRequestResponse : ServiceResponse
    {
        /// <summary>
        /// Initializes a new instance of the BadRequestResponse class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public BadRequestResponse(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
            //No Validation required

        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!Validate())
            {
                Diags.LogIgnoredMessage(this, "Message is not valid");
                return;
            }

            ProcessFailureResponse();

        }


        public const int Code = 400;

        public const string DefaultMessage = "Bad Request";

        /// <summary>
        /// Appends the raw response data to a string builder
        /// </summary>
        /// <param name="sb">The StringBuilder to append data to</param>
        /// <param name="Message">The response reason phrase</param>
        /// <param name="ASPNETVersion">The state server version</param>
        internal static void AppendResponse(StringBuilder sb,string Message, string ASPNETVersion)
        {
            sb.AppendFormat("{0} {1}\r\nX-AspNet-Version: {2}\r\nCache-Control: private\r\n", Code.ToString(), Message == string.Empty ? DefaultMessage : Message ?? DefaultMessage, ASPNETVersion);
        }
    }

    /// <summary>
    /// Represents the NotFoundResponse message
    /// </summary>
    /// <remarks>
    /// This message is sent by a state server to a client (web server) to indicate that the
    /// requested action could not be performed because the session was not found.
    /// This message is only transmitted from state server to client.
    /// </remarks>
    public class NotFoundResponse : ServiceResponse
    {

        /// <summary>
        /// Initializes a new instance of the NotFoundResponse class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public NotFoundResponse(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
            //Validate
            if (!isError)
            {
                //This message requires an empty content length
                if (body.Length != 0)
                {
                    isError = true;
                }
            }

        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!Validate())
            {
                Diags.LogIgnoredMessage(this, "Message is not valid");
                return;
            }

            //A Peer should not receive this message, if it is erroneously related to a sent request, then process it as a failure response
            ProcessFailureResponse();
            
        }

        public const int Code = 404;

        public const string DefaultMessage = "Not Found";

        /// <summary>
        /// Appends the raw response data to a string builder
        /// </summary>
        /// <param name="sb">The StringBuilder to append data to</param>
        /// <param name="Message">The response reason phrase</param>
        /// <param name="ASPNETVersion">The state server version</param>
        internal static void AppendResponse(StringBuilder sb, string Message, string ASPNETVersion)
        {
            sb.AppendFormat("{0} {1}\r\nX-AspNet-Version: {2}\r\nCache-Control: private\r\n", Code.ToString(), Message == string.Empty ? DefaultMessage : Message ?? DefaultMessage, ASPNETVersion);
        }
    }

    /// <summary>
    /// Represents the LockedResponse message
    /// </summary>
    /// <remarks>
    /// This message is sent by a state server to a client (web server) to indicate that the
    /// requested action could not be performed because the session is locked.
    /// This message is only transmitted from state server to client.
    /// </remarks>
    public class LockedResponse : ServiceResponse
    {
        /// <summary>
        /// Initializes a new instance of the LockedResponse class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public LockedResponse(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
            //Validate
            if (!isError)
            {
                //This message requires an empty content length
                if (body.Length != 0)
                {
                    isError = true;
                }
            }

        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!Validate())
            {
                Diags.LogIgnoredMessage(this, "Message is not valid");
                return;
            }

            //A Peer should not receive this message, if it is errorneously related to a sent request, then process it as a failure response
            ProcessFailureResponse();
            
        }

        public const int Code = 423;

        public const string DefaultMessage = "Locked";

        /// <summary>
        /// Appends the raw response data to a string builder
        /// </summary>
        /// <param name="sb">The StringBuilder to append data to</param>
        /// <param name="Message">The response reason phrase</param>
        /// <param name="ASPNETVersion">The state server version</param>
        /// <param name="ResponseInfo">The session response information</param>
        internal static void AppendResponse(StringBuilder sb, string Message, string ASPNETVersion, ISessionResponseInfo ResponseInfo)
        {
            sb.AppendFormat("{0} {1}\r\nX-AspNet-Version: {2}\r\n", Code.ToString(), Message == string.Empty ? DefaultMessage : Message ?? DefaultMessage, ASPNETVersion);
            sb.AppendFormat("LockDate: {0}\r\nLockAge: {1}\r\nLockCookie: {2}\r\nCache-Control: private\r\n", ResponseInfo.LockDateInTicks, ResponseInfo.LockAgeInSeconds, ResponseInfo.LockCookie);
        }

    }

    /// <summary>
    /// Represents the UnauthorizedResponse message
    /// </summary>
    /// <remarks>
    /// The UnauthorizedResponse message is sent in response to BeginAuthRequest, CompleteAuthRequest or SetTransferRequest messages.
    /// If this message is in response to a BeginAuthRequest, it indicates that the authentication process can proceed.
    /// If this message is in response to a CompleteAuthRequest, it indicates the authentication failed.
    /// If this message is in response to a SetTransferRequest, it indicates that the peer is not accepting the transfer because the transmitting peer is not authenticated.
    /// This message is only transmitted between peers.
    /// </remarks>
    public class UnauthorizedResponse : ServiceResponse
    {

        protected string realm = null;
        protected string qop = null;
        protected string nonce = null;

        /// <summary>
        /// Initializes a new instance of the UnauthorizedResponse class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public UnauthorizedResponse(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
            string www_auth = headers["WWW-AUTHENTICATE"];

            if (www_auth != null)
            {
                //Split comma-delimited directives
                string[] directives = www_auth.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                //first check for and remove 'Digest' from the first line
                if (directives.Length > 0 && directives[0].Trim().ToUpperInvariant().StartsWith("DIGEST"))
                {
                    directives[0] = directives[0].Trim().Substring(6); //remove digest word

                    //Read realm, qop and nonce
                    foreach (string line in directives)
                    {
                        string key, value;
                        GetKeyValue(line, '=', out key, out value);

                        switch(key.ToUpperInvariant().Trim())
                        {
                            case "REALM":
                                realm = Unquote( value).Trim();
                                break;

                            case "QOP":
                                qop = Unquote( value).Trim();
                                break;

                            case "NONCE":                                   
                                nonce = Unquote( value).Trim();
                                if (!IsValidBase64(nonce)) nonce = null;
                                break;
                        }
                            
                    }

                }


            }

            //Validate
            if (!isError)
            {
                //This message requires an empty content-length, qop, nonce and realm
                if (body.Length != 0 || qop == null || nonce == null || realm == null)
                {
                    isError = true;
                }
            }

        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!Validate())
            {
                Diags.LogIgnoredMessage(this, "Message is not valid");
                return;
            }

            //Check if this peer initiated an \AUTH request
            ResponseData[] sentMsgs = socket.SentMessages;
            if (sentMsgs != null && sentMsgs.Length > 0)
            {
                Type lastMsg = sentMsgs[sentMsgs.Length - 1].ResponseType;

                if (lastMsg == typeof(BeginAuthRequest))
                {
                    //Last sent message was a BeginAuthRequest

                    //Check if Async request is still valid
                    if (!service.AsyncRequests.ContainsKey(socket)) return;

                    //then send a Complete \AUTH request

                    string clientNonce = service.Authenticator.GetNewChallenge();
                    string computerName = service.Authenticator.MachineName;
                    string algorithmName = service.Authenticator.HashAlgorithmName;

                    //Send a CompleteAuthRequest 
                    CompleteAuthRequest.Send(nonce, clientNonce,
                        service.Authenticator.GetServerResponseDigest(algorithmName, computerName, realm, nonce, 1, clientNonce, "auth", "\\AUTH"),
                        service.Authenticator.GetClientResponseDigest(algorithmName, computerName, realm, nonce, 1, clientNonce, "auth", "\\AUTH"),
                        service.Authenticator.GetSessionKey(computerName, realm, nonce, clientNonce), computerName,
                        algorithmName, realm, socket);

                    return;
                }
                else if (lastMsg == typeof(CompleteAuthRequest))
                {
                    //Look for the scavenger's reference object for the original BeginAuth/CompleteAuth request
                    //if the object is still valid, then call the method to tell the original request that things didn't go well
                    AsyncResultActions<ServiceSocket> calls;
                    if (service.AsyncRequests.TryGetValue(socket, out calls))
                    {
                        if (service.AsyncRequests.Remove(socket))
                        {
                            Diags.LogPeerAuthenticationFailed("Final Unauthorized response received at UnauthorizedResponse.Process()",socket.RemoteIP);
                            calls.InvokeResult2Action(); //Result2 is the failure result
                            return;
                        }

                        return; //Async operation has already been handled
                    }
                }
                else if (lastMsg == typeof(SetTransferRequest))
                {
                    ProcessFailureResponse();
                    return;
                }

            }

            //I don't know why I'm receiving this

            //abort connection
            socket.Abort();

        }

        public const int Code = 401;

        public const string DefaultMessage = "Unauthorized";

        /// <summary>
        /// Appends the raw response data to a string builder
        /// </summary>
        /// <param name="sb">The StringBuilder to append data to</param>
        /// <param name="Message">The response reason phrase</param>
        /// <param name="ASPNETVersion">The state server version</param>
        /// <param name="Nonce">The nonce field value in the WWW-Authenticate Response Header, according to RFC 2617</param>
        /// <param name="Realm">The realm field value in the WWW-Authenticate Response Header, according to RFC 2617</param>
        /// <param name="HashAlgorithmName">The algorithm field value in the WWW-Authenticate Response Header, according to RFC 2617</param>
        internal static void AppendResponse(StringBuilder sb, string Message, string ASPNETVersion, string Nonce, string Realm, string HashAlgorithmName)
        {
            sb.AppendFormat("{0} {1}\r\nX-AspNet-Version: {2}\r\n", Code.ToString(), Message == string.Empty ? DefaultMessage : Message ?? DefaultMessage, ASPNETVersion);
            sb.AppendFormat("WWW-Authenticate: Digest realm=\"{0}\", qop=\"auth\", nonce=\"{1}\", algorithm=\"{2}\"\r\n", Realm, Nonce, HashAlgorithmName );

        }




    }

    /// <summary>
    /// Represents the PreconditionFailedResponse message.
    /// </summary>
    /// <remarks>
    /// The PreconditionFailedResponse message is sent by a peer in response to a SetTransferMessage
    /// if the peer already has the transferred resource and so cannot accept the transfer.
    /// This message is only transmitted between peers.
    /// </remarks>
    public class PreconditionFailedResponse : ServiceResponse
    {
        /// <summary>
        /// Initializes a new instance of the PreconditionFailedResponse class
        /// </summary>
        /// <param name="Data">The HTTPPartialData class to load this instance from</param>
        /// <param name="Service">State server instance</param>
        public PreconditionFailedResponse(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
            //Validate
            if (!isError)
            {
                //This message requires an empty content length
                if (body.Length != 0)
                {
                    isError = true;
                }
            }

        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!Validate())
            {
                Diags.LogIgnoredMessage(this, "Message is not valid");
                return;
            }

            
            //Check if this socket sent a SETTRANSFER request
            ResponseData[] sentMsgs = socket.SentMessages;
            if (sentMsgs != null && sentMsgs.Length > 0)
            {
                Type lastMsgType = sentMsgs[sentMsgs.Length - 1].ResponseType;
                if ( lastMsgType == typeof(SetTransferRequest))
                {
                    //Remove reference object for this request from scavenger's list
                    AsyncResultActions<ServiceSocket> calls;
                    if (service.AsyncRequests.TryGetValue(socket, out calls))
                    {
                        if (service.AsyncRequests.Remove(socket))
                        {
                            //Call the 'transfer-already-exists' method for the original request that initiated the transfer
                            calls.InvokeResult3Action(); //Result3 is the Already Exiting action
                            return;
                        }
                    }

                    return; //Another method has handled this async operation

                }
                else if (lastMsgType == typeof(BeginAuthRequest) || lastMsgType == typeof(CompleteAuthRequest))
                {
                    ProcessFailureResponse();
                    return;
                }
            }

            //I have no clue why I'm receiving this
            //Abort connection
            socket.Abort();

        }

        public const int Code = 412;

        public const string DefaultMessage = "Precondition Failed";

        /// <summary>
        /// Appends the raw response data to a string builder
        /// </summary>
        /// <param name="sb">The StringBuilder to append data to</param>
        /// <param name="Message">The response reason phrase</param>
        /// <param name="ASPNETVersion">The state server version</param>
        internal static void AppendResponse(StringBuilder sb, string Message, string ASPNETVersion)
        {
            sb.AppendFormat("{0} {1}\r\nX-AspNet-Version: {2}\r\nCache-Control: private\r\n", Code.ToString(), Message == string.Empty ? DefaultMessage : Message ?? DefaultMessage, ASPNETVersion);
        }

    }

    /// <summary>
    /// Represents the ServiceUnavailableResponse message sent by a peer when it's shutting down
    /// </summary>
    /// <remarks>
    /// The ServiceUnavailableResponse message is sent by a peer in response to a SetTransferMessage 
    /// if the peer is shutting down and cannot accept the transfer.
    /// This message is only transmitted between peers.
    /// </remarks>
    public class ServiceUnavailableResponse : ServiceResponse
    {
        /// <summary>
        /// Initializes a new instance of the ServiceUnavailableResponse class
        /// </summary>
        /// <param name="Data">The HTTPPartialData to create object from</param>
        /// <param name="Service">State server instance</param>
        public ServiceUnavailableResponse(HTTPPartialData Data, StateServer Service)
            : base(Data, Service)
        {
            //Validate
            if (!isError)
            {
                //This message requires an empty content length
                if (body.Length != 0)
                {
                    isError = true;
                }
            }

        }

        /// <summary>
        /// Process the message
        /// </summary>
        public override void Process()
        {
            if (!Validate())
            {
                Diags.LogIgnoredMessage(this, "Message is not valid");
                return;
            }

            //Check if this socket sent a SETTRANSFER request
            ResponseData[] sentMsgs = socket.SentMessages;
            if (sentMsgs != null && sentMsgs.Length > 0)
            {
                Type lastMsgType = sentMsgs[sentMsgs.Length - 1].ResponseType;
                if (lastMsgType == typeof(SetTransferRequest))
                {
                    //Remove reference object for this request from scavenger's list
                    AsyncResultActions<ServiceSocket> calls;
                    if (service.AsyncRequests.TryGetValue(socket, out calls))
                    {
                        if (service.AsyncRequests.Remove(socket))
                        {
                            //Call the 'peer-is-shutting-down' method for the original request that initiated the transfer
                            calls.InvokeResult4Action(); //Result4 is the Peer is shutting down action
                            return;
                        }
                    }

                    return; //Another method has handled this async operation

                }
                else if (lastMsgType == typeof(BeginAuthRequest) || lastMsgType == typeof(CompleteAuthRequest))
                {
                    ProcessFailureResponse();
                    return;
                }
            }

            //I have no clue why I'm receiving this
            //Abort connection
            socket.Abort();

        }

        public const int Code = 503;

        public const string DefaultMessage = "Service Unavailable";

        /// <summary>
        /// Appends the raw response data to a string builder
        /// </summary>
        /// <param name="sb">The StringBuilder to append data to</param>
        /// <param name="Message">The response reason phrase</param>
        /// <param name="ASPNETVersion">The state server version</param>
        internal static void AppendResponse(StringBuilder sb, string Message, string ASPNETVersion)
        {
            sb.AppendFormat("{0} {1}\r\nX-AspNet-Version: {2}\r\nCache-Control: private\r\n", Code.ToString(), Message == string.Empty ? DefaultMessage : Message ?? DefaultMessage, ASPNETVersion);
        }

    }

    /// <summary>
    /// Represents a parser for the first line of a HTTP request or response.
    /// </summary>
    /// <remarks>
    /// The HTTPMethod class parses the first line of a HTTP request or response and provides properties for the parsed components.
    /// </remarks>
    /// <param name="Line"></param>
    public class HTTPMethod
    {

        /// <summary>
        /// The message request method if the message is a request
        /// </summary>
        public RequestMethods RequestMethod;

        /// <summary>
        /// The message response code if the message is a response
        /// </summary>
        public int ResponseCode;

        /// <summary>
        /// The resource URI of the message
        /// </summary>
        public string Resource;

        /// <summary>
        /// The determined Type of the message
        /// </summary>
        public HTTPMessageType Type;

        /// <summary>
        /// Initializes a new instance of the HTTPMethod class
        /// </summary>
        /// <param name="Line">the line to parse</param>
        public HTTPMethod(string Line)
        {
            if (Line == null)
            {
                //Not good
                throw new ArgumentNullException("Line");
            }

            //Parse line
            Line = Line.Trim();
            string[] words = Line.Split(new char[] { ' ' }, StringSplitOptions.None);

            if (words.Length > 0)
            {
                switch (words[0].ToUpperInvariant())
                {
                    case "GET":
                        RequestMethod = RequestMethods.Get;
                        Type = HTTPMessageType.Request;
                        break;
                    case "PUT":
                        RequestMethod = RequestMethods.Put;
                        Type = HTTPMessageType.Request;
                        break;
                    case "DELETE":
                        RequestMethod = RequestMethods.Delete;
                        Type = HTTPMessageType.Request;
                        break;
                    case "HEAD":
                        RequestMethod = RequestMethods.Head;
                        Type = HTTPMessageType.Request;
                        break;
                    default:
                        RequestMethod = RequestMethods.Unknown;

                        int res;
                        if (int.TryParse(words[0], out res) ||
                            (words.Length > 1 && (words[0] == "HTTP/1.0" || words[0] == "HTTP/1.1") && int.TryParse(words[1], out res))
                            )
                        {
                            ResponseCode = res;
                            Type = HTTPMessageType.Response;
                        }

                        break;
                }


                if (words.Length > 2 && words[words.Length - 1] == "HTTP/1.1")
                {
                    Resource = string.Join(" ", words, 1, words.Length - 2).Trim();

                }
                else if (words.Length > 2 || (words[words.Length - 1] != "HTTP/1.1" && words.Length > 1))
                {
                    Resource = string.Join(" ", words, 1, words.Length - 1).Trim();
                }
                else
                {
                    Resource = string.Empty;
                }

            }
            else
            {
                throw new ArgumentException("Empty Line", "Line");
            }
        }

        /// <summary>
        /// Types of accepted HTTP Request methods
        /// </summary>
        public enum RequestMethods
        {
            Unknown = 0, //Unknown HTTP header
            Get, //GET HTTP header
            Put, //PUT HTTP header
            Delete, //DELETE HTTP header
            Head //HEAD HTTP header

        }
    }

    /// <summary>
    /// Represents a structure where partial HTTP data can accumulate as it is transmitted until transmission is complete.
    /// </summary>
    /// <remarks>
    /// The HTTPPartialData class holds HTTP data as it is transmitted. It verifies the transmitted data is valid HTTP and provides properties to signal the message was completely received or to signal an error.
    /// </remarks>
    public class HTTPPartialData
    {

        //Max data to receive at a time
        const int BufferSize = 16384;

        //Max number of bytes in a line
        const int MaxLineLength = 2048;

        //Max number of lines
        const int MaxLines = 40;

        //Max content Length
        const int MaxContentLength = 20971520; //Roughly 20 megs

        const string ContentLengthHeader = "CONTENT-LENGTH:";

        ServiceSocket handler; //Socket receiving data  

        List<byte[]> lines; // List of HTTP lines
        byte[] buffer; // Buffer where socket stores data
        byte[] content; // HTTP content data
        byte[] bufferedLine; // Line where data is appended before moved to list
        int totalLength; //total length of received information
        int? contentLength; //HTTP content-length header info
        int bufferPos; //the position where data was last stored in bufferedLine or content
        bool isError; //indicates there is a data error
        bool isComplete; //indicates that transmission is complete
        bool contentlengthMode; //indicates that content data is expected

        //TODO: FEATURE: PIPELINING: Add a new feature for pipelining called "RemainingData","FalloverData","NextMessagePrefix" or something similar to report data to Prefix the next message on this socket

        /// <summary>
        /// Initializes a new instance of the HTTPPartialData class
        /// </summary>
        /// <param name="HandlerSocket">The associated socket</param>
        public HTTPPartialData(ServiceSocket HandlerSocket)
        {
            handler = HandlerSocket;

            lines = new List<byte[]>();
            buffer = new byte[BufferSize];
            content = null;
            bufferedLine = new byte[MaxLineLength];
            totalLength = 0;
            contentLength = null;
            bufferPos = -1;
            isError = false;
            isComplete = false;
            contentlengthMode = false;
        }

        /// <summary>
        /// Gets the received lines in the HTTP data
        /// </summary>
        public byte[][] Lines
        {
            get { return lines.ToArray(); }
        }

        /// <summary>
        /// Gets the received content (message body) of the HTTP data
        /// </summary>
        public byte[] Content
        {
            get { return content; }
        }

        /// <summary>
        /// Gets or sets the buffer where transmitted data is stored
        /// </summary>
        public byte[] Buffer
        {
            get { return buffer; }
            set { buffer = value; }
        }

        /// <summary>
        /// Gets a value indicating whether the HTTP data is a complete message
        /// </summary>
        public bool IsComplete
        {
            get
            {
                return isComplete;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the HTTP data has an error
        /// </summary>
        public bool IsError
        {
            get { return isError; }
        }

        /// <summary>
        /// Gets the ServiceSocket transmitting the HTTP data
        /// </summary>
        public ServiceSocket HandlerSocket
        {
            get { return handler; }
        }

        /// <summary>
        /// Reads data from the receive buffer and fills the partial data object with the read data
        /// </summary>
        /// <param name="DataLength">Length of data to read, in bytes</param>
        public void Append(int DataLength)
        {
            if (DataLength > 0 && !isError && !isComplete)
            {
                totalLength += DataLength;

                for (int i = 0; i < DataLength; i++)
                {

                    bufferPos++;
                    if (!contentlengthMode)
                    {
                        if (bufferPos == MaxLineLength)
                        {
                            //Max length of a line has been reached
                            isError = true;
                            return;
                        }

                        //Copy byte to bufferedData
                        byte b = buffer[i];
                        bufferedLine[bufferPos] = b;

                        //look for CRLF
                        if (b == 10 && i > 0 && buffer[i - 1] == 13)
                        {
                            if (lines.Count == MaxLines)
                            {
                                //Can't have more lines
                                isError = true;
                                return;
                            }

                            byte[] newByteLine = new byte[bufferPos + 1];
                            Array.Copy(bufferedLine, newByteLine, bufferPos + 1);
                            lines.Add(newByteLine);
                            bufferPos = -1; //reset bufferPos;

                            //Convert line to string to check if content-length can be read
                            string line = Encoding.UTF8.GetString(newByteLine).ToUpperInvariant();

                            if (line.StartsWith(ContentLengthHeader))
                            {
                                if (line.Length > ContentLengthHeader.Length)
                                {
                                    int len;
                                    if (Int32.TryParse(line.Substring(ContentLengthHeader.Length), out len))
                                    {
                                        contentLength = len;
                                        if (contentLength > MaxContentLength)
                                        {
                                            //Max ContentLength exceeded
                                            isError = true;
                                            return;
                                        }

                                        content = new byte[contentLength.Value]; //initialize array

                                    }
                                }

                            }

                            // Is this a double new line?
                            if (newByteLine.Length == 2 && lines.Count > 1)
                            {
                                //2 or more lines and empty new line signals end of a request or to expect content
                                if (contentLength == null || contentLength == 0)
                                {
                                    //TODO: FEATURE: PIPELINING: Check if there is remaining data to be reported for pipelining
                                    isComplete = true;
                                    return;
                                }

                                bufferPos = -1;
                                contentlengthMode = true;
                            }

                        }
                    }
                    else
                    {
                        //Data is longer than contentlength
                        if (DataLength + bufferPos - i > contentLength)
                        {
                            //TODO: FEATURE: PIPELINING: This shouldn't be an error after pipelining is implemented
                            isError = true;
                            return;
                        }

                        //Copy the data
                        //TODO: FEATURE: PIPELINING: For pipelining, copy only up to conent-Length , not the entire data
                        Array.Copy(buffer, i, content, bufferPos, DataLength - i);
                        bufferPos += DataLength - (i + 1);

                        if (bufferPos == contentLength - 1)
                        {
                            //TODO: FEATURE: PIPELINING: Check if there is remaining data to be reported for pipelining

                            //Content is complete
                            isComplete = true;
                            return;
                        }

                        //leave loop
                        break;

                    }


                }


            }


        }



    }


    /// <summary>
    /// Types of HTTP messages
    /// </summary>
    public enum HTTPMessageType
    {
        Unknown = 0,
        Request,
        Response
    }


}
