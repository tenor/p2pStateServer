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
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;

namespace P2PStateServer
{

    /// <summary>
    /// Represents an exception-safe wrapper of the .NET socket class.
    /// It exposes asynchronous methods and properties useful for state server soket operations.
    /// </summary>
    /// <remarks>
    /// The .NET Socket class is thread-safe but you can never be too careful. 
    /// This class introduces an extra synchronization layer.
    /// </remarks>
    public class ServiceSocket
    {
        //Max Backlogged connections on listening sockets
        const int MaxConnections = 10000;

        Socket socket; //encapsulated socket
        bool fromPeerListener; //True if socket was spawned from peer port i.e socket conneted to peer port and was then handled
        object syncSocket = new object(); //used to synchronize socket operations
        object syncReferenceTime = new object(); //used to synchronize syncReferenceTime get/sets
        byte[] sessionKey; //Encryption session key
        Guid id; //Socket identifier, used in generating unique hashcodes for socket
        bool isOutbound = false; //True if socket is outbound (i.e connection was initiated by local peer)
        bool isClosing = false; //True if socket is shutting down
        DateTime referenceTime = DateTime.MinValue; //A reference time used by the state server
        Queue<ResponseData> sentMsgs = new Queue<ResponseData>(); //List of recently sent messages

        /// <summary>
        /// Initializes a new instance of the ServiceSocket class.
        /// </summary>
        /// <param name="socket">The .NET Socket object to encapsulate</param>
        /// <param name="IsPeerSocket">Indicates if this socket was spawned from the state server peer port</param>
        public ServiceSocket(Socket socket, bool IsPeerSocket)
        {
            this.socket = socket;
            fromPeerListener = IsPeerSocket;
            sessionKey = null;
            id = Guid.NewGuid();
        }

        /// <summary>
        /// Initializes a new instance of the ServiceSocket class.
        /// </summary>
        /// <param name="IsPeerSocket">Indicates if this socket was spawned from the state server peer port</param>
        public ServiceSocket(bool IsPeerSocket)
            : this(new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp), IsPeerSocket)
        { }

        /// <summary>
        /// Gets a value indicating whether the socket was spawned from the state server peer port.
        /// </summary>
        public bool FromPeerListener
        {
            get { return fromPeerListener; }
        }

        /// <summary>
        /// Gets a value indicating whether the socket is authenticated.
        /// </summary>
        public bool IsAuthenticated
        {
            get { return sessionKey != null; }
        }

        /// <summary>
        /// Gets or sets a time that can be used for any arbitrary purpose.
        /// </summary>
        public DateTime ReferenceTime
        {
            get 
            {
                lock (syncReferenceTime)
                {
                    return referenceTime;
                }
            }
            set 
            {
                lock (syncReferenceTime)
                {
                    referenceTime = value;
                }
            }
        }

        /// <summary>
        /// Gets the local IP address of the socket.
        /// </summary>
        public string LocalIP
        {
            get 
            {
                try
                {
                    return socket.LocalEndPoint.ToString();
                }
                catch
                {
                    return string.Empty;
                }
            }
        }

        /// <summary>
        /// Gets the remote IP address of the socket.
        /// </summary>
        public string RemoteIP
        {
            get 
            {
                try
                {
                    return socket.RemoteEndPoint.ToString();
                }
                catch
                {
                    return string.Empty;
                }
            }
        }

        /// <summary>
        /// Gets a list of recently sent messages on this socket.
        /// </summary>
        public ResponseData[] SentMessages
        {
            get
            {

                lock (syncSocket)
                {
                    return sentMsgs.ToArray();
                }
            }
        }

        /// <summary>
        /// Gets a value indicating whether the socket was still connected as at the last I/O operation.
        /// </summary>
        /// <remarks>
        /// This is a passive way to check if the socket is still connected and may not reflect the true connected state
        /// <seealso cref="CheckConnection"/>
        /// </remarks>
        public bool IsConnected
        {
            get
            {
                try
                {
                    lock (syncSocket)
                    {
                        return socket.Connected;
                    }
                }
                catch(Exception ex)
                {
                    Diags.LogSocketException(ex);
                    return false;
                }
            }
        }


        /// <summary>
        /// Gets or sets the session encryption key used to encrypt and decrypt data over the connection on this socket
        /// </summary>
        public byte[] SessionKey
        {
            get
            {
                return sessionKey;
            }
            set
            {
                sessionKey = value;
            }
        }

        /// <summary>
        /// Listens on a specified port on the machine
        /// </summary>
        /// <param name="Port">Port number</param>
        /// <param name="AcceptCallback">Callback for accepting new connections</param>
        /// <returns>.NET Socket if successful, Null if not</returns>
        public static Socket Listen(int Port, AsyncCallback AcceptCallback)
        {
            Socket listener;
            // Start Listening on Web Server Socket
            IPEndPoint wsEndPoint = new IPEndPoint(IPAddress.Any, Port);
            listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                listener.Bind(wsEndPoint);
                listener.Listen(MaxConnections);
                listener.BeginAccept(AcceptCallback, listener);
            }
            catch (Exception ex)
            {
                Diags.LogSocketException(ex);
                return null;
            }


            return listener;
        }

        /// <summary>
        /// Begins an asynchronous receive
        /// </summary>
        /// <param name="Buffer">Buffer to store received data</param>
        /// <param name="ReadCallBack">Method to call on receiving data</param>
        /// <param name="StateObject">State object to be passed to ReadCallBack</param>
        /// <returns>AsyncResult for the asynchronous operation</returns>
        public IAsyncResult BeginReceive(byte[] Buffer, AsyncCallback ReadCallBack, object StateObject)
        {
            try
            {
                lock (syncSocket)
                {
                    return socket.BeginReceive(Buffer, 0, Buffer.Length, SocketFlags.None, ReadCallBack, StateObject);
                }
            }
            catch (Exception ex)
            {
                Diags.LogSocketException(ex);
                return null;

            }
        }

        /// <summary>
        /// Ends an asynchronous Receive
        /// </summary>
        /// <param name="ar">AsyncResult obtained from BeginReive</param>
        /// <param name="Error">Indicates an error occured while receiving data</param>
        /// <param name="BytesRead">Number of bytes read</param>
        public void EndReceive(IAsyncResult ar, out bool Error, out int BytesRead)
        {
            Error = false;
            BytesRead = 0;
            try
            {
                lock (syncSocket)
                {
                    BytesRead = socket.EndReceive(ar);
                }
            }
            catch (ObjectDisposedException ex)
            {
                if (!isClosing)
                {
                    Diags.LogSocketException(ex);
                }
                Error = true;
            }
            catch (Exception ex)
            {
                Diags.LogSocketException(ex);
                Error = true;
            }
        }

        /// <summary>
        /// Begins an asynchronous Connect
        /// </summary>
        /// <param name="Host">Host to connect to</param>
        /// <param name="Port">Port number to connect to</param>
        /// <param name="ConnectCallBack">Callback to call on connecting</param>
        /// <param name="StateObject">State object to pass to ConnectCallback</param>
        /// <returns>AsyncResult for the asynchronous operation</returns>
        public IAsyncResult BeginConnect(string Host, int Port, AsyncCallback ConnectCallBack, object StateObject)
        {
            try
            {
                lock (syncSocket)
                {
                    return socket.BeginConnect(Host, Port, ConnectCallBack, StateObject);
                }
            }
            catch (Exception ex)
            {
                Diags.LogSocketException(ex);
                return null;

            }
        }

        /// <summary>
        /// Ends an asynchronous Connect
        /// </summary>
        /// <param name="ar">AsyncResult obtained from BeginConnect</param>
        public void EndConnect(IAsyncResult ar)
        {
            try
            {
                lock (syncSocket)
                {
                    isOutbound = true;
                    socket.EndConnect(ar);
                }
            }
            catch (Exception ex)
            {
                Diags.LogSocketException(ex);
            }
        }

        /// <summary>
        /// Closes the socket gracefully
        /// </summary>
        public void Close()
        {

            //TODO: ENHANCEMENT: Seems like the graceful shutdown process in this method is not working well
            //Is it because of the 1 ms timeout? 
            //I see a lot more stale Peer connections than stale web server connections, so it looks like 
            //Thw web server connections are closing better than the peer connections. Investigate this.

            try
            {
                lock (syncSocket)
                {

                    if (socket.Connected)
                    {
                        socket.Shutdown(SocketShutdown.Both);
                    }
                    isClosing = true;
                    socket.Close(1);
                }
            }
            catch (Exception ex)
            {
                Diags.LogSocketException(ex);
            }
        }

        /// <summary>
        /// Terminates a connection
        /// </summary>
        public void Abort()
        {
            try
            {
                lock (syncSocket)
                {
                    if (socket.Connected)
                    {
                        socket.Shutdown(SocketShutdown.Send);
                    }
                    isClosing = true;
                    socket.Close();
                }
            }
            catch (Exception ex)
            {
                Diags.LogSocketException(ex);
            }
        }


        /// <summary>
        /// Sends data via the socket asynchronously
        /// </summary>
        /// <param name="Message">Data to transmit</param>
        public void Send(ResponseData Message)
        {

            //TODO: ENHANCEMENT: Log consecutive bad request response types and use that information to disconnect socket after 3
            try
            {
                lock (syncSocket)
                {
                    if (sentMsgs.Count > 1)
                    {
                        sentMsgs.Dequeue();
                    }
                    sentMsgs.Enqueue(Message);

                    //Log error if .Data is null -- this will help raise a flag if the message is being resent after .ClearData was called
                    Diags.Assert(Message.Data != null, "ASSERTION FAILED: Message Data is null", new System.Diagnostics.StackTrace().ToString());

                    socket.BeginSend(Message.Data, 0, Message.Data.Length, SocketFlags.None, CompleteSend, null);

                    Message.ClearData(); //free some memory

                }
            }
            catch (Exception ex)
            {
                Diags.LogSocketException(ex);
            }


        }


        /// <summary>
        /// Returns a value which indicates whether the socket is still connected.
        /// </summary>
        /// <remarks>
        /// This method actively checks the connection status by sending a zero-sized payload packet
        /// to inbound sockets or calling Socket.Poll for outbound sockets.
        /// </remarks>
        /// <seealso cref="IsConnected"/>
        /// <returns>True if connection is still connected. Otherwise, False</returns>
        public bool CheckConnection()
        {
            //Actively determine if socket is still connected
            if (isOutbound)
            {

                try
                {
                    //Test for disconnection
                    lock (syncSocket)
                    {
                        socket.Send(new byte[1], 0, SocketFlags.None);
                    }
                    return true;
                }
                catch
                {
                    //Do not log this exception
                    return false;
                }

            }
            else
            {
                //check if work (client) socket is disconnected
                try
                {
                    //Test for disconnection
                    bool isDisconnected = false;
                    lock (syncSocket)
                    {
                        isDisconnected = socket.Available == 0 &&
                            socket.Poll(1, SelectMode.SelectRead);
                    }

                    if (isDisconnected)
                    {
                        return false;
                    }
                    return true;
                }
                catch
                {
                    return false;
                }
            }
        }


        /// <summary>
        /// Completes an asynchronous send
        /// </summary>
        /// <param name="ar">AsyncResul obtained from BeginSend</param>
        private void CompleteSend(IAsyncResult ar)
        {            
            // Complete asynchronous send
            try
            {
                if (!socket.Connected)
                {
                    return;
                }
                lock (syncSocket)
                {
                    socket.EndSend(ar);
                }
            }
            catch (Exception ex)
            {
                Diags.LogSocketException(ex);
                return;
            }
        }



        // override object.Equals
        public override bool Equals(object obj)
        {

            if (obj == null || GetType() != obj.GetType())
            {
                return false;
            }

            return base.Equals(obj);

        }

        // override object.GetHashCode
        public override int GetHashCode()
        {
            return id.GetHashCode();
        }




    }

}
