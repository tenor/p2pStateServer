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
using System.Text;
using System.Diagnostics;
using System.Threading;

namespace P2PStateServer
{
    /// <summary>
    /// Provides methods and properties for tracking messages, errors, processing time, deadlocks and other issues that may occur in the state server
    /// </summary>
    class Diags
    {

        [ThreadStatic]
        static int deadlockCounter;

        [ThreadStatic]
        static bool deadlocked;

        [Conditional("DEBUG")]
        static public void ResetDeadLockCounter()
        {            
            deadlockCounter = 0;

            if (deadlocked)
            {
                deadlocked = false;

                Debug.WriteLine("[" + DateTime.Now.ToString("T") + "] " + string.Format("DeadLock freed at Thread {0}. StackTrace: {1}\n", Thread.CurrentThread.ManagedThreadId, new StackTrace().ToString()), "THREADING");
            }
        }

        [Conditional("DEBUG")]
        static public void DetectDeadLock(object Object, int Iterations)
        {
            if (deadlocked) return;

            deadlockCounter++;
            if (deadlockCounter >= Iterations)
            {
                deadlocked = true;

                Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("DeadLock detected at Thread {0} on Object {1} after {2} iterations. StackTrace: {3}\n", Thread.CurrentThread.ManagedThreadId, Object.ToString(), deadlockCounter, new StackTrace().ToString()), "THREADING");

                //reset deadLock counter
                deadlockCounter = 0;
            }
        }

        [Conditional("DEBUG")]
        static public void LogSocketException(Exception ex)
        {
            System.Net.Sockets.SocketException socketEx = ex as System.Net.Sockets.SocketException;

            if(socketEx == null)
            {
                //Not a socket exception
                Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Exception: {0} occured at {1}\n", ex.Message, ex.StackTrace),"SOCKETS");  
            }
            else
            {
                Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Socket Exception: Code {0}, Message {1} occured at {2}\n", socketEx.ErrorCode, socketEx.Message, socketEx.StackTrace), "SOCKETS");  
            }
        }

        [Conditional("DEBUG")]
        static public void TagMessage(ServiceMessage Msg)
        {
            Msg.Tag = new Tag();            
            ((Tag)Msg.Tag).Timer.Start(); //Start the timer on this message            
        }

        [Conditional("DEBUG")]
        public static void Assert(bool Condition, string Message, string DetailMessage)
        {
            Debug.Assert(Condition, Message, DetailMessage);
        }


        [Conditional("DEBUG")]
        public static void Fail(string Message)
        {
            Debug.Fail(Message);
        }

        [Conditional("VERBOSE")]
        static public void LogNewMessage(ServiceMessage Msg)
        {
            if (Msg is ServiceRequest || Msg is GetTransferMessage)
            {
                Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Received {0} Message ID {1} for resource {2} from {3}\n", Msg.GetType().Name, Msg.Tag, Msg.Resource, Msg.Source), "MESSAGING");
            }
            else
            {
                Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Received {0} Message ID {1} from {2}\n", Msg.GetType().Name, Msg.Tag, Msg.Source), "MESSAGING");
            }
            
        }

        [Conditional("DEBUG")]
        static public void LogMessageError(ServiceMessage Msg, Exception ex)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Error processing {0} Message ID {1} for resource {2}. Error Message {3} occured at {4}\n", Msg.GetType().Name, Msg.Tag, Msg.Resource, ex.Message, ex.StackTrace), "MESSAGING");
        }

        [Conditional("DEBUG")]
        static public void LogApplicationError(string Error, Exception ex)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Application error: {0} . Error Message {1} occured at {2}\n", Error, ex.Message, ex.StackTrace), "SERVER");
        }

        [Conditional("DEBUG")]
        static public void LogMessageContentCipherError(ServiceMessage Msg, Exception ex)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Error decrypting content of {0} Message ID {1} for resource {2}. Error Message {3} occured at {4}\n", Msg.GetType().Name, Msg.Tag, Msg.Resource, ex.Message, ex.StackTrace), "MESSAGING");
        }

        [Conditional("DEBUG")]
        static public void LogMessageUnprotectedError(ServiceMessage Msg)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Error: Unencrypted message content from {0} Message ID {1} for resource {2} -- expected encrypted message \n", Msg.GetType().Name, Msg.Tag, Msg.Resource), "MESSAGING");
        }

        [Conditional("DEBUG")]
        static public void LogMessageProtectedError(ServiceMessage Msg)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Error: Encrypted message content from {0} Message ID {1} for resource {2} -- expected unencrypted message \n", Msg.GetType().Name, Msg.Tag, Msg.Resource), "MESSAGING");
        }

        [Conditional("VERBOSE")]
        static public void LogReply(ServiceMessage Msg, ResponseData Response)
        {
            Stopwatch timer = ((Tag)Msg.Tag).Timer;
            timer.Stop();
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Replied Message {0} with {1} . Processed in {2} ms \n", Msg.Tag, Response.ResponseType.Name, timer.ElapsedMilliseconds ), "MESSAGING");
        }

        [Conditional("VERBOSE")]
        static public void LogIgnoredMessage(ServiceMessage Msg, string Reason)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Ignored Message {0}. Reason: {1}\n", Msg.Tag, Reason), "MESSAGING");
        }

        [Conditional("VERBOSE")]
        static public void LogSend(ServiceSocket socket, ResponseData Response)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Sent {0} to {1}\n", Response.ResponseType.Name, socket.RemoteIP), "MESSAGING");
        }

        [Conditional("VERBOSE")]
        static public void LogNewWebServerConnection(System.Net.Sockets.Socket socket)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Incoming web server connection from {0}\n", socket.RemoteEndPoint.ToString()), "SOCKETS");
        }

        [Conditional("VERBOSE")]
        static public void LogNewPeerConnection(System.Net.Sockets.Socket socket)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Incoming peer connection from {0}\n", socket.RemoteEndPoint.ToString()), "SOCKETS");
        }

        [Conditional("VERBOSE")]
        static public void LogNewSession(string key, ISessionObject Session)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Stored new session data for key {0} , length: {1} bytes \n", key,Session.Data.Length), "SESSION_DICT");
        }

        [Conditional("VERBOSE")]
        static public void LogUpdatedSession(string key, ISessionObject Session)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Updated session data for key {0} , length: {1} bytes \n", key, Session.Data.Length), "SESSION_DICT");
        }

        [Conditional("VERBOSE")]
        static public void LogSessionNotFound(string key)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Session not found for key {0} \n", key), "SESSION_DICT");
        }

        [Conditional("VERBOSE")]
        static public void LogSessionAlreadyExists(string key)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Session already exists for key {0} \n", key), "SESSION_DICT");
        }

        [Conditional("VERBOSE")]
        static public void LogSessionIsLocked(string key)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Session is locked for key {0} \n", key), "SESSION_DICT");
        }

        [Conditional("VERBOSE")]
        static public void LogSessionRead(string key, ISessionObject Session)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Session read for key {0}, length: {1} bytes \n", key, Session.Data.Length), "SESSION_DICT");
        }

        [Conditional("VERBOSE")]
        static public void LogSessionExporting(string key, ISessionObject Session)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Export started for session key {0}, length: {1} bytes \n", key, Session.Data.Length), "SESSION_DICT");
        }

        [Conditional("VERBOSE")]
        static public void LogSessionExported(string key)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Export completed for session key {0} \n", key), "SESSION_DICT");
        }

        [Conditional("VERBOSE")]
        static public void LogSessionDeleted(string key)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Session deleted for key {0} \n", key), "SESSION_DICT");
        }

        [Conditional("VERBOSE")]
        static public void LogSessionExpired(string key)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Session expired for key {0} \n", key), "SESSION_DICT");
        }

        [Conditional("DEBUG")]
        static public void LogConnectingPeer(string Peer)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Connecting Peer {0}\n", Peer), "P2P");
        }

        [Conditional("VERBOSE")]
        static public void LogConnectingSessionTransferPeer(string Peer)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Connecting session transfer Peer {0}\n", Peer), "P2P");
        }

        [Conditional("DEBUG")]
        static public void LogErrorConnectingPeer()
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Error Connecting Peer\n"), "P2P");
        }

        [Conditional("DEBUG")]
        static public void LogPeerAuthenticationFailed(string Reason, string Peer)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Error Authenticating Peer {1}. Reason:{0} \n",Reason, Peer), "P2P");
        }


        [Conditional("VERBOSE")]
        static public void LogDisconnectingPeer(string Peer)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Disconnecting Peer {0} \n", Peer), "P2P");
        }


        [Conditional("VERBOSE")]
        static public void LogDisconnectingSocket(string Socket, bool IsFromPeer, string Reason)
        {
            string socketType = IsFromPeer == true ? "Peer" : "Web server";
            Debug.WriteLine("[" + DateTime.Now.ToString("T") + "] " + string.Format("Disconnecting Socket {0}. Type: {1}. Reason: {2}\n", Socket, socketType, Reason), "SERVER");
        }

        [Conditional("VERBOSE")]
        static public void LogTransferringSession(string Resource, string Peer)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Transferring session {0} to Peer {1} \n", Resource, Peer), "P2P");
        }

        [Conditional("VERBOSE")]
        static public void LogQueryingNetwork(string Resource)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Querying network for resource {0} \n", Resource), "P2P");
        }

        [Conditional("VERBOSE")]
        static public void LogNetworkQueryTimeout(string Resource)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Network query timed out for resource {0} \n", Resource), "P2P");
        }

        [Conditional("VERBOSE")]
        static public void LogForwardingNetworkQuery(string Resource)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Forwarding network query for resource {0} \n", Resource), "P2P");
        }

        [Conditional("VERBOSE")]
        static public void LogRebroadcastingNetworkQuery(string Resource)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Rebroadcasting network query for resource {0} \n", Resource), "P2P");
        }

        [Conditional("VERBOSE")]
        static public void LogNetworkTransferredResource(string Resource)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Resource {0} was transferred from the network \n", Resource), "P2P");
        }

        [Conditional("VERBOSE")]
        static public void LogTransferSuccess(string Resource)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Session {0} transferred successfully \n", Resource), "P2P");
        }

        [Conditional("DEBUG")]
        static public void LogTransferFailed(string Resource, string Reason)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Session {0} transfer failed : {1} \n", Resource, Reason), "P2P");
        }

        [Conditional("DEBUG")]
        static public void LogContentionDetected(string Resource, string Activity)
        {
            Debug.WriteLine( "[" + DateTime.Now.ToString("T") + "] " + string.Format("Contention detected for session {0}: {1} \n", Resource, Activity), "SERVER");
        }

        [Conditional("VERBOSE")]
        static public void LogShuttingdownMessage()
        {
            Debug.WriteLine("[" + DateTime.Now.ToString("T") + "] " + string.Format("SHUTTING DOWN SERVER ... \n"), "SERVER");
        }

        /// <summary>
        /// Represents a tag used for tracking a message for diagnostic purposes
        /// </summary>
        public class Tag
        {
            static ulong idCounter;

            readonly ulong id;

            /// <summary>
            /// Gets the integral tag identifier
            /// </summary>
            public ulong ID
            {
                get
                {
                    return id;
                }
            }                    

            public Stopwatch Timer = new Stopwatch();

            /// <summary>
            /// Gets a string representation of the tag identifier
            /// </summary>
            /// <returns>string identifier</returns>
            public override string ToString()
            {
                return id.ToString("X");
            }

            public Tag()
            {
                unchecked
                {
                    idCounter++;
                }

                id = idCounter; 

            }


        }

    }
}
