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
using System.Threading;

namespace P2PStateServer
{
    public delegate void SessionReadHandler(ISessionObject Session,object StateObject);

    /// <summary>
    /// Represents a thread-safe session state dictionary.
    /// </summary>
    class SessionDictionary
    {
        //ReaderWriterLock used while accessing dictionary
        #if NET20
            ReaderWriterLock rwl = new ReaderWriterLock();
        #else
            ReaderWriterLockSlim rwl = new ReaderWriterLockSlim();
        #endif

         //This stores a list of all sessions sorted by expiration date -- very helpful to the session expiry scavenger.
        DateSortedDictionary<string,string> expiryList = new DateSortedDictionary<string, string>();

        const int DeadLockIterationCount = 2000; //Number of iterations to count before declaring a deadlock

        private Dictionary<string, ISessionObject> dict = new Dictionary<string, ISessionObject>();

        /// <summary>
        /// Adds a session into the dictionary
        /// </summary>
        /// <param name="Key">Session Key</param>
        /// <param name="Session">Session object</param>
        /// <param name="UpdateIfNotFound">Indicates whether session should be updated if the session was not found. If set to flase, this gives the caller a chance to query the network before trying again</param>
        /// <param name="LockedSessionInfo">Locked session information if session is locked</param>
        /// <returns>Result of Action</returns>
        public SessionActionResult Add(string Key, ISessionObject Session,bool UpdateIfNotFound, out SessionResponseInfo LockedSessionInfo)
        {

            //If an item with key already exists, return SessionActionResult.AlreadyExists
            //else add the item and return SessionActionResult.OK
            //Calls UpSert internally

            return UpSert(Key, Session, true, UpdateIfNotFound, out LockedSessionInfo); //Insert Item if it doesn't exist
        }


        /// <summary>
        /// Updates a session (adds a new one if it was not found)
        /// </summary>
        /// <param name="Key">Session Key</param>
        /// <param name="Session">Session object</param>
        /// <param name="UpdateIfNotFound">Indicates whether session should be updated if the session was not found. If set to flase, this gives the caller a chance to query the network before trying again</param>
        /// <param name="LockedSessionInfo">Locked session information if session is locked</param>
        /// <returns>Result of Action</returns>
        public SessionActionResult Update(string Key, ISessionObject Session, bool UpdateIfNotFound, out SessionResponseInfo LockedSessionInfo)
        {

            //If the item is locked and the new items lockCookie does not match, return SessionActionResult.Locked
            //else add the item and return SessionActionResult.OK
            //Calls UpSert internally

            return UpSert(Key, Session, false, UpdateIfNotFound, out LockedSessionInfo); //Insert or Update item
        }


        /// <summary>
        /// Updates or inserts a session in the dictionary
        /// </summary>
        /// <param name="Key">Session Key</param>
        /// <param name="Session">Session object</param>
        /// <param name="InsertOnly">Indicates that session should only be inserted if it does not already exist</param>
        /// <param name="UpdateIfNotFound">Indicates whether session should be updated if the session was not found. If set to flase, this gives the caller a chance to query the network before trying again </param>
        /// <param name="LockedSessionInfo">Locked session information if session is locked</param>
        /// <returns>Result of Action</returns>
        private SessionActionResult UpSert(string Key, ISessionObject Session, bool InsertOnly, bool UpdateIfNotFound, out SessionResponseInfo LockedSessionInfo)
        {

            // Look for the session using a reader lock. 
            // If session is not found, switch to a writer lock and insert item.
            // If session is found:
            // Perform an atomic compare exchange on the variable 'InUse'
            // If session is in Use, try Upsert again from the start.
            // If session is not in Use, Perform UpSert and reset InUse
            // Also update Sorted session list

            if(Key == null) throw new ArgumentNullException("Key");
            if(Session == null) throw new ArgumentNullException("Session");

            LockedSessionInfo = null;
            bool tryAgain;

            Diags.ResetDeadLockCounter();
            do
            {
                tryAgain = false;
                AcquireReadLock();
                ISessionObject entry;
                try
                {
                    dict.TryGetValue(Key, out entry);
                }
                finally
                {
                    ReleaseReadLock();
                }

                if (entry == null)
                {
                    if (!UpdateIfNotFound)
                    {
                        return SessionActionResult.NotFound;
                    }
                    
                    //Session not found -- insert brand new session object
                    AcquireWriteLock();
                    try
                    {
                        //Check again to be sure now that the write-lock has been obtained
                        dict.TryGetValue(Key, out entry);
                        if (entry != null)
                        {
                            //ooops -- another thread inserted a seesion with this key while this thread was trying to obtain the write-lock
                            //so try again
                            tryAgain = true;
                            continue;
                        }

                        Session.LockCookie = 1; //For some reason Lockcookie starts counting from 2 -- so set it to 1 now so that it increments to 2 when sought
                        dict[Key] = Session;
                        expiryList.Add(DateTime.UtcNow.Add(new TimeSpan(0, Session.TimeOut,0)) , Key, Key);
                        Diags.LogNewSession(Key, Session);
                    }
                    finally
                    {
                        ReleaseWriteLock();
                    }


                }
                else
                {
                    //Session Found

                    if (InsertOnly)
                    {
                        Diags.LogSessionAlreadyExists(Key);
                        return SessionActionResult.AlreadyExists; //Do not perform an update if InsertOnly is requested
                    }

                    //There is no need to acquire a write lock here since the dictionary is not been modified. 
                    //Only the dictionary entry itself is been updated and such updates are guaranteed to be atomic 
                    //if the atomic InUse property is set.

                    if (entry.CompareExchangeIsInUse(true, false) == false)
                    {
                        //the InUse flag is set, so this code section has exclusive access to this session object
                        try
                        {
                            if (entry.IsLocked)
                            {
                                if (!entry.UnLock(Session.LockCookie ))
                                {
                                    //Lockcookie did not match
                                    LockedSessionInfo = (SessionResponseInfo) entry.CreateResponseInfo();
                                    Diags.LogSessionIsLocked(Key);
                                    return SessionActionResult.Locked;
                                }
                            }

                            Session.LockCookie = entry.LockCookie; //Overwrite the incoming session's lock-cookie with the internal one's so as not to let external input change the lockcookie 
                            Session.ExtraFlags = -1; //disable extra flags since an update is being performed

                            entry.CopyFrom(Session); //Copy all information from Session to entry
                            expiryList.Add(DateTime.UtcNow.Add(new TimeSpan(0, Session.TimeOut, 0)), Key, Key); //reset expiry timeout
                            Diags.LogUpdatedSession(Key, Session);
                        }
                        finally
                        {
                            entry.CompareExchangeIsInUse(false, true);
                        }

                    }
                    else
                    {
                        //Is this entry being exported?
                        if (entry.IsExporting)
                        {
                            //This session is already been exported so leave
                            Diags.ResetDeadLockCounter();
                            return SessionActionResult.Exporting;
                        }


                        //Another thread is using this session and will be done soon so try again
                        
                        Thread.Sleep(1); //pause for 1 ms
                        tryAgain = true;

                    }
                }

                Diags.DetectDeadLock(Key, DeadLockIterationCount); //Signal a deadlock after 2000 iterations

            } while (tryAgain);

            Diags.ResetDeadLockCounter(); //Signal deadlock was freed

            return SessionActionResult.OK;
        }

        /// <summary>
        /// Removes a session from the dictionary
        /// </summary>
        /// <param name="Key">Session Key</param>
        /// <param name="LockCookie">Lock Cookie (used to unlock item if it's locked)</param>
        /// <param name="LockedSessionInfo">Locked session information if session is locked</param>
        /// <returns>Result of Action</returns>
        public SessionActionResult Remove(string Key, uint LockCookie, out SessionResponseInfo LockedSessionInfo)
        {
            // Look for the session using a reader lock. 
            // If session is not found, return false;
            // If session is found:
            // Perform an atomic compare exchange on the variable 'InUse'
            // if session is in Use, try Delete again from the start.
            // if session is not In Use, Perform Delete

            return Remove(Key, LockCookie, false, DateTime.MinValue, out LockedSessionInfo);
        }

        /// <summary>
        /// Remove a session item because it has expired
        /// </summary>
        /// <param name="Key">Session Key</param>
        /// <param name="ExpiryDate">session Expiry date</param>
        /// <returns>Result of Action</returns>
        private SessionActionResult Expire(string Key, DateTime ExpiryDate)
        {
            SessionResponseInfo sessInfo;
            return Remove(Key, 0, true, ExpiryDate, out sessInfo) ;
        }

        /// <summary>
        /// Removes a session from the dictionary
        /// </summary>
        /// <param name="Key">Session Key</param>
        /// <param name="LockCookie">Lock Cookie</param>
        /// <param name="IsExpiring">Indicates that the item is being removed because it's expiring</param>
        /// <param name="ExpiryDate">The Item expiry date (for comparison)</param>
        /// <param name="LockedSessionInfo">Locked session information if session is locked</param>
        /// <returns>Result of Action</returns>
        private SessionActionResult Remove(string Key, uint LockCookie, bool IsExpiring, DateTime ExpiryDate ,out SessionResponseInfo LockedSessionInfo)
        {
            if (Key == null) throw new ArgumentNullException("Key");
            LockedSessionInfo = null;

            bool tryAgain;

            Diags.ResetDeadLockCounter();

            do
            {
                tryAgain = false;
                AcquireReadLock();
                ISessionObject entry;
                try
                {
                    dict.TryGetValue(Key, out entry);
                }
                finally
                {
                    ReleaseReadLock();
                }

                if (entry == null)
                {
                    //Session not found
                    Diags.LogSessionNotFound(Key);
                    return SessionActionResult.NotFound;
                }
                else
                {
                    //Session Found
                    if (entry.CompareExchangeIsInUse(true, false) == false)
                    {
                        try
                        {
                            //The InUse flag is set and so this code section has exclusive access to this session object
                            AcquireWriteLock();

                            try
                            {

                                //Check again to be sure, now that the write-lock has been obtained
                                ISessionObject oldEntry = entry;
                                if (!dict.TryGetValue(Key, out entry))
                                {
                                    //ooops -- another thread deleted the session from the dictionary while this thread 
                                    //was either trying to do the compareExchange (or if buggy, while obtaining the write-lock)
                                    //so try again
                                    oldEntry.CompareExchangeIsInUse(false, true); //unlock the previously locked item
                                    tryAgain = true;
                                    continue;
                                }

                                if (IsExpiring)
                                {
                                    DateTime timeStamp;
                                    if (expiryList.TryGetTimeStamp(Key, out timeStamp))
                                    {
                                        if (timeStamp != ExpiryDate)
                                        {
                                            //The expiration date on this session was updated, so leave
                                            return SessionActionResult.OK;
                                        }
                                    }
                                }

                                if (!IsExpiring && entry.IsLocked) //Locked items DO expire. if not expiring, LockCookie has to match session's 
                                {
                                    if (!entry.UnLock(LockCookie))
                                    {
                                        //Lockcookie did not match
                                        LockedSessionInfo = (SessionResponseInfo)entry.CreateResponseInfo();
                                        Diags.LogSessionIsLocked(Key);
                                        return SessionActionResult.Locked;
                                    }
                                }

                                if (dict.Remove(Key))
                                {
                                    expiryList.Remove(Key);
                                    if (IsExpiring)
                                    {
                                        Diags.LogSessionExpired(Key);
                                    }
                                    else
                                    {
                                        Diags.LogSessionDeleted(Key);
                                    }
                                }
                                else
                                {
                                    //This should never happen
                                    Diags.Fail("ASSERTION Failed -- Session dictionary was unable to remove key\r\n");
                                }

                            }
                            finally
                            {
                                ReleaseWriteLock();

                            }
                        }
                        finally
                        {
                            if (entry != null) entry.CompareExchangeIsInUse(false, true);
                        }
                    }
                    else
                    {
                        //Is this entry being exported?
                        if (entry.IsExporting)
                        {
                            //This session is already been exported so leave
                            Diags.ResetDeadLockCounter();
                            return SessionActionResult.Exporting;
                        }

                        //Another thread is using this session and will be done soon so try again

                        Thread.Sleep(1); //pause for 1 ms
                        tryAgain = true;


                    }

                    Diags.DetectDeadLock(Key, DeadLockIterationCount); //Signal a deadlock after 2000 iterations


                }
            } while (tryAgain);

            Diags.ResetDeadLockCounter(); //Signal deadlock was freed
            return SessionActionResult.OK;

        }


        /// <summary>
        /// Reads a stored session
        /// </summary>
        /// <param name="Key">Session Key</param>
        /// <param name="Reader">Method to call to complete read</param>
        /// <param name="StateObject">State object</param>
        /// <returns>Result of read action</returns>
        public SessionActionResult Read(string Key, SessionReadHandler Reader, object StateObject)
        {

            // Look for session using a reader lock.
            // If session is not found, return false;
            // If session is found:
            // Perform an atomic compare exchange on the variable 'InUse'
            // if session is in Use, try read again from the start.
            // if session is not in use, call delegate and return OK

            return Read(Key, Reader, StateObject, false);

        }

        /// <summary>
        /// Reads a stored session
        /// </summary>
        /// <param name="Key">Session Key</param>
        /// <param name="Reader">Method to call to complete read</param>
        /// <param name="StateObject">State object</param>
        /// <param name="isExporting">Indicates if the session is to be exported</param>
        /// <returns>Result of read action</returns>
        private SessionActionResult Read(string Key, SessionReadHandler Reader, object StateObject, bool isExporting)
        {
            if (Key == null) throw new ArgumentNullException("Key");

            bool tryAgain;
            bool sessionIslocked = false;

            Diags.ResetDeadLockCounter(); //Reset Dead lock counter

            do
            {
                tryAgain = false;
                AcquireReadLock();
                ISessionObject entry;
                try
                {
                    dict.TryGetValue(Key, out entry);
                }
                finally
                {
                    ReleaseReadLock();
                }

                if (entry == null)
                {
                    //Session not found
                    Diags.LogSessionNotFound(Key);
                    return SessionActionResult.NotFound;
                }
                else
                {
                    //Session Found
                    if (entry.CompareExchangeIsInUse(true, false) == false)
                    {
                        //The InUse flag has been set and now this thread has exclusive access to this session object
                        
                        try
                        {

                            //Set IsExporting flag for this entry if item is to be exported
                            if (isExporting)
                            {
                                entry.IsExporting = true;
                            }
  
                            //Call Reader Delegate
                            if(Reader != null) Reader(entry, StateObject);

                            if (isExporting)
                            {
                                Diags.LogSessionExporting(Key, entry); 
                            }
                            else
                            {
                                Diags.LogSessionRead(Key, entry);
                            }
                            sessionIslocked = entry.IsLocked;
                        }
                        finally
                        {
                            if (!isExporting) //Remove inUse property if not exporting
                            {
                                entry.CompareExchangeIsInUse(false, true);
                            }
                        }

                    }
                    else
                    {
                        //Nope, it's still there so check if it's been exported and try again

                        if (entry.IsExporting)
                        {
                            //This session is already been exported so leave
                            Diags.ResetDeadLockCounter();
                            return SessionActionResult.Exporting;
                        }
                        
                        Thread.Sleep(1); //pause for 1 ms
                        tryAgain = true;
                    }

                    Diags.DetectDeadLock(Key, DeadLockIterationCount); //Signal a deadlock after 2000 iterations

                }
            } while (tryAgain);

            Diags.ResetDeadLockCounter(); //Signal deadlock was freed

            if (sessionIslocked && !isExporting )
            {
                Diags.LogSessionIsLocked(Key);
                return SessionActionResult.Locked;
            }
            else
            {
                return SessionActionResult.OK;
            }
        }



        /// <summary>
        /// Begins an external session export
        /// </summary>
        /// <param name="Key">Session key</param>
        /// <param name="Reader">Method to call to kickstart export</param>
        /// <param name="StateObject">State object</param>
        /// <returns>Result of the operation</returns>
        public SessionActionResult BeginExport(string Key, SessionReadHandler Reader, object StateObject)
        {
            // Look for session using a reader lock.
            // If session is not found, return not found;
            // If session is found:
            // Perform an atomic compare exchange on the variable 'InUse'
            // if session is in Use, try read again from the start.
            // if session is not in use, call delegate and return OK response -- do not reset inuse property

            return Read(Key, Reader, StateObject, true);
        }
        

        /// <summary>
        /// Ends an external session export
        /// </summary>
        /// <param name="Key">Session key</param>
        /// <param name="RemoveSession">True to remove session from dictionary</param>
        public void EndExport(string Key, bool RemoveSession)
        {
            //This method resets the inuse property if the isExporting property is true

            if (Key == null) throw new ArgumentNullException("Key");

            AcquireReadLock();
            ISessionObject entry;
            try
            {
                dict.TryGetValue(Key, out entry);
            }
            finally
            {
                ReleaseReadLock();
            }

            if (entry == null)
            {
                //Session not found -- it's okay, don't freak out, session may have expired.
                return; 
            }
            else
            {
                //Session Found
                if (entry.IsInUse) 
                {
                    //The InUse flag, now check the isExporting flag
                    if (!entry.IsExporting)
                    {
                        Exception ex = new InvalidOperationException("EndExport must be called after a call to BeginExport");
                        Diags.LogApplicationError("EndExport must be called after a call to BeginExport -- Entry is InUse but IsExporting is false", ex);
                        throw ex;
                    }

                    try
                    {
                        //Delete session
                        if (RemoveSession)
                        {
                            AcquireWriteLock();
                            try
                            {
                                if (dict.Remove(Key))
                                {
                                    expiryList.Remove(Key);
                                    Diags.LogSessionDeleted(Key);
                                }

                            }
                            finally
                            {
                                ReleaseWriteLock();
                            }
                        }
                    }
                    finally
                    {
                        entry.IsExporting = false;
                        Diags.LogSessionExported(Key);
                        entry.CompareExchangeIsInUse(false, true);
                    }

                }
                else
                {
                    Exception ex = new InvalidOperationException("EndExport must be called after a call to BeginExport");
                    Diags.LogApplicationError("EndExport must be called after a call to BeginExport -- Entry is not in use", ex);
                    throw ex;
                }

            }

        }


        /// <summary>
        /// Gets the list of all keys in the session dictionary
        /// </summary>
        /// <remarks>
        /// This is useful to perform an operation on all keys in the session.
        /// However, this is a static list and the caller should be aware a key may no longer exist when the operation is performed
        /// </remarks>
        public List<string> Keys
        {
            get
            {
                AcquireReadLock();
                try
                {   
                    Dictionary<string, ISessionObject>.KeyCollection keys = dict.Keys;
                    List<string> keyList = new List<string>(keys);
                    return keyList;
                }
                finally
                {
                    ReleaseReadLock();
                }
            }
        }

        /// <summary>
        /// Removes all expired sessions from the dictionary
        /// </summary>
        public void Sweep()
        {
            List<string> keys = expiryList.GetOldKeys(DateTime.UtcNow);

            foreach (string key in keys)
            {
                //Get Timestamp
                DateTime timeStamp;                
                if (expiryList.TryGetTimeStamp(key, out timeStamp))
                {
                    //Make sure new timestamp is expired
                    if (DateTime.UtcNow > timeStamp)
                    {
                        //Expired
                        Expire(key, timeStamp);
                    }
                }
            }

        }

        #region Reader Writer Lock Acquisition/Release

        /// <summary>
        /// Acquires the session dictionary Read Lock
        /// </summary>
        private void AcquireReadLock()
        {
            #if NET20
                rwl.AcquireReaderLock(Timeout.Infinite);
            #else
                rwl.EnterReadLock();
            #endif
        }

        /// <summary>
        /// Releases the session dictionary Read Lock
        /// </summary>
        private void ReleaseReadLock()
        {
            #if NET20
                rwl.ReleaseReaderLock();
            #else
                rwl.ExitReadLock();
            #endif
        }

        /// <summary>
        /// Acquires the Session dictionary Write Lock
        /// </summary>
        private void AcquireWriteLock()
        {
            #if NET20
                rwl.AcquireWriterLock(Timeout.Infinite);
            #else
                rwl.EnterWriteLock();
            #endif
        }

        /// <summary>
        /// Releases the Session Dictionary Write Lock
        /// </summary>
        private void ReleaseWriteLock()
        {
            #if NET20
                rwl.ReleaseWriterLock();
            #else
                rwl.ExitWriteLock();
            #endif
        }

        #endregion

    }

    public enum SessionActionResult
    {
        OK, //Operation was successful
        Locked, //Resource is locked
        NotFound, //resource was not found
        AlreadyExists, //Resource already exists
        Exporting //Resource is being exported 
    }

    /// <summary>
    /// Represents a thread safe dictionary of key-value pairs sorted in place by their time stamps.
    /// </summary>
    /// <typeparam name="TKey">Type of item key</typeparam>
    /// <typeparam name="TValue">Type of item value</typeparam>
    class DateSortedDictionary<TKey, TValue>
    {
        List<TimeTaggedItem<TKey>> list = new List<TimeTaggedItem<TKey>>();
        Dictionary<TKey, TimeTaggedItem<TValue>> dict = new Dictionary<TKey, TimeTaggedItem<TValue>>();
        object sync = new object();

        /// <summary>
        /// Adds or updates an item in the dictionary
        /// </summary>
        /// <param name="TimeStamp">The timestamp to set for the item</param>
        /// <param name="Key">The Item Key</param>
        /// <param name="Value">The Item Value</param>
        public void Add(DateTime TimeStamp, TKey Key, TValue Value)
        {
            lock(sync)
            {
                TimeTaggedItem<TValue> entryValueItem;
                if (dict.TryGetValue(Key, out entryValueItem))
                {
                    //This item exists so update both dictionary and list

                    //First update list
                    //Look for existing item using the found entry
                    int index = BinaryLocate(Key, entryValueItem);

                    //Remove it
                    list.RemoveAt(index);

                    //Reinsert it in the right place in the ordered timestamp list 
                    //1. Look for next largest item in list for the new timestamp
                    TimeTaggedItem<TKey> listItem = new TimeTaggedItem<TKey>(TimeStamp, Key);
                    index = list.BinarySearch(listItem);
                    //2. Insert it there                    
                    list.Insert(index < 0 ? ~index : index, listItem);

                    //Secondly update dictionary with the value
                    dict[Key] = new TimeTaggedItem<TValue>(TimeStamp, Value);

                }
                else
                {
                    //This item does not exist so insert into both dictionary and list

                    //First insert into list
                    //Look for next largest item in list
                    TimeTaggedItem<TKey> listItem = new TimeTaggedItem<TKey>(TimeStamp,Key);
                    int index = list.BinarySearch(listItem);
                    //Insert it there                    
                    list.Insert(index < 0 ? ~index : index, listItem);
                    
                    //Secondly insert into dictionary
                    dict.Add(Key,new TimeTaggedItem<TValue>(TimeStamp,Value));
                }
            }
        }

        /// <summary>
        /// Scans for the location of an item within the internal list.
        /// </summary>
        /// <remarks>
        /// Performs a binary search within the list with forward and backward scanning.
        /// Will throw an exception if item is not found. USE ONLY to find an item by key when you KNOW it's there.
        /// </remarks>
        /// <param name="Key">Item Key</param>
        /// <param name="entryValueItem">The Item Value</param>
        /// <returns>The zer-based index of the items location</returns>
        private int BinaryLocate(TKey Key, TimeTaggedItem<TValue> entryValueItem)
        {
            int index = list.BinarySearch(new TimeTaggedItem<TKey>(entryValueItem.TimeStamp, Key));

            if (index < 0)
            {
                throw new InvalidOperationException("Use BinaryLocate only when the item exists in the List");
            }

            //This might not be the one corresponding to the right key
            int b = 0, f = 0;
            while (!list[index].Value.Equals(Key))
            {
                //So scan backwards and forwards silmultaneously
                b++;
                f++;

                if (index - b >= 0)
                {
                    if (list[index - b].Value.Equals(Key))
                    {
                        index = index - b;
                        break;
                    }
                }

                if (index + f <= list.Count - 1)
                {
                    if (list[index + f].Value.Equals(Key))
                    {
                        index = index + f;
                        break;
                    }
                }

                if ((index + f > list.Count - 1) && (index - b < 0))
                {
                    throw new InvalidOperationException("Use BinaryLocate only when the item exists in the List");
                }

            }
            return index;
        }

        /// <summary>
        /// Checks if the dictionary contains an item
        /// </summary>
        /// <param name="key">Item Key</param>
        /// <returns>True, if the item was found. Otherwise, false</returns>
        public bool ContainsKey(TKey key)
        {
            lock (sync)
            {
                return dict.ContainsKey(key);
            }
        }

        /// <summary>
        /// Removes an item from the dictionary
        /// </summary>
        /// <param name="Key">Item Key</param>
        /// <returns>true if item was removed. Otherwise, false.</returns>
        public bool Remove(TKey Key)
        {
            lock (sync)
            {
                TimeTaggedItem<TValue> entryValueItem;
                if (dict.TryGetValue(Key, out entryValueItem))
                {
                    //This item exists so remove both dictionary and list

                    //First remove from list
                    //Look for existing item using the found entry
                    int index = BinaryLocate(Key, entryValueItem);
                    //Remove item from the list
                    list.RemoveAt(index);

                    //Secondly remove from dictionary
                    dict.Remove(Key);

                    return true;

                }

                return false;

            }
        }

        /// <summary>
        /// Gets the value of an item
        /// </summary>
        /// <param name="key">Item Key</param>
        /// <param name="value">Item Value</param>
        /// <returns>True, if item value was obtained. Otherwise, false</returns>
        public bool TryGetValue(TKey key, out TValue value)
        {
            value = default(TValue);
            TimeTaggedItem<TValue> entry;
            lock(sync)
            {
                if (dict.TryGetValue(key, out entry))
                {
                    value = entry.Value;
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        /// <summary>
        /// Gets the time stamp value of an item
        /// </summary>
        /// <param name="Key">Key</param>
        /// <param name="TimeStamp">The Timestamp</param>
        /// <returns>True if timestamp was obtained. Otherwise, false.</returns>
        public bool TryGetTimeStamp(TKey Key, out DateTime TimeStamp)
        {
            TimeTaggedItem<TValue> entry;
            TimeStamp = DateTime.MinValue;
            lock (sync)
            {
                if (dict.TryGetValue(Key, out entry))
                {
                    //This item exists so return the value;
                    TimeStamp = entry.TimeStamp;
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        /// <summary>
        /// Gets the key of the item with the newest time stamp
        /// </summary>
        public TKey NewestKey
        {
            get
            {
                lock (sync)
                {
                    if (list.Count > 0)
                    {
                        return list[list.Count - 1].Value;
                    }
                    else
                    {
                        return default(TKey);
                    }
                }
            }
        }

        /// <summary>
        /// Gets the key of the item with the oldest time stamp
        /// </summary>
        public TKey OldestKey
        {
            get
            {
                lock (sync)
                {
                    if (list.Count > 0)
                    {
                        return list[0].Value;
                    }
                    else
                    {
                        return default(TKey);
                    }
                }
            }
        }

        /// <summary>
        /// Gets a list of all keys newer than a specified date
        /// </summary>
        /// <param name="DatedAfter">The specified date</param>
        /// <returns>A list of keys</returns>
        public List<TKey> GetNewKeys(DateTime DatedAfter)
        {
            List<TKey> keys = new List<TKey>();
            lock (sync)
            {
                if (list.Count > 0)
                {
                    for (int i = list.Count - 1; i >= 0; i--)
                    {
                        if (list[i].TimeStamp > DatedAfter)
                        {
                            keys.Add(list[i].Value);
                        }
                        else
                        {
                            break;
                        }
                    }
                }
            }
            return keys;
        }

        /// <summary>
        /// Gets a list of all keys older than a specified date
        /// </summary>
        /// <param name="DatedBefore">The specified date</param>
        /// <returns>List of keys</returns>
        public List<TKey> GetOldKeys(DateTime DatedBefore)
        {            
            List<TKey> keys = new List<TKey>();
            lock (sync)
            {
                if (list.Count > 0)
                {
                    for (int i = 0; i < list.Count; i++)
                    {
                        if (list[i].TimeStamp < DatedBefore)
                        {
                            keys.Add(list[i].Value);
                        }
                        else
                        {
                            break;
                        }
                    }
                }
            }
            
            return keys;

            
        }


        /// <summary>
        /// Gets the item with the newest time stamp
        /// </summary>
        public TimeTaggedItem<TValue> Newest
        {
            get
            {
                lock (sync)
                {
                    if (list.Count > 0)
                    {
                        return dict[list[list.Count - 1].Value];
                    }
                    else
                    {
                        return null;
                    }
                }
            }
        }

        /// <summary>
        /// Gets the item with the oldest timestamp
        /// </summary>
        public TimeTaggedItem<TValue> Oldest
        {
            get
            {
                lock (sync)
                {
                    if (list.Count > 0)
                    {
                        return dict[list[0].Value];
                    }
                    else
                    {
                        return null;
                    }
                }
            }
        }

        /// <summary>
        /// Gets the number of items in the dictionary
        /// </summary>
        public int Count
        {
            get
            {
                lock (sync)
                {
                    return list.Count;
                }
            }
        }

        /// <summary>
        /// Gets or sets the value for an item in the dictionary
        /// </summary>
        /// <param name="Key">Session key</param>
        /// <returns>The item value</returns>
        public TValue this[TKey Key]
        {
            get
            {
                TimeTaggedItem<TValue> entry;
                lock (sync)
                {
                    if (dict.TryGetValue(Key, out entry))
                    {
                        //This item exists so return the value;
                        return entry.Value;
                    }
                    else
                    {
                        throw new KeyNotFoundException("The key was not found in the dictionary");
                    }
                }
            }
            set
            {
                TimeTaggedItem<TValue> entry;
                bool found = false;
                lock (sync)
                {
                    if (dict.TryGetValue(Key, out entry))
                    {
                        //This item exists so update the value;
                        entry.Value = value;
                        found = true;
                    }
                }

                if (!found)
                {
                    this.Add(DateTime.MinValue, Key, value);
                }
                
            }
        }

    }

    /// <summary>
    /// Represents a time tagged item.
    /// </summary>
    /// <remarks>
    /// Note that this class can be used encapsulate a dictionary key or value
    /// </remarks>
    /// <typeparam name="T">The Type of the time tagged item's value</typeparam>
    class TimeTaggedItem<T> : IComparable<TimeTaggedItem<T>>
    {
        public DateTime TimeStamp;
        public T Value;

        /// <summary>
        /// Initializes a new instance of a TimeTaggedItem class
        /// </summary>
        /// <param name="TimeStamp">The timestamp to assign</param>
        /// <param name="Value">The value of the item</param>
        public TimeTaggedItem(DateTime TimeStamp, T Value)
        {
            this.TimeStamp = TimeStamp;
            this.Value = Value;
        }


        #region IComparable<DatedItem<TItem>> Members

        public int CompareTo(TimeTaggedItem<T> other)
        {
            return TimeStamp.CompareTo(other.TimeStamp);
        }

        #endregion
    }

    
}


