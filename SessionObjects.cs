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
using System.Threading;

namespace P2PStateServer
{

    /// <summary>
    /// Defines methos and properties that a class implements to encapsulate stored session data
    /// </summary>
    public interface ISessionObject
    {
        /// <summary>
        /// Gets a value indicating whether the session is currently in use by another operation
        /// </summary>
        bool IsInUse {get;}

        /// <summary>
        /// Gets or sets a value indicating whether the session is currently being transferred to a remote location
        /// </summary>
        bool IsExporting { get; set;}

        /// <summary>
        /// Performs an atomic compare exchange on the IsInuse property
        /// </summary>
        /// <param name="Value">The value to set IsInUse with if the compare matches</param>
        /// <param name="Comparand">The value to compare IsInUse with</param>
        /// <returns>The original IsInUse value before the compare operation</returns>
        bool CompareExchangeIsInUse(bool Value, bool Comparand);

        /// <summary>
        /// Gets the session data
        /// </summary>
        byte[] Data { get; }

        /// <summary>
        /// Gets the session last-updated date
        /// </summary>
        DateTime UpdateDate { get;}

        /// <summary>
        /// Gets or sets the session lock cookie value
        /// </summary>
        uint LockCookie { get;set;}

        /// <summary>
        /// Gets the session lock date
        /// </summary>
        DateTime LockDate { get;}

        /// <summary>
        /// Gets the session lock age
        /// </summary>
        TimeSpan LockAge { get;}

        /// <summary>
        /// Locks a session
        /// </summary>
        void Lock();

        /// <summary>
        /// Unlocks a locked session using the provided LockCookie value
        /// </summary>
        /// <remarks>
        /// The LockCookie value must match the session lock cookie value to perform the unlock
        /// </remarks>
        /// <param name="LockCookie">The Lock-Cookie value</param>
        /// <returns>True if session was unlocked. Otherwise, false</returns>
        bool UnLock(uint LockCookie);

        /// <summary>
        /// Resets the session timeout thus extending the lifespan of the session by the value of the session's timeout
        /// </summary>
        void ResetTimeout();

        /// <summary>
        /// Gets a value indicating whether the session is locked
        /// </summary>
        bool IsLocked { get;}

        /// <summary>
        /// Gets the session time out value in minutes
        /// </summary>
        int TimeOut { get;} //Length of the session before it is erased

        /// <summary>
        /// Gets or sets the session ExtraFlags value
        /// </summary>
        int ExtraFlags { get; set;}

        /// <summary>
        /// Copies all data from one Session object to this one
        /// </summary>
        /// <param name="ObjectToCopy">Session object to copy from</param>
        void CopyFrom(ISessionObject ObjectToCopy); //Essentially copies all information from ObjectToCopy

        /// <summary>
        /// Initializes a new SessionResponseInfo object filled with information from this session
        /// </summary>
        /// <returns>A SessionResponseInfo object</returns>
        ISessionResponseInfo CreateResponseInfo();


    }

    /// <summary>
    /// Defines methods and properties that a class implements to encapsulate information 
    /// sent to a web server regarding a session
    /// </summary>
    public interface ISessionResponseInfo
    {
        /// <summary>
        /// Gets the session Lock Cookie value
        /// </summary>
        uint LockCookie { get;}

        /// <summary>
        /// Gets the session Lock Date in Ticks
        /// </summary>
        long LockDateInTicks { get;}

        /// <summary>
        /// Gets the session Lock Age in seconds
        /// </summary>
        long LockAgeInSeconds { get;}

        /// <summary>
        /// Gets the session ActionFlags
        /// </summary>
        int ActionFlags { get;}

        /// <summary>
        /// Gets the session Timeout in minutes
        /// </summary>
        int Timeout { get;}

        /// <summary>
        /// Gets the session Last-Updated date in ticks
        /// </summary>
        long UpdateDateInTicks { get;}
    }

    /// <summary>
    /// Represents a stored session
    /// </summary>
    public class SessionObject : ISessionObject
    {
        const int DEFAULT_SESSION_TIMEOUT = 20; //20 minutes

        //NOTE: Any new variables should be supported in the CopyFrom() method and constructors
        int inuse;
        int isExporting;
        byte[] data;
        uint lockCookie;
        DateTime lockDate;
        DateTime updateDate;
        int timeout;
        sbyte extraFlags;
        bool locked;


        /// <summary>
        /// Initializes a new instance of the SessionObject class
        /// </summary>
        /// <param name="Message">The SetRequest Message to initialize fields from</param>
        public SessionObject(SetRequest Message)
        {
            inuse = 0;
            isExporting = 0;
            data = Message.Data;
            lockCookie = Message.LockCookie ?? 0;
            lockDate = DateTime.MinValue;
            updateDate = DateTime.UtcNow;
            timeout = Message.Timeout ?? DEFAULT_SESSION_TIMEOUT;
            sbyte.TryParse(Message.ExtraFlags, out extraFlags);
            locked = false;

        }

        /// <summary>
        /// Initializes a new instance of the SessionObject class
        /// </summary>
        /// <param name="Message">The SetTransferRequest Message to initialize fields from</param>
        public SessionObject(SetTransferRequest Message)
        {

            inuse = 0;
            isExporting = 0;
            data = Message.Data;           
            timeout = Message.Timeout ?? DEFAULT_SESSION_TIMEOUT;
            sbyte.TryParse(Message.ExtraFlags, out extraFlags);
            lockCookie = Message.LockCookie ?? 0;
            updateDate = Message.LastModified;

            if (Message.LockDate.HasValue && Message.LockDate.Value != DateTime.MinValue)
            {
                locked = true;
                lockDate = Message.LockDate.Value;
            }
            else
            {
                locked = false;
                lockDate = DateTime.MinValue;
            }
            
        }


        #region ISessionObject Members

        /// <summary>
        /// Gets a value indicating whether the session is currently in use by another operation
        /// </summary>
        public bool IsInUse
        {
            get
            {
                
                /* No need to use Interlocked to read a 32 bit value
                int i = Interlocked.CompareExchange(ref inuse, -1, -1);
                return i == -1;
                 */

                return inuse == -1;
            }
        }

        /// <summary>
        /// Performs an atomic compare exchange on the IsInuse property
        /// </summary>
        /// <param name="Value">The value to set IsInUse with if the compare matches</param>
        /// <param name="Comparand">The value to compare IsInUse with</param>
        /// <returns>The original IsInUse value before the compare operation</returns>
        public bool CompareExchangeIsInUse(bool Value, bool Comparand)
        {
            int value = Value ? -1 : 0;
            int comparand = Comparand ? -1 : 0;

            return Interlocked.CompareExchange(ref inuse, value, comparand) == -1;            
        }

        /// <summary>
        /// Gets or sets a value indicating whether the session is currently being transferred to a remote location
        /// </summary>
        public bool IsExporting
        {
            get 
            {

                /* No need to use Interlocked to read a 32-bit value
                return Interlocked.CompareExchange(ref isExporting,-1,-1) == -1; 
                 */

                return isExporting == -1;
            }
            set 
            {
                if (inuse == 0)
                {
                    throw new InvalidOperationException("IsInuse property must be set to true before setting isExporting property");
                }

                int v = value ? -1 : 0;
                int comparand = value ? 0 : -1; //opposite of value

                Interlocked.CompareExchange(ref isExporting, v, comparand);
            }
        }

        /// <summary>
        /// Gets the session data
        /// </summary>
        public byte[] Data
        {
            get { return data ?? new byte[0]; }
        }

        /// <summary>
        /// Gets or sets the session lock cookie value
        /// </summary>
        public uint LockCookie
        {
            get { return lockCookie; }
            set { lockCookie = value; }
        }

        /// <summary>
        /// Gets the session last-modified date
        /// </summary>
        public DateTime UpdateDate
        {
            get { return updateDate; }
        }

        /// <summary>
        /// Gets the session lock date
        /// </summary>
        public DateTime LockDate
        {
            get { return lockDate; }
        }

        /// <summary>
        /// Gets the session lock age
        /// </summary>
        public TimeSpan LockAge
        {
            get { return locked ? DateTime.UtcNow.Subtract(lockDate) : new TimeSpan(0); }
        }

        /// <summary>
        /// Gets the session time out value in minutes
        /// </summary>
        public int TimeOut
        {
            get { return timeout; }
        }

        /// <summary>
        /// Gets or sets the session ExtraFlags value
        /// </summary>
        public int ExtraFlags
        {
            get { return extraFlags;  }
            set
            {
                try
                {                    
                    extraFlags = (sbyte)ExtraFlags; //This will take only the lowest byte of ExtraFlags
                }
                catch{}
            }
        }

        /// <summary>
        /// Copies all data from one Session object to this one
        /// </summary>
        /// <param name="ObjectToCopy">Session object to copy from</param>
        public void CopyFrom(ISessionObject ObjectToCopy)
        {
          //Do not copy inUse and isExporting properties (they are used internally)
          //inuse = ObjectToCopy.IsInUse ? -1 : 0;
          //isExporting = ObjectToCopy.IsExporting;

          data = ObjectToCopy.Data;
          lockCookie = ObjectToCopy.LockCookie;
          lockDate = ObjectToCopy.LockDate;
          updateDate = ObjectToCopy.UpdateDate;
          timeout = ObjectToCopy.TimeOut;
          extraFlags = (sbyte)ObjectToCopy.ExtraFlags;
          locked = ObjectToCopy.IsLocked;
        }

        /// <summary>
        /// Initializes a new SessionResponseInfo object filled with information from this session
        /// </summary>
        /// <returns>A SessionResponseInfo object</returns>
        public ISessionResponseInfo CreateResponseInfo()
        {
           return new SessionResponseInfo(this);
        }

        /// <summary>
        /// Locks a session
        /// </summary>
        public void Lock()
        {
            if (inuse == 0)
            {
                throw new InvalidOperationException("IsInuse property must be set to true before locking resource");
            }

            lockDate = DateTime.UtcNow;
            locked = true;

        }

        /// <summary>
        /// Unlocks a locked session using the provided LockCookie value
        /// </summary>
        /// <remarks>
        /// The LockCookie value must match the session lock cookie value to perform the unlock
        /// </remarks>
        /// <param name="LockCookie">The Lock-Cookie value</param>
        /// <returns>True if session was unlocked. Otherwise, false</returns>
        public bool UnLock(uint LockCookie)
        {
            if (inuse == 0)
            {
                throw new InvalidOperationException("IsInuse property must be set to true before unlocking resource");
            }            
            
            if (LockCookie == this.lockCookie)
            {
                locked = false;
                lockDate = DateTime.MinValue;
            }

            return !locked;
        }

        /// <summary>
        /// Resets the session timeout thus extending the lifespan of the session by the value of the session's timeout
        /// </summary>
        public void ResetTimeout()
        {
            updateDate = DateTime.UtcNow;
        }

        /// <summary>
        /// Gets a value indicating whether the session is locked
        /// </summary>
        public bool IsLocked
        {
            get { return locked; }

        }
        #endregion

    }

    /// <summary>
    /// Represents basic information about a session sent in a transmission
    /// </summary>
    public class SessionResponseInfo : ISessionResponseInfo
    {
        uint lockCookie;
        long lockdate;
        long lockAge;
        int flags;
        int timeout;
        DateTime updateDate;

        /// <summary>
        /// Initializes a new instance of the SessionResponseInfo class
        /// </summary>
        /// <param name="Session">The Session object to initialize field values from</param>
        public SessionResponseInfo(SessionObject Session)
        {
            lockCookie = Session.LockCookie;
            lockdate = Session.LockDate.Ticks;
            lockAge = (long)Session.LockAge.TotalSeconds > 0 ? (long)Session.LockAge.TotalSeconds : 0;
            flags = Session.ExtraFlags;
            timeout = Session.TimeOut;
            updateDate = Session.UpdateDate;
        }

        #region ISessionResponseInfo Members

        /// <summary>
        /// Gets the session Last-Updated date in ticks
        /// </summary>
        public long UpdateDateInTicks
        {
            get { return updateDate.Ticks; }
        }

        /// <summary>
        /// Gets the session Lock Cookie
        /// </summary>
        public uint LockCookie
        {
            get { return lockCookie ; }
        }

        /// <summary>
        /// Gets the session Lock Date in Ticks
        /// </summary>
        public long LockDateInTicks
        {
            get { return lockdate ; }
        }

        /// <summary>
        /// Gets the session Lock Age in seconds
        /// </summary>
        public long LockAgeInSeconds
        {
            get { return lockAge; }
        }

        /// <summary>
        /// Gets the session ActionFlags
        /// </summary>
        public int ActionFlags
        {
            get { return flags; }
        }

        /// <summary>
        /// Gets the session Timeout in minutes
        /// </summary>
        public int Timeout
        {
            get { return timeout; }
        }

        #endregion
    }



   
}
