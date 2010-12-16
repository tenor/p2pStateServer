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
using System.Security.Cryptography;
using System.IO;

namespace P2PStateServer
{
    /// <summary>
    /// Represents an authentication object that hashes data with he SHA256 hash algorithm and encrypts/decrypts data with the Rjindael algorithm
    /// </summary>
    public class SHA256_AESAuthenticator
    {

        const string serverGroup = "state_service";
        const string hashAlgorithmName = "SHA-256";


        readonly string realm;
        readonly int privateInfo;
        readonly string machineName;

        const int keySize = 16; //half of the hashsize of the hash algorithm
        const int ivSize = 16;


        string password;

        /// <summary>
        /// Initializes a new instance of the SHA256_AESAuthenticator class
        /// </summary>
        /// <param name="Password">Secret password used for authentication and generating encryption keys</param>
        public SHA256_AESAuthenticator(string Password)
        {
            password = Password;
            realm = serverGroup + "@" + System.Environment.MachineName;
            machineName = Environment.MachineName;
            privateInfo = new Random().Next();

        }

        /// <summary>
        /// Gets the HashAlgorithm object used by this Authenticator
        /// </summary>
        /// <returns>The Authenticator HashAlgorithm</returns>
        private HashAlgorithm GetHashAlgorithm()
        {
            //Using the same hash algorithm in a muli-threaded environment leads to big problems BIG TIME, 
            //so create a brand new one whenever something needs to be hashed

            return new SHA256Managed();
        }

        /// <summary>
        /// Gets the Authentication realm parameter acording to RFC 2617
        /// </summary>
        public string Realm
        {
            get
            {
                return realm;
            }
        }

        /// <summary>
        /// Gets the network name of this computer
        /// </summary>
        public string MachineName
        {
            get
            {
                return machineName;
            }
        }

        /// <summary>
        /// Generates a new random challenge
        /// </summary>
        /// <returns>a new Challenge string</returns>
        /// <see cref="http://www.ietf.org/rfc/rfc2617.txt"/>
        public string GetNewChallenge()
        {
            byte[] nonce = Encoding.UTF8.GetBytes(String.Format("{0}:{1}", DateTime.UtcNow.Ticks, privateInfo.ToString("x")));
            return Convert.ToBase64String(nonce);
        }

        /// <summary>
        /// Gets the name of the Hash algorithm as required by RFC 2617
        /// </summary>
        public string HashAlgorithmName
        {
            get { return hashAlgorithmName; }
        }

        /// <summary>
        /// Calculate a Response Digest in Accordance to RFC 2617
        /// </summary>
        /// <param name="Username">The Username</param>
        /// <param name="Realm">The Realm</param>
        /// <param name="Password">The secret password</param>
        /// <param name="Nonce">The Nonce</param>
        /// <param name="NonceCount">The Nonce count</param>
        /// <param name="ClientNonce">The Client nonce</param>
        /// <param name="QOP">QOP</param>
        /// <param name="Method">Method</param>
        /// <param name="URI">URI</param>
        /// <param name="HashAlg">The Hash Algorithm to use</param>
        /// <returns>The calculated Response Digest</returns>
        /// <see cref="http://www.ietf.org/rfc/rfc2617.txt"/>
        private static string CalculateDigest(string Username, string Realm, string Password, string Nonce, int NonceCount,
            string ClientNonce, string QOP, string Method, string URI, HashAlgorithm HashAlg)
        {
            if (Username == null) throw new ArgumentNullException("Username");
            if (Realm == null) throw new ArgumentNullException("Realm");
            if (Password == null) throw new ArgumentNullException("Password");
            if (Nonce == null) throw new ArgumentNullException("Nonce");
            if (ClientNonce == null) throw new ArgumentNullException("ClientNonce");
            if (QOP == null) throw new ArgumentNullException("QOP");
            if (URI == null) throw new ArgumentNullException("URI");


            byte[] hA1 = HashAlg.ComputeHash(Encoding.UTF8.GetBytes(string.Format("{0}:{1}:{2}", Username.Trim(), Realm.Trim(), Password)));

            byte[] hA2 = HashAlg.ComputeHash(Encoding.UTF8.GetBytes(string.Format("{0}:{1}", Method, URI.Trim())));

            return EnHex(HashAlg.ComputeHash(Encoding.UTF8.GetBytes(string.Format("{0}:{1}:{2}:{3}:{4}:{5}", EnHex(hA1), Nonce.Trim(), NonceCount, ClientNonce.Trim(), QOP.Trim(), EnHex(hA2)))));


        }

        /// <summary>
        /// Calculates a Hex string representation of data, in accordance to the 32LHEX format
        /// of the Authorization Request Header in RFC 2617
        /// </summary>
        /// <param name="data">Data</param>
        /// <returns>Hex string representation of supplied data</returns>
        private static string EnHex(byte[] data)
        {
            
            if (data == null) throw new ArgumentNullException("data");

            return BitConverter.ToString(data).Replace("-",string.Empty);

            /* A slower implementation
            StringBuilder sb = new StringBuilder();
            foreach (byte b in data)
            {
                sb.Append(b.ToString("x2"));

                // An even slower implementation
                //sb.Append(((b >> 4) & (byte)0xF).ToString("x"));
                //sb.Append((b & (byte)0xF).ToString("x"));
                
            }
            return sb.ToString();              
             
            */

        }

        /// <summary>
        /// Calculate a Server Response Digest in Accordance to RFC 2617
        /// </summary>
        /// <param name="Algorithm">The Algorithm name</param>
        /// <param name="Username">The Username</param>
        /// <param name="Realm">The Realm</param>
        /// <param name="Nonce">The Nonce</param>
        /// <param name="NonceCount">The Nonce count</param>
        /// <param name="ClientNonce">The Client nonce</param>
        /// <param name="QOP">QOP</param>
        /// <param name="URI">URI</param>
        /// <returns>Server Response Digest</returns>
        /// <see cref="http://www.ietf.org/rfc/rfc2617.txt"/>
        public string GetClientResponseDigest(string Algorithm, string Username, string Realm, string Nonce, int NonceCount, string ClientNonce, string QOP, string URI)
        {
            if (Algorithm.ToUpperInvariant() != hashAlgorithmName.ToUpperInvariant()) return null;

            return CalculateDigest(Username, Realm, password, Nonce, NonceCount, ClientNonce, QOP, string.Empty, URI, GetHashAlgorithm());
        }

        /// <summary>
        /// Calculate a Server Response Digest in Accordance to RFC 2617
        /// </summary>
        /// <param name="Algorithm">The Algorithm name</param>
        /// <param name="Username">The Username</param>
        /// <param name="Realm">The Realm</param>
        /// <param name="Nonce">The Nonce</param>
        /// <param name="NonceCount">The Nonce count</param>
        /// <param name="ClientNonce">The Client nonce</param>
        /// <param name="QOP">QOP</param>
        /// <param name="URI">URI</param>
        /// <returns>Server Response Digest</returns>
        /// <see cref="http://www.ietf.org/rfc/rfc2617.txt"/>
        public string GetServerResponseDigest(string Algorithm, string Username, string Realm, string Nonce, int NonceCount, string ClientNonce, string QOP, string URI)
        {
            if (Algorithm.ToUpperInvariant() != hashAlgorithmName.ToUpperInvariant()) return null;

            return CalculateDigest(Username, Realm, password, Nonce, NonceCount, ClientNonce, QOP, "GET", URI, GetHashAlgorithm());
        }

        /// <summary>
        /// Calculates a session key from the supplied data
        /// </summary>
        /// <param name="Username">The Username</param>
        /// <param name="Realm">The Realm</param>
        /// <param name="Nonce">The Nonce</param>
        /// <param name="ClientNonce">The ClientNonce</param>
        /// <returns>Session key</returns>
        public byte[] GetSessionKey(string Username, string Realm, string Nonce, string ClientNonce)
        {
            //Session key is Hash([Username][Realm][Password][ServerChallenge][ClientChallenge])
            //This is somewhat in accordance to RFC 2617

            List<byte> byteBuilder = new List<byte>();
            byteBuilder.AddRange(Encoding.UTF8.GetBytes(Username));
            byteBuilder.AddRange(Encoding.UTF8.GetBytes(Realm));
            byteBuilder.AddRange(Encoding.UTF8.GetBytes(password));
            byteBuilder.AddRange(Convert.FromBase64String(Nonce));
            byteBuilder.AddRange(Convert.FromBase64String(ClientNonce));

            return GetHashAlgorithm().ComputeHash(byteBuilder.ToArray());

        }


        /// <summary>
        /// Encrypts data using the AES algorithm
        /// </summary>
        /// <param name="Data">Plaintext data</param>
        /// <param name="SessionKey">The encryption session key</param>
        /// <returns>Encrypted data</returns>
        public byte[] Protect(byte[] Data, byte[] SessionKey)
        {


            RijndaelManaged aes = new RijndaelManaged();
            byte[] key = new byte[keySize];
            byte[] iv = new byte[ivSize];

            Array.Copy(SessionKey, key, keySize);
            Array.Copy(SessionKey, keySize, iv, 0, ivSize);

            //Create a key with initialization vector.
            aes.KeySize = keySize * 8;
            aes.Key = key;
            aes.IV = iv;

            return Encrypt(Data, aes);
            
        }

        /// <summary>
        /// Encrypt data
        /// </summary>
        /// <param name="Data">Data to encrypt</param>
        /// <param name="EncryptionObject">Encryption object</param>
        /// <returns>Encrypted data</returns>
        private static byte[] Encrypt(byte[] Data, SymmetricAlgorithm EncryptionObject)
        {
            //Get an encryptor.
            ICryptoTransform encryptor = EncryptionObject.CreateEncryptor(EncryptionObject.Key, EncryptionObject.IV);

            CryptoStream csEncrypt = null;

            //Encrypt the data.
            MemoryStream msEncrypt = new MemoryStream();

            try
            {

                try
                {
                    csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);

                    try
                    {

                        //Write all data to the crypto stream and flush it.
                        csEncrypt.Write(Data, 0, Data.Length);
                        csEncrypt.FlushFinalBlock();
                    }
                    finally
                    {
                        csEncrypt.Close();
                    }
                }

                finally
                {
                    msEncrypt.Close();
                }

                byte[] result = msEncrypt.ToArray();
                return result;
            }

            finally
            {
                //free resources

                //encryptor = null;
                if (encryptor != null) encryptor.Dispose();

                //msEncrypt = null;
                if (msEncrypt != null) msEncrypt.Dispose();

                //csEncrypt = null;
                if (csEncrypt != null) csEncrypt.Dispose();
            }
        }

        /// <summary>
        /// Decrypts data using the AES algorithm
        /// </summary>
        /// <param name="Data">Encrypted Data</param>
        /// <param name="SessionKey">Encrytion Session key</param>
        /// <param name="Length">Length of descrypted data</param>
        /// <returns>Decrypted data</returns>
        public byte[] Unprotect(byte[] Data, byte[] SessionKey, int Length)
        {

            RijndaelManaged aes = new RijndaelManaged();
            byte[] key = new byte[keySize];
            byte[] iv = new byte[ivSize];

            Array.Copy(SessionKey, key, keySize);
            Array.Copy(SessionKey, keySize, iv, 0, ivSize);

            //Create a key with initialization vector.
            aes.KeySize = keySize * 8;
            aes.Key = key;
            aes.IV = iv;

            return Decrypt(Data, aes, Length);
        }

        /// <summary>
        /// Decrypts data
        /// </summary>
        /// <param name="Data">Encrypted Data</param>
        /// <param name="DecryptionObject">Decryption object</param>
        /// <param name="UnEncryptedSize">Size of decrypted data</param>
        /// <returns>Decrypted data</returns>
        private static byte[] Decrypt(byte[] Data, SymmetricAlgorithm DecryptionObject, int UnEncryptedSize)
        {
            //Get an decryptor.
            ICryptoTransform decryptor = DecryptionObject.CreateDecryptor(DecryptionObject.Key, DecryptionObject.IV);

            CryptoStream csDecrypt = null;

            //Decrypt the data.
            MemoryStream msDecrypt = new MemoryStream(Data);

            try
            {
                csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);

                try
                {

                    byte[] buffer = new byte[UnEncryptedSize];
                    csDecrypt.Read(buffer, 0, UnEncryptedSize);
                    return buffer;
                }
                catch
                {
                    throw;
                }
                finally
                {
                    csDecrypt.Close();
                }
            }

            finally
            {
                msDecrypt.Close();


                //free resources

                //decryptor = null;
                if (decryptor != null) decryptor.Dispose();

                //msDecrypt = null;
                if (msDecrypt != null) msDecrypt.Dispose();

                //csDecrypt = null;
                if (csDecrypt != null) csDecrypt.Dispose();

            }
        }

    }

}
