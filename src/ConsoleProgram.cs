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
using System.Threading;
using P2PStateServer;


namespace ConsoleServer
{

    class ConsoleProgram
    {
        static void Main(string[] args)
        {
            Console.BackgroundColor = ConsoleColor.DarkRed;
            Console.Clear();

            //Attach a console listener
            System.Diagnostics.Debug.Listeners.Add(new System.Diagnostics.ConsoleTraceListener());

            //Start server
            ServerSettings settings = new ServerSettings();
            StateServer server = new StateServer(settings, new SHA256_AESAuthenticator(settings["PeerPassword"]));
            server.Start();

            Console.WriteLine("[SERVER STARTED. PRESS ESCAPE KEY TO QUIT.]\r\n");

            //Wait for user signal to end server
            while (true)
            {
                if (Console.KeyAvailable)
                {
                    if (Console.ReadKey(true).Key == ConsoleKey.Escape)
                    {
                        break;
                    }
                }
                else
                {
                    Thread.Sleep(500);
                }
            }

            //Stop server
            server.Stop();

            

        }

    }

}
