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
using System.ComponentModel;
using System.Diagnostics;
using System.ServiceProcess;
using P2PStateServer;

namespace StateService
{
    public partial class StateService : ServiceBase
    {
        StateServer server;

        public StateService()
        {
            InitializeComponent();
            this.ServiceName = InternalName; //override whatever value is in the editor
        }

        public const string InternalName = "P2PStateService";
        public const string DisplayName = "Peer to Peer State Service";
        public const string Description = "Provides out-of-process distributed session state support for ASP.NET";

        protected override void OnStart(string[] args)
        {
            //Start server
            ServerSettings settings = new ServerSettings();
            server = new StateServer(settings, new SHA256_AESAuthenticator(settings["PeerPassword"]));
            server.Start();


        }

        protected override void OnStop()
        {
            RequestAdditionalTime(300000); //an extra five minutes -- this can be a lengthy process

            //stop server
            server.Stop();
            server = null;
        }
    }
}
