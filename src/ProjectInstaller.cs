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
using System.Collections;
using System.ComponentModel;
using System.Configuration.Install;
using System.ServiceProcess;

namespace StateService
{

    [RunInstaller(true)]
    public class ProjectInstaller : System.Configuration.Install.Installer
    {
       private ServiceInstaller serviceInstaller;
       private ServiceProcessInstaller processInstaller;

        public ProjectInstaller()
        {
            // Instantiate installers for process and service.
            processInstaller = new ServiceProcessInstaller();
            serviceInstaller = new ServiceInstaller();

            //TODO: FEATURE: Figure out how to get this to run in the Network Service account
            // The service runs under the local system account.
            processInstaller.Account = ServiceAccount.LocalSystem;
            serviceInstaller.StartType = ServiceStartMode.Manual;

            // ServiceName must equal those on ServiceBase derived classes.            
            serviceInstaller.ServiceName = StateService.InternalName;
            serviceInstaller.DisplayName = StateService.DisplayName;
            serviceInstaller.Description = StateService.Description;

            // Add installers to collection
            Installers.Add(serviceInstaller);
            Installers.Add(processInstaller);
        }

    }



}