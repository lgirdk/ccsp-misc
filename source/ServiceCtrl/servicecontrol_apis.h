/*
 * If not stated otherwise in this file or this component's Licenses.txt file
 * the following copyright and licenses apply:
 *
 * Copyright 2023 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <rbus/rbus.h>
#include "safec_lib_common.h"
#include "ansc_platform.h"
#include <secure_wrapper.h>

#define SC_COMPONENT_NAME "ServiceControlRbus"

char const* GetParamName(char const* path);

int ServiceControl_Init();
void ServiceControl_Deinit();
void *svc_restart_queue_loop(void *arg);
int spawn_svc_restart_queue_loop();
int push_svc_to_queue(char *buffer);

/***************************************************************************************************

    Api              - int ServiceControl_Get_Sevice_Restart_List(char *pString)
    Function         - ServiceRestartList Get Functionality
    Parameter        - Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.ServiceCtrl.ServiceRestartList
    Supported Values - Comma delimited string

***************************************************************************************************/
int ServiceControl_Get_Sevice_Restart_List
    (
        char *pString
    );

/***************************************************************************************************

    Api              - int ServiceControl_Set_Sevice_Restart_List(char *pString)
    Function         - ServiceRestartList Set Functionality
    Parameter        - Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.ServiceCtrl.ServiceRestartList
    Supported Values - Comma delimited string

***************************************************************************************************/
int ServiceControl_Set_Sevice_Restart_List
    (
        char *pString
    );
