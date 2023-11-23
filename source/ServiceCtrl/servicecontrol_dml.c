/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
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

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "servicecontrol_dml.h"
#include "servicecontrol_apis.h"
#include "servicecontrol_log.h"

ULONG
ServiceControl_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pParamName,
        char*                       pString,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pUlSize);
    SvcCtrlDebug(("In %s\n", __FUNCTION__));
    ULONG ret = -1;
    if (strcmp(pParamName, SERVICE_CONTROL_RESTART_LIST_PARAM_NAME) == 0)
    {
        if (ServiceControl_Get_Sevice_Restart_List(pString) == 0)
        {
            ret = 0;
        }
    }
    else
    {
        SvcCtrlError(("%s:Unsupported parameter '%s'\n", __FUNCTION__, pParamName));
        ret = 1;
    }
    SvcCtrlDebug(("Out %s\n", __FUNCTION__));
    return ret;
}


BOOL
ServiceControl_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    SvcCtrlDebug(("In %s\n", __FUNCTION__));
    if (strcmp(pParamName, SERVICE_CONTROL_RESTART_LIST_PARAM_NAME) == 0)
    {
        if (ServiceControl_Set_Sevice_Restart_List(pString) == 0)
        {
            SvcCtrlDebug(("Out %s\n", __FUNCTION__));
            return TRUE;
        }
        SvcCtrlError(("%s:ServiceControl_Set_Sevice_Restart_List failed\n", __FUNCTION__));
        return FALSE;
    }

    SvcCtrlError(("%s:Unsupported parameter '%s'\n", __FUNCTION__, pParamName));
    return FALSE;
}
