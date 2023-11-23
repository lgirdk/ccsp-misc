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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include "servicecontrol_rbus_handler_apis.h"
#include "servicecontrol_dml.h"
#include "servicecontrol_apis.h"
#include "servicecontrol_log.h"

#define SC_NUM_OF_RBUS_PARAMS  sizeof(ServiceControlRbusDataElements)/sizeof(ServiceControlRbusDataElements[0])

extern rbusHandle_t g_rbusHandle;

rbusDataElement_t ServiceControlRbusDataElements[] =
{
    /* RBUS_STRING */
    {SERVICE_CONTROL_RESTART_LIST_DML, RBUS_ELEMENT_TYPE_PROPERTY, {ServiceControl_GetStringHandler, ServiceControl_SetStringHandler, NULL, NULL, NULL, NULL}},
};

/*****************************************************************************************

  ServiceControl_Rbus_Init(): Initialize Rbus and data elements for ServiceCtrl

 *****************************************************************************************/
rbusError_t ServiceControl_Rbus_Init()
{
    int rc = RBUS_ERROR_SUCCESS;
    SvcCtrlDebug(("In %s\n", __FUNCTION__));
    if(RBUS_ENABLED == rbus_checkStatus())
    {
        SvcCtrlInfo(("RBUS enabled, Proceed with ServiceCtrl\n"));
    }
    else
    {
        SvcCtrlError(("RBUS is NOT ENABLED, Can't Proceed with ServiceCtrl\n"));
        return RBUS_ERROR_BUS_ERROR;
    }

    rc = rbus_open(&g_rbusHandle, SC_COMPONENT_NAME);
    if (rc != RBUS_ERROR_SUCCESS)
    {
        SvcCtrlError(("ServiceCtrl RBUS Initialization failed\n"));
        rc = RBUS_ERROR_NOT_INITIALIZED;
        return rc;
    }

    // Register data elements
    rc = rbus_regDataElements(g_rbusHandle, SC_NUM_OF_RBUS_PARAMS, ServiceControlRbusDataElements);

    if (rc != RBUS_ERROR_SUCCESS)
    {
        SvcCtrlError(("rbus register data elements failed\n"));
        rc = rbus_close(g_rbusHandle);
        return rc;
    }
    SvcCtrlDebug(("Out %s\n", __FUNCTION__));
    return rc;
}

/************************************************************************************

Get Handler API for objects of type RBUS_STRING for objects:

    Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.ServiceCtrl.ServiceRestartList

*************************************************************************************/

rbusError_t ServiceControl_GetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    SvcCtrlDebug(("In %s\n", __FUNCTION__));
    errno_t rc = 0;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t val;
    char value[1024] = {0};

    SvcCtrlInfo(("Called %s for [%s]\n", __FUNCTION__, propName));

    rbusValue_Init(&val);

    rc = ServiceControl_GetParamStringValue(NULL, param, value, NULL);
    free(param);
    if(rc != 0)
    {
        SvcCtrlError(("[%s]: ServiceControl_GetParamStringValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }

    rbusValue_SetString(val, value);
    rbusProperty_SetValue(property, val);
    rbusValue_Release(val);
    SvcCtrlDebug(("Out %s\n", __FUNCTION__));
    return RBUS_ERROR_SUCCESS;
}

/************************************************************************************

Set Handler API for objects of type RBUS_STRING for objects:

    Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.ServiceCtrl.ServiceRestartList

*************************************************************************************/

rbusError_t ServiceControl_SetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    (void)handle;
    (void)options;
    SvcCtrlDebug(("In %s\n", __FUNCTION__));
    BOOL rc = FALSE;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t val = rbusProperty_GetValue(property);

    SvcCtrlInfo(("Called %s for [%s]\n", __FUNCTION__, param));

    rc = ServiceControl_SetParamStringValue(NULL, param, (char*) rbusValue_GetString(val,NULL));
    free(param);
    if(!rc)
    {
        SvcCtrlError(("[%s]: ServiceControl_SetParamStringValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }
    SvcCtrlDebug(("Out %s\n", __FUNCTION__));
    return RBUS_ERROR_SUCCESS;
}
