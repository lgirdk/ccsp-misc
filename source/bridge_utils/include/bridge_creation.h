/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
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

#ifndef _BRIDGE_CREATION_H_
#define _BRIDGE_CREATION_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include "network_interface.h"

#if !defined(USE_LINUX_BRIDGE)
#include "OvsAgentApi.h"
#define OTHER_IF_TYPE_VALUE OVS_OTHER_IF_TYPE
#define IF_UP_CMD_TYPE OVS_IF_UP_CMD
#define GRE_IF_TYPE_VALUE OVS_GRE_IF_TYPE
#define VLAN_IF_TYPE_VALUE OVS_VLAN_IF_TYPE
#define ETH_IF_TYPE_VALUE  OVS_ETH_IF_TYPE
#define BRIDGE_IF_TYPE_VALUE OVS_BRIDGE_IF_TYPE
#define IF_DELETE_CMD_TYPE OVS_IF_DELETE_CMD
#define BR_REMOVE_CMD_TYPE OVS_BR_REMOVE_CMD
#define IF_DOWN_CMD_TYPE OVS_IF_DOWN_CMD
typedef Gateway_Config Gateway_Config_t;
#else
#define OTHER_IF_TYPE_VALUE OTHER_IF_TYPE
#define IF_UP_CMD_TYPE IF_UP_CMD
#define GRE_IF_TYPE_VALUE GRE_IF_TYPE
#define VLAN_IF_TYPE_VALUE VLAN_IF_TYPE	
#define ETH_IF_TYPE_VALUE  ETH_IF_TYPE
#define BRIDGE_IF_TYPE_VALUE BRIDGE_IF_TYPE
#define IF_DELETE_CMD_TYPE IF_DELETE_CMD
#define BR_REMOVE_CMD_TYPE BR_REMOVE_CMD
#define IF_DOWN_CMD_TYPE IF_DOWN_CMD
typedef Gateway_Config_Non_Ovs_Bridge Gateway_Config_t;
#endif

typedef struct interact_request{
    #if !defined(USE_LINUX_BRIDGE)
    ovs_interact_request ovs_request;
    #endif
    Gateway_Config_t *gw_config;
}interact_request;

// Function declarations
#if !defined(USE_LINUX_BRIDGE)
bool create_ovs_bridge_api(interact_request *request, ovs_interact_cb callback);
#else
bool create_linux_bridge_api(interact_request *request);
#endif
bool brctl_interact(Gateway_Config_t *gw_config);
#endif

