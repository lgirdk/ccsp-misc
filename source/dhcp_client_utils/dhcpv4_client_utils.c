/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dhcp_client_utils.h"
#include "udhcpc_client_utils.h"
#ifdef  DHCPV4_CLIENT_TI_UDHCPC
#include "ti_udhcpc_client_utils.h"
#endif
#include <syscfg/syscfg.h>
#include <string.h>

/*
 * get_dhcpv4_opt_list ()
 * @description: Returns a list of DHCP REQ and a list of DHCP SEND options
 * @params     : req_opt_list - output param to fill the DHCP REQ options
               : send_opt_list - output param to fill the DHCP SEND options
 * @return     : returns the SUCCESS on successful fetching of DHCP options, else returns failure
 *
 */
static int get_dhcpv4_opt_list (dhcp_params * params, dhcp_opt_list ** req_opt_list, dhcp_opt_list ** send_opt_list)
{

    if ((req_opt_list == NULL) || (send_opt_list == NULL))
    {
        DBG_PRINT ("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

#ifdef EROUTER_DHCP_OPTION_MTA
    //syscfg for eth_wan_enabled
    char wanoe_enable[BUFLEN_16] = {0};
    if (syscfg_get(NULL, "eth_wan_enabled", wanoe_enable, sizeof(wanoe_enable)) == 0)
    {
        if (strcmp(wanoe_enable, "true") == 0)
        {
            // request option 122 - CableLabs Client Configuration
            add_dhcp_opt_to_list(req_opt_list, DHCPV4_OPT_122, NULL);
            // send option 125 - option value added by hal
            add_dhcp_opt_to_list(send_opt_list, DHCPV4_OPT_125, NULL);
        }
    }
    else
    {
        DBG_PRINT("Failed to get eth_wan_enabled \n");
    }
#endif

#if defined(_HUB4_PRODUCT_REQ_)
    DBG_PRINT("%s %d: interface=[%s] Adding Option 43 \n", __FUNCTION__, __LINE__, params->baseIface);
    add_dhcp_opt_to_list(req_opt_list, DHCPV4_OPT_43, NULL);
#else
    UNUSED_VARIABLE(params);
#endif

    if (platform_hal_GetDhcpv4_Options(req_opt_list, send_opt_list) == FAILURE)
    {
        DBG_PRINT("%s %d: failed to get option list from platform hal\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    return SUCCESS;

}

/*
 * start_dhcpv4_client ()
 * @description: This API will build dhcp request/send options and start dhcp client program.
 * @params     : input parameter to pass interface specific arguments
 * @return     : returns the pid of the dhcp client program else return error code on failure
 *
 */
pid_t start_dhcpv4_client (dhcp_params * params)
{
    if (params == NULL)
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return 0;
    }


    pid_t pid = FAILURE;

#ifdef  DHCPV4_CLIENT_TI_UDHCPC
    char udhcpcV2Enabled[BUFLEN_16] = {0};
    syscfg_get(NULL, "UDHCPEnable_v2", udhcpcV2Enabled, sizeof(udhcpcV2Enabled));
    if (strcmp(udhcpcV2Enabled, "true"))
    {
        DBG_PRINT("%s %d: TI_UDHCPC enabled \n", __FUNCTION__, __LINE__);
        pid =  start_ti_udhcpc (params);
        return pid;
    }
#endif

    // init part
    dhcp_opt_list * req_opt_list = NULL;
    dhcp_opt_list * send_opt_list = NULL;

    DBG_PRINT("%s %d: Collecting DHCP GET/SEND Request\n", __FUNCTION__, __LINE__);
    if (get_dhcpv4_opt_list(params, &req_opt_list, &send_opt_list) == FAILURE)
    {
        DBG_PRINT("%s %d: failed to get option list from platform hal\n", __FUNCTION__, __LINE__);
        return pid;
    }

    // building args and starting dhcpv4 client
    DBG_PRINT("%s %d: Starting DHCP Clients\n", __FUNCTION__, __LINE__);
#ifdef DHCPV4_CLIENT_UDHCPC
    if (params->ifType == WAN_LOCAL_IFACE)
    {
    pid =  start_udhcpc (params, req_opt_list, send_opt_list);
    }
    else
    {
        // for REMOTE_IFACE,
        //  DHCP request options are needed
        //  DHCP send options are not necessary
        pid =  start_udhcpc (params, req_opt_list, NULL);
    }
#endif

    //exit part
    DBG_PRINT("%s %d: freeing all allocated resources\n", __FUNCTION__, __LINE__);
    free_opt_list_data (req_opt_list);
    DBG_PRINT("%s %d: freeing all allocated resources\n", __FUNCTION__, __LINE__);
    free_opt_list_data (send_opt_list);
    return pid;

}


/*
 * stop_dhcpv4_client ()
 * @description: This API will stop DHCP client running for interface specified in parameter
 * @params     : input parameter to pass interface specific arguments
 * @return     : SUCCESS if client is filled, else returns failure
 *
 */
int stop_dhcpv4_client (dhcp_params * params)
{
    if (params == NULL)
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

#ifdef  DHCPV4_CLIENT_TI_UDHCPC
    char udhcpcV2Enabled[BUFLEN_16] = {0};
    syscfg_get(NULL, "UDHCPEnable_v2", udhcpcV2Enabled, sizeof(udhcpcV2Enabled));
    if (strcmp(udhcpcV2Enabled, "true"))
    {
        return stop_ti_udhcpc (params);
    }
#endif
    return stop_udhcpc (params);
}
