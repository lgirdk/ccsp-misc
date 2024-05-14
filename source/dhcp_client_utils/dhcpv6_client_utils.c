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

#include "dibbler_client_utils.h"
#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>
#include <string.h>
#ifdef DHCPv6_CLIENT_TI_DHCP6C
#include "ti_dhcp6c_client_utils.h"
#endif

#define LOCALHOST         "127.0.0.1"
#define DHCP_SYSEVENT_NAME "dhcp_evt_handler"
#define DHCPV6C_ENABLED    "dhcpv6c_enabled"

token_t dhcp_sysevent_token;
int dhcp_sysevent_fd;

static int get_dhcpv6_opt_list (dhcp_opt_list ** req_opt_list, dhcp_opt_list ** send_opt_list)
{
    char dslite_enable[BUFLEN_16] = {0};
    char wanoe_enable[BUFLEN_16] = {0};

    if ((req_opt_list == NULL) || (send_opt_list == NULL))
    {
        DBG_PRINT ("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    //syscfg for eth_wan_enabled
    if (syscfg_get(NULL, "eth_wan_enabled", wanoe_enable, sizeof(wanoe_enable)) == 0)
    {
        if (strcmp(wanoe_enable, "true") == 0)
        {
	    //ToDo, eth_wan_enabled is not being be used by any platform at moment ,
	    //Comcast Platform is not affected by this change as currently comcast don't use
	    //Wan Interface State Machine.
        }
    }
    else
    {
        DBG_PRINT("Failed to get eth_wan_enabled \n");
    }

    //syscfg for dslite_enable and sysevent for dslite_enabled
    if (syscfg_get(NULL, "dslite_enable", dslite_enable, sizeof(dslite_enable)) == 0)
    {
        if (strcmp(dslite_enable, "true") == 0)
        {
            memset(dslite_enable, 0, BUFLEN_16);
            sysevent_get(dhcp_sysevent_fd, dhcp_sysevent_token, "dslite_enabled", dslite_enable, sizeof(dslite_enable));
            if (strcmp(dslite_enable, "true") == 0)
            {
                if (add_dhcp_opt_to_list (req_opt_list, DHCPV6_OPT_64, NULL) != RETURN_OK)
                {
                    DBG_PRINT("%s %d: failed to add REQUEST option OPTION_AFTR_NAME to list\n", __FUNCTION__, __LINE__);
                    return FAILURE;
                }
            }
        }
    }
    else
    {
        DBG_PRINT("Failed to get dslite_enable \n");
    }

    if (platform_hal_GetDhcpv6_Options(req_opt_list, send_opt_list) == FAILURE)
    {
        DBG_PRINT("%s %d: failed to get option list from platform hal\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    return SUCCESS;

}


/*
 * start_dhcpv6_client ()
 * @description: This API will build dhcp request/send options and start dibbler client program.
 * @params     : input parameter to pass interface specific arguments
 * @return     : returns the pid of the dibbler client program else return error code on failure
 *
 */
pid_t start_dhcpv6_client (dhcp_params * params)
{
    char * sysevent_name = DHCP_SYSEVENT_NAME;

    if (params == NULL)
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return 0;
    }

    //Check if default dibbler tmp path available or not. If not then create it
    create_dir_path(DIBBLER_TMP_DIR_PATH);

    pid_t pid = 0;
    pid = get_process_pid(DIBBLER_CLIENT, params->ifname, false);
    if (pid > 0)
    {
        DBG_PRINT("%s %d: another instance of %s running on %s \n", __FUNCTION__, __LINE__, DIBBLER_CLIENT, params->ifname);
        return FAILURE;
    }


    dhcp_sysevent_fd =  sysevent_open(LOCALHOST, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, sysevent_name, &dhcp_sysevent_token);
    if (dhcp_sysevent_fd < 0)
    {
        DBG_PRINT("%s %d: Fail to open sysevent.\n", __FUNCTION__, __LINE__);
	/* CID 189993 Improper use of negative value */
	return FAILURE;
    }

    // check if interface is ipv6 ready with a link-local address
    unsigned int waitTime = INTF_V6LL_TIMEOUT_IN_MSEC;
    char cmd[BUFLEN_128] = {0};
    snprintf(cmd, sizeof(cmd), "ip address show dev %s tentative", params->ifname);
    while (waitTime > 0)
    {
        FILE *fp_dad   = NULL;
        char buffer[BUFLEN_256] = {0};

        fp_dad = popen(cmd, "r");
        if(fp_dad != NULL) 
        {
            if ((fgets(buffer, BUFLEN_256, fp_dad) == NULL) || (strlen(buffer) == 0))
            {
                pclose(fp_dad);
                break;
            }
            DBG_PRINT("%s %d: interface still tentative: %s\n", __FUNCTION__, __LINE__, buffer);
            pclose(fp_dad);
        }
        usleep(INTF_V6LL_INTERVAL_IN_MSEC * USECS_IN_MSEC);
        waitTime -= INTF_V6LL_INTERVAL_IN_MSEC;
    }

    if (waitTime <= 0)
    {
        DBG_PRINT("%s %d: interface %s doesnt have link local address\n", __FUNCTION__, __LINE__, params->ifname);
        sysevent_close(dhcp_sysevent_fd, dhcp_sysevent_token);
        return pid;
    }

#ifdef DHCPv6_CLIENT_TI_DHCP6C
    char dibblerV2Enabled[BUFLEN_16] = {0};
    syscfg_get(NULL, "dibbler_client_enable_v2", dibblerV2Enabled, sizeof(dibblerV2Enabled));
    if (strcmp(dibblerV2Enabled, "true"))
    {
        return start_ti_dhcp6c (params);
    }
#endif

    // init part
    dhcp_opt_list * req_opt_list = NULL;
    dhcp_opt_list * send_opt_list = NULL;

    DBG_PRINT("%s %d: Collecting DHCP GET/SEND Request\n", __FUNCTION__, __LINE__);
    if ((params->ifType == WAN_LOCAL_IFACE) && (get_dhcpv6_opt_list(&req_opt_list, &send_opt_list)) == FAILURE)
    {
        DBG_PRINT("%s %d: failed to get option list from platform hal\n", __FUNCTION__, __LINE__);
        sysevent_close(dhcp_sysevent_fd, dhcp_sysevent_token);
        return pid;
    }

    // building args and starting dhcpv4 client
    DBG_PRINT("%s %d: Starting Dibbler Clients\n", __FUNCTION__, __LINE__);
#ifdef DHCPV6_CLIENT_DIBBLER
    pid =  start_dibbler (params, req_opt_list, send_opt_list);
#endif

    /* set dhcpv6c_enabled sysevent to restart dibbler-server in Selfheal process */
    sysevent_set(dhcp_sysevent_fd, dhcp_sysevent_token, DHCPV6C_ENABLED, "1", 0);

    //exit part
    DBG_PRINT("%s %d: freeing all allocated resources\n", __FUNCTION__, __LINE__);
    free_opt_list_data (req_opt_list);
    free_opt_list_data (send_opt_list);
    sysevent_close(dhcp_sysevent_fd, dhcp_sysevent_token);

    return pid;

}

/*
 * stop_dhcpv6_client ()
 * @description: This API will stop dhcpv6 client program for interface passed in paramter.
 * @params     : input parameter to pass interface specific arguments
 * @return     : returns SUCCESS if killed else returns FAILURE
 *
 */
int stop_dhcpv6_client (dhcp_params * params)
{
    char * sysevent_name = DHCP_SYSEVENT_NAME;

    if (params == NULL)
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return 0;
    }

    dhcp_sysevent_fd =  sysevent_open(LOCALHOST, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, sysevent_name, &dhcp_sysevent_token);
    if (dhcp_sysevent_fd < 0)
    {
        DBG_PRINT("%s %d: Fail to open sysevent.\n", __FUNCTION__, __LINE__);
	/* CID 280237 Improper use of negative value */
	return 0;
    }

    sysevent_set(dhcp_sysevent_fd, dhcp_sysevent_token, DHCPV6C_ENABLED, "0", 0);
    sysevent_close(dhcp_sysevent_fd, dhcp_sysevent_token);

#if DHCPv6_CLIENT_TI_DHCP6C
    char dibblerV2Enabled[BUFLEN_16] = {0};
    syscfg_get(NULL, "dibbler_client_enable_v2", dibblerV2Enabled, sizeof(dibblerV2Enabled));
    if (strcmp(dibblerV2Enabled, "true"))
    {
        return stop_ti_dhcp6c (params);
    }
#endif
    return stop_dibbler (params);
    return 0;

}

