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
#include <syscfg/syscfg.h>
#include <string.h>

#define DUID "3561"
#define VENDOR_SPEC_FILE "/etc/udhcpc.vendor_specific"
#define VENDOR_OPTIONS_LENGTH 512

#ifndef CONFIG_VENDOR_NAME
#define CONFIG_VENDOR_NAME "Undefined Vendor"
#endif
#ifndef CONFIG_VENDOR_ID
#define CONFIG_VENDOR_ID "123456"
#endif

#if DHCPV4_CLIEN_TI_UDHCPC
static pid_t start_ti_udhcpc (dhcp_params * params)
{
    if (params == NULL)
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }
}
#endif  // DHCPV4_CLIENT_TI_UDHCPC

static int verifyBufferSpace(const int length, int opt_len, int size)
{
    if (length - opt_len <= size) {
        DBG_PRINT("%s: Too many options\n", __FUNCTION__);
        return 0;
    }

    return 1;
}

static int writeTOHexFromAscii(char *options, const int length, int opt_len, char *value)
{
    char *ptr;

    for (ptr = value; *ptr != 0; ptr++) {
        if (!verifyBufferSpace(length, opt_len, 2)) {
            return 0;
        }
        opt_len += sprintf(options + opt_len, "%02x", *ptr);
    }

    return opt_len;
}

/***
// RFC 3925 - Vendor-Identifying Vendor Options
// The format of the V-I Vendor-specific Information option is a follows:
//                        1 1 1 1 1 1
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  option-code  |  option-len   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |      enterprise-number1       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |   data-len1   |               |
//   +-+-+-+-+-+-+-+-+ option-data1  |
//   /                               /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
//   |      enterprise-number2       |   ^
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   |
//   |   data-len2   |               | optional
//   +-+-+-+-+-+-+-+-+ option-data2  |   |
//   /                               /   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   |
//   ~            ...                ~   V
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
//
//   option-code         OPTION_V-I_VENDOR_OPTS (125)
//   option-len          total length of all following option data in octets
//   enterprise-numberN  The vendor's registered 32-bit Enterprise Number as registered with IANA [3]
//   data-lenN           Length of option-data field
//   option-dataN        Vendor-specific options, described below
//   data-len1           Size of the option-data1
//
//   option-data1 format as follows
//                        1 1 1 1 1 1
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  subopt-code  |  subopt-len   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   /        sub-option-data        /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***/

static int prepare_dhcp125_optvalue(char *options_125, const int length)
{
    int opt_len = 0;
    int padding = 0;
    char duid [64];
    char options[128];
    int subopt;
    char buf[64];
    size_t len;

    //Create enterprise number
    snprintf(duid, sizeof(duid),"%02x%02x%x%02x",padding,padding,padding,atoi(DUID));

    //Create option-data1
    //Suboptions as per MVXREQ-3598 
    /*
       Sub-option code 1 - Manufacturer OUI 
    */
    subopt = 1;
    len = strlen (CONFIG_VENDOR_ID);
    if (len > 0)
    {
        if ((len > 0xFF) || !verifyBufferSpace(length, opt_len, 2 + 2 + (2 * len))) {
            return -1;
        }
        opt_len += sprintf(options + opt_len, "%02x%02x", subopt, len);
        opt_len = writeTOHexFromAscii(options, length, opt_len, CONFIG_VENDOR_ID);
    }
    /*
       Sub-option code 2 -  Product Class 
    */

    if(platform_hal_GetProductClass(buf) == RETURN_OK)
    {
        subopt = 2;
        len = strlen (buf);
        if (len > 0)
        {
            if ((len > 0xFF) || !verifyBufferSpace(length, opt_len, 2 + 2 + (2 * len))) {
              return -1;
        }
            opt_len += sprintf(options + opt_len, "%02x%02x", subopt, len);
            opt_len = writeTOHexFromAscii(options, length, opt_len, buf);
        }
    }
    else
    {
        DBG_PRINT("Option 125, Failed to get ProductClass \n");
        return -1;
    }

    /*
       Sub-option code 3 - Model Number
    */
    if (platform_hal_GetModelName(buf) == RETURN_OK)
    {
        subopt = 3;
        len = strlen (buf);
        if (len > 0)
        {
            if ((len > 0xFF) || !verifyBufferSpace(length, opt_len, 2 + 2 + (2 * len))) {
              return -1;
        }
            opt_len += sprintf(options + opt_len, "%02x%02x", subopt, len);
            opt_len = writeTOHexFromAscii(options, length, opt_len, buf);
        }
    }
    else
    {
        DBG_PRINT("Option 125, Failed to get ModelName \n");
        return -1;
    }

    /*
       Sub-option code 4 - serial number
    */
    if (platform_hal_GetSerialNumber (buf) == RETURN_OK)
    {
        subopt = 4;
        len = strlen (buf);
        if (len > 0)
        {
            if ((len > 0xFF) || !verifyBufferSpace(length, opt_len, 2 + 2 + (2 * len))) {
                return -1;
            }
            opt_len += sprintf(options + opt_len, "%02x%02x", subopt, len);
            opt_len = writeTOHexFromAscii(options, length, opt_len, buf);
        }
    }
    else
    {
        DBG_PRINT("Option 125, Failed to get SerialNumber \n");
        return -1;
    }
    len = strlen(options);
    snprintf(options_125,length,"%s%02x%s",duid,(len/2),options);
    return 0;
}

static int prepare_dhcp61_optvalue(char *options, const int length, dhcp_params * params)
{
    char basemac[18], ProductClass[32], SerialNo[64], IAID[9], buf[256];
    int type = 255;
    ULONG IAID_HEX = 0;
    int padding = 0;
    int opt_len = 0;
    int DUID_TYPE = 2;

    if(platform_hal_GetBaseMacAddress(basemac) == RETURN_OK)
    {
        IAID[0] = basemac[6];
        IAID[1] = basemac[7];
        IAID[2] = basemac[9];
        IAID[3] = basemac[10];
        IAID[4] = basemac[12];
        IAID[5] = basemac[13];
        IAID[6] = basemac[15];
        if (strcmp(params->ifname, "erouter0") == 0)
        {
            IAID[7] = basemac[16];
        }
        else if(strcmp(params->ifname, "mg0") == 0)
        {
            IAID[7] = basemac[16]+5;
        }
        else 
        {
            IAID[7] = basemac[16]+4;
        }
        IAID[8] = 0;
    }

    IAID_HEX = strtol(IAID,NULL,16); //convert char to hex
    //Identifier in format <OUI>"-"<ProductClass>"-"<CPE_LogisticsSerialNumber>

    if(platform_hal_GetProductClass(ProductClass) != RETURN_OK)  //Product class is MERCV3X
    {
        DBG_PRINT("Failed to get ProductClass \n");
        return -1;
    }

    if(platform_hal_GetSerialNumber(SerialNo) != RETURN_OK) //Serial Number
    {
        DBG_PRINT("Failed to get SerialNumber \n");
        return -1;
    }

    snprintf(buf, sizeof(buf),"%s-%s-%s",CONFIG_VENDOR_ID,ProductClass,SerialNo);
    opt_len += sprintf(options + opt_len, "%02x%0lx%02x%02x%02x%02x%x%02x",type,IAID_HEX,padding,DUID_TYPE,padding,padding,padding,atoi(DUID));
    opt_len = writeTOHexFromAscii(options, length, opt_len, buf);

    return 0;
}

/*
 * add_dhcpv4_opt_to_list ()
 * @description: util function to add DHCP opt and DHCP opt value to list
 * @params     : opt_list - output param to add DHCP options
               : opt - DHCP option
               : opt_val - DHCP option value - optional
 * @return     : returns the SUCCESS on adding option to list, else returns failure
 *
 */
static int add_dhcpv4_opt_to_list (dhcp_opt_list ** opt_list, int opt, char * opt_val)
{

    if ((opt_list == NULL) || (opt <= 0) ||(opt >= DHCPV4_OPT_END) )
    {
        return RETURN_ERR;
    }

    dhcp_opt_list * new_dhcp_opt = malloc (sizeof(dhcp_opt_list));
    if (new_dhcp_opt == NULL)
    {
        return RETURN_ERR;
    }
    memset (new_dhcp_opt, 0, sizeof(dhcp_opt_list));
    new_dhcp_opt->dhcp_opt = opt;

    if (opt_val)
    {
        new_dhcp_opt->dhcp_opt_val = strdup(opt_val);
        if (new_dhcp_opt->dhcp_opt_val == NULL)
        {
            free(new_dhcp_opt);
            return RETURN_ERR;
        }
    }
    else
    {
        new_dhcp_opt->dhcp_opt_val = NULL;
    }

    if (*opt_list != NULL)
    {
        new_dhcp_opt->next = *opt_list;
    }
    *opt_list = new_dhcp_opt;

    return RETURN_OK;

}

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
            char wanmg_enable[8];

            add_dhcpv4_opt_to_list(req_opt_list, DHCPV4_OPT_122, NULL);
            add_dhcpv4_opt_to_list(req_opt_list, DHCPV4_OPT_43, NULL);

            char options[VENDOR_OPTIONS_LENGTH];
            if (!prepare_dhcp61_optvalue(options, sizeof(options), params))
            {
                 add_dhcpv4_opt_to_list(send_opt_list, DHCPV4_OPT_61, options);
            }
            else
            {
                 DBG_PRINT("Failed to get OPTION 61 \n");
            }

            if (!prepare_dhcp125_optvalue(options, sizeof(options)))
            {
                 add_dhcpv4_opt_to_list(send_opt_list, DHCPV4_OPT_125, options);
            }
            else
            {
                 DBG_PRINT("Failed to get OPTION 125 \n");
            }

            if (strcmp(params->ifname, "erouter0") == 0)
            {
                 syscfg_get(NULL, "management_wan_enabled", wanmg_enable, sizeof(wanmg_enable));
                 if (strcmp(wanmg_enable, "1") != 0)
                 {
                     sprintf(options,"dslforum.org");
                 }
                 else
                 {
                     sprintf(options,"bb.data");
                 }
            }
            else if (strcmp(params->ifname, "mg0") == 0)
            {
                 sprintf(options,"dslforum.org");
            }
            else
            {
                 sprintf(options,"bb.voice");
            }
            add_dhcpv4_opt_to_list(send_opt_list, DHCPV4_OPT_60, options);
        }
    }
    else
    {
        DBG_PRINT("Failed to get eth_wan_enabled \n");
    }

    if ((params->opt & DHCPV4_OPT_43) == DHCPV4_OPT_43)
    {
        DBG_PRINT("%s %d: Adding Option 43 \n", __FUNCTION__, __LINE__);
        add_dhcpv4_opt_to_list(req_opt_list, DHCPV4_OPT_43, NULL);
    }

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
#elif DHCPV4_CLIEN_TI_UDHCPC
    pid =  start_ti_udhcpc (params);
#endif

    //exit part
    DBG_PRINT("%s %d: freeing all allocated resources\n", __FUNCTION__, __LINE__);
    free_opt_list_data (req_opt_list);
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

#ifdef DHCPV4_CLIENT_UDHCPC
    return stop_udhcpc (params);
#endif
    return SUCCESS;

}
