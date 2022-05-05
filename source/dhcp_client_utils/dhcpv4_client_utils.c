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

/***
 * Parses a file containing vendor specific options
 *
 * options:  buffer containing the returned parsed options
 * length:   length of options
 *
 * Option code 43 - DHCPv4 Vendor- Vendor Specific Information Options
 *            Sub-option code 2,  <Device type> - EROUTER
 *            Sub-option code 3,  ECM:<eSAFE1:eSAFE2...eSAFEn>
 *            Sub-option code 4,  <device serial number>
 *            Sub-option code 5,  <Hardware version>
 *            Sub-option code 6,  <Software version>
 *            Sub-option code 7,  <Boot ROM version>  <-- Boot ROM version is mostly meaningless, assume this actually means Bootloader version.
 *            Sub-option code 8,  <OUI>
 *            Sub-option code 9,  <Model Number>
 *            Sub-option code 10, <Vendor name>
 *            Sub-option code 15, eSAFEs with cfg file encapsulation: <eSAFE1:eSAFE2...eSAFEn>
 *
 *      Code    Type   Len   Val   Type Len      Val    Type
 *     +-----+-------+-----+-----+----+----+-----------+----+--------
 *     | 43  |   2   |  3  | ECM |  3 |  8 |  ECM:EMTA |  4 | . . . .
 *     +-----+-------+-----+-----+----+----+-----------+----+---------
 *
 *
 * returns:  0 on successful parsing, else -1
 ***/

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

/*
   Warning: This function should be kept aligned with dhcp_parse_vendor_info() in utopia/source/service_wan/service_wan.c
*/
static int prepare_dhcp43_optvalue( char *options, const int length, char *ethWanMode )
{
    FILE *fp;
    char subopt_num[12] ={0}, subopt_value[64] = {0} , mode[8] = {0} ;
    int num_read;
    char buf[64];
    int opt_len = 0;   //Total characters read
    int subopt;
    size_t len;

    *options = 0;

    if ((fp = fopen(VENDOR_SPEC_FILE, "ra")) != NULL) {
        while ((num_read = fscanf(fp, "%7s %11s %63s", mode, subopt_num, subopt_value)) == 3) {
            if (length - opt_len < 6) {
                DBG_PRINT("%s: Too many options\n", __FUNCTION__ );
                fclose(fp);   //CID 61631 : Resource leak
                return -1;
            }

            if ( ( strcmp(mode,"DOCSIS") == 0 ) && ( strcmp (ethWanMode,"true") == 0) )
            {
                continue;
            }

            if ( ( strcmp(mode,"ETHWAN") == 0 ) && ( strcmp (ethWanMode,"false") == 0) )
            {
                continue;
            }

            //Print the option number
            if (strcmp(subopt_num, "SUBOPTION1") == 0) {
                if (!verifyBufferSpace(length, opt_len, 2)) {
                    fclose(fp);
                    return -1;
                }
                opt_len += sprintf(options + opt_len, "01");
            }
            else if (strcmp(subopt_num, "SUBOPTION2") == 0) {
                if (!verifyBufferSpace(length, opt_len, 2)) {
                    fclose(fp);
                    return -1;
                }
                opt_len += sprintf(options + opt_len, "02");
            }
            else if (strcmp(subopt_num, "SUBOPTION3") == 0) {
                if (!verifyBufferSpace(length, opt_len, 2)) {
                    fclose(fp);
                    return -1;
                }
                opt_len += sprintf(options + opt_len, "03");
            }
            else {
                DBG_PRINT( "%s: Invalid suboption\n", __FUNCTION__ );
                fclose(fp);
                return -1;
            }

            //Print the length of the sub-option value
            if (!verifyBufferSpace(length, opt_len, 2)) {
                fclose(fp);
                return -1;
            }
            opt_len += sprintf(options + opt_len, "%02x", strlen(subopt_value));

            //Print the sub-option value in hex
            opt_len = writeTOHexFromAscii(options, length, opt_len, subopt_value);
            if (opt_len == 0) {
                fclose(fp);
                return -1;
            }
        } //while

        fclose(fp);

        if ((num_read != EOF) && (num_read != 3)) {
            DBG_PRINT("%s: Error parsing file\n", __FUNCTION__);
            return -1;
        }
    }
    else {
        DBG_PRINT("%s: Cannot read %s\n", __FUNCTION__, VENDOR_SPEC_FILE);
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

    /*
       Sub-option code 5 - Hardware version
    */
    if (platform_hal_GetHardwareVersion (buf) == RETURN_OK)
    {
        subopt = 5;
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

    /*
       Sub-option code 6 - Software version (must match SW version field in SNMP MIB object sysDescr)
    */
    if (platform_hal_GetSoftwareVersion (buf, sizeof(buf)) == RETURN_OK)
    {
        subopt = 6;
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

    /*
       Sub-option code 7 - Boot ROM version (aka Bootloader version)
    */
    if (platform_hal_GetBootloaderVersion (buf, sizeof(buf)) == RETURN_OK)
    {
        subopt = 7;
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

    /*
       Sub-option code 8 - OUI
    */
    subopt = 8;
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
       Sub-option code 9 - Model Number
    */
    if (platform_hal_GetModelName(buf) == RETURN_OK)
    {
        subopt = 9;
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

    /*
       Sub-option code 10 - Vendor Name
    */
    subopt = 10;
    len = strlen (CONFIG_VENDOR_NAME);
    if (len > 0)
    {
        if ((len > 0xFF) || !verifyBufferSpace(length, opt_len, 2 + 2 + (2 * len))) {
            return -1;
        }
        opt_len += sprintf(options + opt_len, "%02x%02x", subopt, len);
        opt_len = writeTOHexFromAscii(options, length, opt_len, CONFIG_VENDOR_NAME);
    }

    /*
       Sub-option code 15 - device eSAFE with cfg file encapsulation
    */
    subopt = 15;
    len = strlen ("EROUTER");
    if (len > 0)
    {
        if ((len > 0xFF) || !verifyBufferSpace(length, opt_len, 2 + 2 + (2 * len))) {
            return -1;
        }
        opt_len += sprintf(options + opt_len, "%02x%02x", subopt, len);
        opt_len = writeTOHexFromAscii(options, length, opt_len, "EROUTER");
    }

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
            add_dhcpv4_opt_to_list(req_opt_list, DHCPV4_OPT_125, NULL);
            add_dhcpv4_opt_to_list(req_opt_list, DHCPV4_OPT_43, NULL);

            syscfg_get(NULL, "management_wan_enabled", wanmg_enable, sizeof(wanmg_enable));
            if (strcmp(wanmg_enable, "1") != 0)
            {
                char options[VENDOR_OPTIONS_LENGTH];

                add_dhcpv4_opt_to_list(send_opt_list, DHCPV4_OPT_60, "dslforum.org");
                prepare_dhcp43_optvalue(options, sizeof(options), "true");
                add_dhcpv4_opt_to_list(send_opt_list, DHCPV4_OPT_43, options);
            }
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
