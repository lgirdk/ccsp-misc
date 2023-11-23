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

#include <stdlib.h>
#include <syscfg/syscfg.h>

#include "dibbler_client_utils.h"

#ifdef DHCPV6_CLIENT_DIBBLER

#define LOCALHOST         "127.0.0.1"
#define MAPT_SYSEVENT_NAME "mapt_evt_handler"
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
#define SYSCFG_MAPT_FEATURE_ENABLE   "MAPT_Enable"
#endif

extern token_t dhcp_sysevent_token;
extern int dhcp_sysevent_fd;


#if 0
static int copy_file (char * src, char * dst)
{
    if ((src == NULL) || (dst == NULL))
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    FILE * fin = NULL;
    FILE * fout = NULL;

    fout = fopen(dst, "wb");
    if (fout == NULL)
    {
        DBG_PRINT("%s %d: failed to open file %s\n", __FUNCTION__, __LINE__, dst);
        return FAILURE;
    }
    
    fin = fopen(src, "r");

    if (fin == NULL)
    {
        DBG_PRINT("%s %d: failed to open file %s\n", __FUNCTION__, __LINE__, src);
        fclose (fout);
        return FAILURE;
    }

    ssize_t nread;
    size_t len = 0;
    char *line = NULL;

    while ((nread = getline(&line, &len, fin)) != -1) 
    {
        fwrite(line, nread, 1, fout);
    }

    if (line)
    {
        free(line);
    }
    fclose(fin);
    fclose(fout);

    DBG_PRINT ("%s %d: successfully copied content from %s to %s\n", __FUNCTION__, __LINE__, src, dst);
    return SUCCESS;

}

/*
 * dibbler_client_prepare_config ()
 * @description: This function will construct conf file to configure dibbler-client
 * @params     : req_opt_list - input list of DHCPv6 GET options
                 send_opt_list - input list of DHCPv6 send options
                 
 * @return     : SUCCESS if config file written successfully, else returns FAILURE
 *
 */
static int dibbler_client_prepare_config (dibbler_client_info * client_info)
{
    if (client_info == NULL)
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    dhcp_params * param = client_info->if_param;
    dhcp_opt_list * req_opt_list = client_info->req_opt_list;
    dhcp_opt_list * send_opt_list = client_info->send_opt_list;

    if (param == NULL)
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
    char mapt_feature_enable[BUFLEN_16] = {0};
#endif

    FILE * fout;
    fout = fopen(DIBBLER_TMP_CONFIG_FILE, "w+");

    if (fout == NULL)
    {
        DBG_PRINT("%s %d: unable to open tmp file: %s\n", __FUNCTION__, __LINE__, DIBBLER_TMP_CONFIG_FILE);
        return FAILURE;
    }

    char buff[BUFLEN_128] = {0};
    // write common config
    snprintf(buff, sizeof(buff), "script \"%s\"\n", DIBBLER_SCRIPT_FILE);
    fputs(buff, fout);
    fputs(DIBBLER_LOG_CONFIG, fout);
    fputs(DIBBLER_DUID_LL_CONFIG, fout);


    // interface specific config
    snprintf(buff, sizeof(buff), "iface %s {\n", param->ifname);
    fputs(buff, fout);

    bool option20Found = 0;
    dhcp_opt_list * opt_list = NULL;
    char args [BUFLEN_128] = {0};

    if (param->ifType == WAN_LOCAL_IFACE)
    {
        // request option
        opt_list = req_opt_list;
        while (opt_list)
        {
            memset (&args, 0, BUFLEN_128);

            if (opt_list->dhcp_opt == DHCPV6_OPT_5)
            {
                snprintf (args, BUFLEN_128, "\n\t%s \n", "ia");
                fputs(args, fout);
            }
            else if (opt_list->dhcp_opt == DHCPV6_OPT_23)
            {
                snprintf (args, BUFLEN_128, "\n\t%s \n", "option dns-server");
                fputs(args, fout);
            }
            else if (opt_list->dhcp_opt == DHCPV6_OPT_25)
            {
                snprintf (args, BUFLEN_128, "\n\t%s \n", "pd");
                fputs(args, fout);
            }
            else if (opt_list->dhcp_opt == DHCPV6_OPT_24)
            {
                snprintf (args, BUFLEN_128, "\n\t%s \n", "option domain");
                fputs(args, fout);
            }
            else if (opt_list->dhcp_opt == DHCPV6_OPT_95)
            {
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
                if (syscfg_get(NULL, SYSCFG_MAPT_FEATURE_ENABLE, mapt_feature_enable, sizeof(mapt_feature_enable)) == 0)
                {
                    if (strncmp(mapt_feature_enable, "true", 4) == 0)
                    {
#endif
                        snprintf (args, BUFLEN_128, "\n\toption 00%d hex \n", opt_list->dhcp_opt);
                        fputs(args, fout);
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
                    }
                }
#endif
            }
            else if (opt_list->dhcp_opt == DHCPV6_OPT_64)
            {
                fputs("\n\toption aftr\n", fout);
            }
            else
            {
                snprintf (args, BUFLEN_128, "\n\toption 00%d hex \n", opt_list->dhcp_opt);
                fputs(args, fout);
            }
            opt_list = opt_list->next;
        }

        //send option list
        opt_list = send_opt_list;
        while (opt_list)
        {
            memset (&args, 0, BUFLEN_128);
            if (opt_list->dhcp_opt == DHCPV6_OPT_15)
            {
                char str[32]={0};
                char option15[100]={0};
                char temp[16]={0};

                strncpy(str,opt_list->dhcp_opt_val,strlen(opt_list->dhcp_opt_val)+1);

                snprintf(temp, 8, "0x%04X",(int)strlen(str)+1);
                strncat(option15,temp,8);

                for(int i=0; i<(int)strlen(str)+1; i++)
                {
                    snprintf(temp, 3, "%02X",str[i]);
                    strncat(option15,temp,3);
                }

                snprintf (args, BUFLEN_128, "\n\toption 00%d hex %s\n", opt_list->dhcp_opt,option15 );
                fputs(args, fout);
            }
            else if (opt_list->dhcp_opt == DHCPV6_OPT_20)
            {
                option20Found = 1;
            }
            else if (opt_list->dhcp_opt == DHCPV6_OPT_25)
            {
                snprintf (args, sizeof(args), "\n\tpd  %s\n", opt_list->dhcp_opt_val);
                fputs(args, fout);
            }
            else if (opt_list->dhcp_opt_val != NULL)
            {
                snprintf (args, sizeof(args), "\n\toption 00%d hex %s\n", opt_list->dhcp_opt, opt_list->dhcp_opt_val);
                fputs(args, fout);
            }
            else
            {
                snprintf (args, BUFLEN_128, "\n\toption 00%d hex \n", opt_list->dhcp_opt);
                fputs(args, fout);
            }
            opt_list = opt_list->next;
        }

    }

    fputs("\n}", fout);
    fputs("skip-confirm\n", fout);
    fputs("downlink-prefix-ifaces \"brlan0\"\n", fout);

    if(option20Found)
    {
        snprintf (args, BUFLEN_128, "\n%s\n", "reconfigure-accept 1");
        fputs(args, fout);
    }
    fclose(fout);

    // write the config path into the buffer
    snprintf(client_info->config_path, sizeof(client_info->config_path), "%s%s", DIBBLER_DFT_PATH, param->ifname);

    /* CID 256906  Time of check time of use & CID 256902  Unchecked return value from library */
    if (mkdir(client_info->config_path, 0644) == 0)
    {
        DBG_PRINT ("%s %d: created directory %s\n", __FUNCTION__, __LINE__, client_info->config_path);
    }
    else
    {
        DBG_PRINT ("%s %d: Directory already exists / not created  %s\n", __FUNCTION__, __LINE__, client_info->config_path);
    }

    // copy the file to new location
    char file_path[BUFLEN_128] = {0};
    int ret = snprintf(file_path, sizeof(file_path), "%s/%s", client_info->config_path, DIBBLER_CLIENT_CONFIG_FILE);
    if (ret <= 0)
    {
        DBG_PRINT("%s %d: unable to contruct filepath\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    if (copy_file (DIBBLER_TMP_CONFIG_FILE, file_path) != SUCCESS)
    {
        DBG_PRINT("%s %d: unable to copy %s to %s due to %s\n", __FUNCTION__, __LINE__, DIBBLER_TEMPLATE_CONFIG_FILE, file_path, strerror(errno));
        return FAILURE;
    }

    // dibber-client uses default config to generate DUID, so linking default file to tmp file
    link (DIBBLER_TMP_CONFIG_FILE, DIBBLER_DEFAULT_CONFIG_FILE);

    return SUCCESS;

}
#endif

/*
 * start_dibbler ()
 * @description: This function will build udhcpc request/send options and start dibbler client program.
 * @params     : params - input parameter to pass interface specific arguments
 *               v4_req_opt_list - list of DHCP REQUEST options
 *               v4_send_opt_list - list of DHCP SEND options
 * @return     : returns the pid of the udhcpc client program else return error code on failure
 *
 */
pid_t start_dibbler (dhcp_params * params, dhcp_opt_list * req_opt_list, dhcp_opt_list * send_opt_list)
{

    if (params == NULL)
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    dibbler_client_info client_info;

    memset (&client_info, 0, sizeof(dibbler_client_info));
    client_info.if_param = params;
    client_info.req_opt_list = req_opt_list;
    client_info.send_opt_list = send_opt_list;

#if 0
    if ((dibbler_client_prepare_config(&client_info) != SUCCESS))
    {
        DBG_PRINT("%s %d: Unable to get DHCPv6 REQ OPT.\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }
#endif

    pid_t pid;
    char custom_cfg_path[BUFLEN_128];
    char cmd_args[BUFLEN_256] = {0};

    snprintf(custom_cfg_path, sizeof(custom_cfg_path), DIBBLER_LG_PATH, params->ifname);
    if (access(custom_cfg_path, F_OK))
    {
        custom_cfg_path[0] = '\0'; /* custom dibbler cfg is not enabled in the platform */
        DBG_PRINT("%s %d: Starting dibbler\n", __FUNCTION__, __LINE__);
        snprintf(cmd_args, sizeof(cmd_args), "%s", DIBBLER_CLIENT_RUN_CMD);
    }
    else
    {
        DBG_PRINT("%s %d: Starting dibbler with custom config %s\n", __FUNCTION__, __LINE__, custom_cfg_path);
        snprintf(cmd_args, sizeof(cmd_args), "%s -w %s", DIBBLER_CLIENT_RUN_CMD, custom_cfg_path);
    }


    pid_t ret = start_exe(DIBBLER_CLIENT_PATH, cmd_args);
    if (ret <= 0)
    {
        DBG_PRINT("%s %d: unable to start dibbler-client %d.\n", __FUNCTION__, __LINE__, ret);
        return FAILURE;
    }

    //dibbler-client will demonize a child thread during start, so we need to collect the exited main thread
    if (collect_waiting_process(ret, DIBBLER_CLIENT_TERMINATE_TIMEOUT) != SUCCESS)
    {
        DBG_PRINT("%s %d: unable to collect pid for %d.\n", __FUNCTION__, __LINE__, ret);
    }

    pid = get_process_pid (DIBBLER_CLIENT, custom_cfg_path[0] != '\0' ? custom_cfg_path : NULL, true);
    DBG_PRINT("%s %d: Started dibbler-client. returning pid (%d)..\n", __FUNCTION__, __LINE__, pid);
    return pid;
}

/*
 * stop_dibbler ()
 * @description: This function will stop dibbler instance that is running for interface name passed in params.ifname
 * @params     : params - input parameter to pass interface specific arguments
 * @return     : returns the SUCCESS or FAILURE
 *
 */
int stop_dibbler (dhcp_params * params)
{
    if ((params == NULL) || (params->ifname == NULL))
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    pid_t pid = 0;
    char cmdargs[BUFLEN_256];
    char custom_cfg_path[BUFLEN_128];

    snprintf(custom_cfg_path, sizeof(custom_cfg_path), DIBBLER_LG_PATH, params->ifname);
    if (access(custom_cfg_path, F_OK))
    {
        custom_cfg_path[0] = '\0';
        snprintf(cmdargs, sizeof(cmdargs), DIBBLER_CLIENT " stop");
    }
    else
    {
        snprintf(cmdargs, sizeof(cmdargs), DIBBLER_CLIENT " stop -w %s", custom_cfg_path);
    }

    pid = get_process_pid(DIBBLER_CLIENT, custom_cfg_path[0] != '\0' ? custom_cfg_path : NULL, false);
    if (pid <= 0)
    {
        DBG_PRINT("%s %d: unable to get pid of %s\n", __FUNCTION__, __LINE__, DIBBLER_CLIENT);
        return FAILURE;
    }

    if (system(cmdargs) != 0)
    {
        return FAILURE;
    }

    unsigned int waitTime = DIBBLER_CLIENT_TERMINATE_TIMEOUT;
    struct stat sts;
    char cmd[BUFLEN_128] = {0};
    snprintf(cmd, sizeof(cmd), "/proc/%d", pid);
    while (waitTime > 0)
    {
        // check if pid is still present
        if (stat(cmd, &sts) == -1 && errno == ENOENT) {
            // process doesn't exist
            DBG_PRINT("%s %d: dibbler-client exited\n", __FUNCTION__, __LINE__);
            break;
        }
        
        usleep(DIBBLER_CLIENT_TERMINATE_INTERVAL * USECS_IN_MSEC);
        waitTime -= DIBBLER_CLIENT_TERMINATE_INTERVAL;
    }
    if (waitTime <= 0)
    {
        DBG_PRINT("%s %d: Waited for %d millisec, dibbler-client still running\n", __FUNCTION__, __LINE__, DIBBLER_CLIENT_TERMINATE_TIMEOUT);
        return FAILURE;
    }

    return SUCCESS;

}


#endif  // DHCPV6_CLIENT_DIBBLER	
