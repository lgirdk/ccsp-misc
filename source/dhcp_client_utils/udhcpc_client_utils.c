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

#ifdef DHCPV4_CLIENT_UDHCPC

#define DHCPV4_OPT_2  2  // time zone offset

/*
 * udhcpc_get_req_options ()
 * @description: This function will construct a buffer with all the udhcpc REQUEST options
 * @params     : buff - output buffer to pass all REQUEST options
 *               req_opt_list - input list of DHCP REQUEST options
 *               buff_size - size of output buffer
 * @return     : return a buffer that has -O <REQ-DHCP-OPT>
 *
 */
static int udhcpc_get_req_options (char * buff, size_t buff_size, dhcp_opt_list * req_opt_list)
{
    int n = 0;
    size_t cur_pos;

    if (buff == NULL)
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    if (req_opt_list == NULL)
    {
        DBG_PRINT("%s %d: No req option sent to udhcpc.\n", __FUNCTION__, __LINE__);
        return SUCCESS;
    }

    cur_pos = strlen(buff);
    while (req_opt_list)
    {
        if (req_opt_list->dhcp_opt == DHCPV4_OPT_2)
	    {
            /* CID 189999 Calling risky function */
            n = snprintf(buff + cur_pos, buff_size - cur_pos, "-O timezone ");
        }
        else if (req_opt_list->dhcp_opt == DHCPV4_OPT_42)
        {
            n = snprintf(buff + cur_pos, buff_size - cur_pos, "-O ntpsrv ");
        }
        else
        {
            n = snprintf (buff + cur_pos, buff_size - cur_pos, "-O %d ", req_opt_list->dhcp_opt);
        }

        if (n < 0 || n >= buff_size - cur_pos)
        {
            DBG_PRINT("%s %d: Insufficient buff size or snprintf error\n", __FUNCTION__, __LINE__);
            return FAILURE;
        }

        cur_pos += n;
        req_opt_list = req_opt_list->next;
    }

    DBG_PRINT("%s %d: get req args - %s\n", __FUNCTION__, __LINE__, buff);
    return SUCCESS;

}

/*
 * udhcpc_get_send_options ()
 * @description: This function will construct a buffer with all the udhcpc SEND options
 * @params     : buff - output buffer to pass all SEND options
 *               req_opt_list - input list of DHCP SEND options
 *               buff_size - size of output buffer
 * @return     : return a buffer that has -x <SEND-DHCP-OPT:SEND-DHCP-OPT-VALUE> (or -V <SEND-DHCP-OPT-VALUE> for option60)
 *
 */
static int udhcpc_get_send_options (char * buff, size_t buff_size, dhcp_opt_list * send_opt_list)
{
    int n = 0;
    size_t cur_pos;

    if (buff == NULL)
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    if (send_opt_list == NULL)
    {
        DBG_PRINT("%s %d: No send option sent to udhcpc.\n", __FUNCTION__, __LINE__);
        return SUCCESS;
    }

    cur_pos = strlen(buff);
    while ((send_opt_list != NULL) && (send_opt_list->dhcp_opt_val != NULL))
    {
        if (send_opt_list->dhcp_opt == DHCPV4_OPT_60)
        {
            // Option 60 - Vendor Class Identifier has udhcp cmd line arg "-V <option-str>"
            n = snprintf(buff + cur_pos, buff_size - cur_pos, "-V %s ", send_opt_list->dhcp_opt_val);
        }
        else if (send_opt_list->dhcp_opt == DHCPV4_OPT_125)
        {
            n = snprintf(buff + cur_pos, buff_size - cur_pos, "-x %d:%s ", send_opt_list->dhcp_opt, send_opt_list->dhcp_opt_val);
        }
        else if (send_opt_list->dhcp_opt == DHCPV4_OPT_61)
        {
            n = snprintf(buff + cur_pos, buff_size - cur_pos, "-x 0x%02X:%s ", send_opt_list->dhcp_opt, send_opt_list->dhcp_opt_val);
        }
        else if (send_opt_list->dhcp_opt == DHCPV4_OPT_43)
        {
            n = snprintf(buff + cur_pos, buff_size - cur_pos, "-x %s ", send_opt_list->dhcp_opt_val);
        }
        else
        {
/*
            char * buffer = ascii_to_hex (send_opt_list->dhcp_opt_val, strlen(send_opt_list->dhcp_opt_val));
            if (buffer != NULL)
            {
                snprintf (buff + cur_pos, buff_size - cur_pos, "-x 0x%02X:%s ", send_opt_list->dhcp_opt, buffer);
                free(buffer);
            }
*/
            n = snprintf (buff + cur_pos, buff_size - cur_pos, "-x 0x%02X:%s ", send_opt_list->dhcp_opt, send_opt_list->dhcp_opt_val);
        }

        if (n < 0 || n >= buff_size - cur_pos)
        {
            DBG_PRINT("%s %d: Insufficient buff size or snprintf error\n", __FUNCTION__, __LINE__);
            return FAILURE;
        }

        cur_pos += n;
        send_opt_list = send_opt_list->next;
    }

    return SUCCESS;
}

/*
 * udhcpc_get_other_args ()
 * @description: This function will construct a buffer with all other udhcpc options
 * @params     : buff - output buffer to pass all SEND options
 *               params - input parameters to udhcpc like interface
 *               buff_size - size of output buffer
 * @return     : return a buffer that has -i, -p, -s, -b/f/n options
 *
 */
static int udhcpc_get_other_args (char * buff, size_t buff_size, dhcp_params * params)
{
    int n = 0;
    size_t cur_pos;

     if ((buff == NULL) || (params == NULL))
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    cur_pos = strlen(buff);

    // Add -i <ifname>
    if (params->ifname != NULL)
    {
        n = snprintf(buff + cur_pos, buff_size - cur_pos, "-i %s ", params->ifname);
        if (n < 0 || n >= buff_size - cur_pos)
        {
            DBG_PRINT("%s %d: Error in copying ifname \n", __FUNCTION__, __LINE__);
            return FAILURE;
        }
        cur_pos += n;

        // Add -p <pidfile>
        n = snprintf(buff + cur_pos, buff_size - cur_pos, UDHCP_PIDFILE_PATTERN , params->ifname);
        if (n < 0 || n >= buff_size - cur_pos)
        {
            DBG_PRINT("%s %d: Error in copying pidfile \n", __FUNCTION__, __LINE__);
            return FAILURE;
        }
        cur_pos += n;

    }

    // Add -s <servicefile>
#ifdef UDHCPC_SCRIPT_FILE
    n = snprintf(buff + cur_pos, buff_size - cur_pos, "-s %s ", UDHCPC_SERVICE_SCRIPT_FILE);
#else
    n = snprintf(buff + cur_pos, buff_size - cur_pos, "-s %s ", UDHCPC_SERVICE_EXE);
#endif
    if (n < 0 || n >= buff_size - cur_pos)
    {
        DBG_PRINT("%s %d: Error in copying servicefile \n", __FUNCTION__, __LINE__);
        return FAILURE;
    }
    cur_pos += n;

    n = snprintf(buff + cur_pos, buff_size - cur_pos, "-S ");
    if (n < 0 || n >= buff_size - cur_pos)
    {
        DBG_PRINT("%s %d: Error in adding -S option \n", __FUNCTION__, __LINE__);
        return FAILURE;
    }
    cur_pos += n;

    n = snprintf(buff + cur_pos, buff_size - cur_pos, "-vvv ");
    if (n < 0 || n >= buff_size - cur_pos)
    {
        DBG_PRINT("%s %d: Error in adding -vvv option \n", __FUNCTION__, __LINE__);
        return FAILURE;
    }
    cur_pos += n;

    // Add udhcpc process behavior
#ifdef UDHCPC_RUN_IN_FOREGROUND
    // udhcpc will run in foreground
    n = snprintf(buff + cur_pos, buff_size - cur_pos, "-f ");
    if (n < 0 || n >= buff_size - cur_pos)
    {
        DBG_PRINT("%s %d: Error in adding -f option \n", __FUNCTION__, __LINE__);
        return FAILURE;
    }
    cur_pos += n;
#elif UDHCPC_RUN_IN_BACKGROUND
    // udhcpc will run in background if lease not obtained
    n = snprintf(buff + cur_pos, buff_size - cur_pos, "-b ");
    if (n < 0 || n >= buff_size - cur_pos)
    {
        DBG_PRINT("%s %d: Error in adding -b option \n", __FUNCTION__, __LINE__);
        return FAILURE;
    }
    cur_pos += n;
#elif UDHCPC_EXIT_AFTER_LEAVE_FAILURE
    // exit if lease is not obtained
    n = snprintf(buff + cur_pos, buff_size - cur_pos, "-n ");
    if (n < 0 || n >= buff_size - cur_pos)
    {
        DBG_PRINT("%s %d: Error in adding -n option \n", __FUNCTION__, __LINE__);
        return FAILURE;
    }
    cur_pos += n;
#endif
#ifdef UDHCPC_TX_RELEASE_ON_EXIT
    // send release before exit
    n = snprintf(buff + cur_pos, buff_size - cur_pos, "-R ");
    if (n < 0 || n >= buff_size - cur_pos)
    {
        DBG_PRINT("%s %d: Error in adding -R option \n", __FUNCTION__, __LINE__);
        return FAILURE;
    }
    cur_pos += n;
#endif  // UDHCPC_TX_RELEASE_ON_EXIT

    return SUCCESS;
}

/*
 * start_udhcpc ()
 * @description: This function will build udhcpc request/send options and start udhcpc client program.
 * @params     : params - input parameter to pass interface specific arguments
 *               req_opt_list - list of DHCP REQUEST options
 *               send_opt_list - list of DHCP SEND options
 * @return     : returns the pid of the udhcpc client program else return error code on failure
 *
 */
pid_t start_udhcpc (dhcp_params * params, dhcp_opt_list * req_opt_list, dhcp_opt_list * send_opt_list)
{
    if ((params == NULL) || (params->ifname == NULL))
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    pid_t pid = 0;
    pid = get_process_pid(UDHCPC_CLIENT, params->ifname, false);

    if (pid > 0)
    {
        DBG_PRINT("%s %d: another instance of %s runing on %s\n", __FUNCTION__, __LINE__, UDHCPC_CLIENT, params->ifname);
        return FAILURE;
    }

    char buff[1024] = {0};

    DBG_PRINT("%s %d: Constructing REQUEST option args to udhcpc.\n", __FUNCTION__, __LINE__);
    if ((req_opt_list != NULL) && (udhcpc_get_req_options(buff, sizeof(buff), req_opt_list)) != SUCCESS)
    {
        DBG_PRINT("%s %d: Unable to get DHCPv4 REQ OPT.\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    DBG_PRINT("%s %d: Constructing SEND option args to udhcpc.\n", __FUNCTION__, __LINE__);
    if ((send_opt_list != NULL) && (udhcpc_get_send_options(buff, sizeof(buff), send_opt_list) != SUCCESS))
    {
        DBG_PRINT("%s %d: Unable to get DHCPv4 SEND OPT.\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    DBG_PRINT("%s %d: Constructing other option args to udhcpc.\n", __FUNCTION__, __LINE__);
    if (udhcpc_get_other_args(buff, sizeof(buff), params) != SUCCESS)
    {
        DBG_PRINT("%s %d: Unable to get DHCPv4 SEND OPT.\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    DBG_PRINT("%s %d: Starting udhcpc.\n", __FUNCTION__, __LINE__);

    pid = start_exe(UDHCPC_CLIENT_PATH, buff, NULL);

#ifdef UDHCPC_RUN_IN_BACKGROUND
    // udhcpc-client will demonize a child thread during start, so we need to collect the exited main thread
    if (collect_waiting_process(pid, UDHCPC_TERMINATE_TIMEOUT) != SUCCESS)
    {
        DBG_PRINT("%s %d: unable to collect pid for %d\n", __FUNCTION__, __LINE__, pid);
    }

    pid = get_process_pid (UDHCPC_CLIENT, params->ifname, true);
    DBG_PRINT("%s %d: Started udhcpc, returning pid %d\n", __FUNCTION__, __LINE__, pid);
#endif

    return pid;

}

/*
 * stop_udhcpc ()
 * @description: This function will stop udhcpc instance that is running for interface name passed in params.ifname
 * @params     : params - input parameter to pass interface specific arguments
 * @return     : returns the SUCCESS or FAILURE
 *
 */
int stop_udhcpc (dhcp_params * params)
{
    if ((params == NULL) || (params->ifname == NULL))
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    pid_t pid = 0;
    char cmdarg[BUFLEN_32];

    snprintf(cmdarg, sizeof(cmdarg), "%s", params->ifname);
    pid = get_process_pid(UDHCPC_CLIENT, cmdarg, false);

    if (pid <= 0)
    {
        DBG_PRINT("%s %d: unable to get pid of %s\n", __FUNCTION__, __LINE__, UDHCPC_CLIENT);
        return FAILURE;
    }

    /* Fixme... */

    if (signal_process(pid, SIGTERM) != RETURN_OK)
    {
        DBG_PRINT("%s %d: unable to send signal to pid %d\n", __FUNCTION__, __LINE__, pid);
        return FAILURE;
    }

    return collect_waiting_process(pid, UDHCPC_TERMINATE_TIMEOUT);

}
#endif  // DHCPV4_CLIENT_UDHCPC

