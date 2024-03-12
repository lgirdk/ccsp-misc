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

    char args [BUFLEN_16] = {0};

    while (req_opt_list)
    {
        memset (&args, 0, BUFLEN_16);
        if (req_opt_list->dhcp_opt == DHCPV4_OPT_2)
	    {
            /* CID 189999 Calling risky function */
            snprintf(args, (BUFLEN_16-1),"-O timezone ");
        }
        else if (req_opt_list->dhcp_opt == DHCPV4_OPT_42)
        {
            snprintf(args, (BUFLEN_16-1),"-O ntpsrv ");
        }
        else
        {
            snprintf (args, (BUFLEN_16-1), "-O %d ", req_opt_list->dhcp_opt);
        }
        req_opt_list = req_opt_list->next;

        if(strlen(buff) < (buff_size - BUFLEN_16))
        {
            strncat(buff, args, BUFLEN_16 - 1);
        }
        else
        {
            DBG_PRINT("%s %d: Insufficient buff size \n", __FUNCTION__, __LINE__);
        }
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

    char args [BUFLEN_128] = {0};
    while ((send_opt_list != NULL) && (send_opt_list->dhcp_opt_val != NULL))
    {
        memset (&args, 0, BUFLEN_128);
        if (send_opt_list->dhcp_opt == DHCPV4_OPT_60)
        {
            // Option 60 - Vendor Class Identifier has udhcp cmd line arg "-V <option-str>"
            snprintf (args, BUFLEN_128, "-V %s ", send_opt_list->dhcp_opt_val);
        }
        else
        {
/*
            char * buffer = ascii_to_hex (send_opt_list->dhcp_opt_val, strlen(send_opt_list->dhcp_opt_val));
            if (buffer != NULL)
            {
                snprintf (args, BUFLEN_128, "-x 0x%02X:%s ", send_opt_list->dhcp_opt, buffer);
                free(buffer);
            }
*/
            snprintf (args, BUFLEN_128, "-x 0x%02X:%s ", send_opt_list->dhcp_opt, send_opt_list->dhcp_opt_val);
        }
        send_opt_list = send_opt_list->next;
        /* CID 189996 Calling risky function */
        if(strlen(buff) < (buff_size - BUFLEN_128))
        {
            strncat(buff, args, BUFLEN_128 - 1);
        }
        else
        {
            DBG_PRINT("%s %d: Insufficient buff size \n", __FUNCTION__, __LINE__);
        }
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
     if ((buff == NULL) || (params == NULL))
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    // Add -i <ifname>
    if (params->ifname != NULL)
    {
        char ifname_opt[BUFLEN_16] = {0};
        snprintf (ifname_opt, sizeof(ifname_opt), "-i %s ", params->ifname);
        /* CID 189992 Calling risky function */
        if ((strlen(ifname_opt) < BUFLEN_16) && (strlen(buff) < (buff_size - BUFLEN_16)) )
        {
            strncat (buff, ifname_opt,BUFLEN_16-1);
        }
        else
        {
            DBG_PRINT("%s %d: Error in copying ifname \n", __FUNCTION__, __LINE__);
            return FAILURE;
        }

        // Add -p <pidfile>
        char pidfile[BUFLEN_32] = {0};
        snprintf (pidfile, sizeof(pidfile), UDHCP_PIDFILE_PATTERN , params->ifname);
        if ((strlen(pidfile) < BUFLEN_32) && (strlen(buff) < (buff_size - BUFLEN_32)) )
        {
            strncat (buff, pidfile, BUFLEN_32-1 );
        }
        else
        {
            DBG_PRINT("%s %d: Error in copying pidfile \n", __FUNCTION__, __LINE__);
            return FAILURE;
        }

    }

    // Add -s <servicefile>
    char servicefile[BUFLEN_32] = {0};
#ifdef UDHCPC_SCRIPT_FILE
    snprintf (servicefile, sizeof(servicefile), "-s %s ", UDHCPC_SERVICE_SCRIPT_FILE);
#else
    snprintf (servicefile, sizeof(servicefile), "-s %s ", UDHCPC_SERVICE_EXE);
#endif

    if(strlen(buff) < (buff_size - BUFLEN_32))
    {
        strncat (buff, servicefile, BUFLEN_32-1);
    }
    else
    {
        DBG_PRINT("%s %d: Error in copying servicefile \n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    if(strlen(buff) > (buff_size - BUFLEN_8))
    {
        DBG_PRINT("%s %d: Insufficient buffer size \n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    // Add udhcpc process behavior
#ifdef UDHCPC_RUN_IN_FOREGROUND
    // udhcpc will run in foreground
    strncat (buff, "-f ", BUFLEN_4);
#elif UDHCPC_RUN_IN_BACKGROUND
    // udhcpc will run in background if lease not obtained
    strncat (buff, "-b ", BUFLEN_4);
#elif UDHCPC_EXIT_AFTER_LEAVE_FAILURE
    // exit if lease is not obtained
    strncat (buff, "-n ", BUFLEN_4);
#endif
#ifdef UDHCPC_TX_RELEASE_ON_EXIT
    // send release before exit
    strncat (buff, "-R ", BUFLEN_4);
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

    char buff [BUFLEN_512] = {0};

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

    pid = start_exe(UDHCPC_CLIENT_PATH, buff);

#ifdef UDHCPC_RUN_IN_BACKGROUND
    // udhcpc-client will demonize a child thread during start, so we need to collect the exited main thread
    if (collect_waiting_process(pid, UDHCPC_TERMINATE_TIMEOUT) != SUCCESS)
    {
        DBG_PRINT("%s %d: unable to collect pid for %d.\n", __FUNCTION__, __LINE__, pid);
    }

    DBG_PRINT("%s %d: Started dibbler-client. returning pid..\n", __FUNCTION__, __LINE__);
    pid = get_process_pid (UDHCPC_CLIENT, NULL, true);
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

#ifdef UDHCPC_TX_RELEASE_ON_EXIT
#if defined(_PLATFORM_RASPBERRYPI_)
    //In RPI, udhcpc is not getting terminated after sending unicast release packet with SIGUSR2, thus SIGTERM is used
    if (signal_process(pid, SIGTERM) != RETURN_OK)
#else
    if (signal_process(pid, (params->is_release_required)?(SIGUSR2):(SIGTERM)) != RETURN_OK)
#endif
    {
        DBG_PRINT("%s %d: unable to send signal to pid %d\n", __FUNCTION__, __LINE__, pid);
        return FAILURE;
    }
#else
    /*TODO:
     *Should be Removed once MAPT Unified and done in udhcp Demon to relase and kill Demon on SIGUSR2.
     */
    if (params->is_release_required)
    {
        if (signal_process(pid, SIGUSR2) != RETURN_OK)
        {
            DBG_PRINT("%s %d: unable to send signal to pid %d\n", __FUNCTION__, __LINE__, pid);
            return FAILURE;
        }
        DBG_PRINT("%s %d: Successfully Relased V4 IP Address %d\n", __FUNCTION__, __LINE__, pid);
    }
    sleep(1);
    if (signal_process(pid, SIGTERM) != RETURN_OK)
    {
        DBG_PRINT("%s %d: unable to send signal to pid %d\n", __FUNCTION__, __LINE__, pid);
        return FAILURE;
    }
    DBG_PRINT("%s %d: Successfully Exited V4 Demon %d\n", __FUNCTION__, __LINE__, pid);
#endif  // UDHCPC_TX_RELEASE_ON_EXIT 

    return collect_waiting_process(pid, UDHCPC_TERMINATE_TIMEOUT);

}
#endif  // DHCPV4_CLIENT_UDHCPC

