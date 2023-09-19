#include "dhcp_client_utils.h"
#include "ti_udhcpc_client_utils.h"

#ifdef DHCPV4_CLIENT_TI_UDHCPC

pid_t start_ti_udhcpc (dhcp_params * params)
{
    if (params == NULL)
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    char buff[BUFLEN_256] = {0};

    snprintf(buff, sizeof(buff), "-plugin /lib/libert_dhcpv4_plugin.so -i %s -H DocsisGateway -p /var/run/eRT_ti_udhcpc_%s.pid -B -b 4", params->ifname, params->ifname);

    pid_t ret = start_exe(TI_UDHCPC_CLIENT_PATH, buff);
    if (collect_waiting_process(ret, TI_UDHCPC_TERMINATE_TIMEOUT) != SUCCESS)
    {
        DBG_PRINT("%s %d: unable to collect pid for %d.\n", __FUNCTION__, __LINE__, ret);
    }

    DBG_PRINT("%s %d: Started ti_udhcpc. returning pid..\n", __FUNCTION__, __LINE__);
    return get_process_pid (TI_UDHCPC_CLIENT, NULL, true);


}

int stop_ti_udhcpc (dhcp_params * params)
{
    if ((params == NULL) || (params->ifname == NULL))
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    pid_t pid = 0;
    pid = get_process_pid(TI_UDHCPC_CLIENT, params->ifname, false);

    if (pid <= 0)
    {
        DBG_PRINT("%s %d: unable to get pid of %s\n", __FUNCTION__, __LINE__, TI_UDHCPC_CLIENT);
        return FAILURE;
    }
    if (signal_process(pid, SIGTERM) != RETURN_OK)
    {
        DBG_PRINT("%s %d: unable to send signal to pid %d\n", __FUNCTION__, __LINE__, pid);
        return FAILURE;
    }

    return SUCCESS;

}

#endif  // DHCPV4_CLIENT_TI_UDHCPC
