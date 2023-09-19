#include "dhcp_client_utils.h"
#include "ti_dhcp6c_client_utils.h"

#ifdef DHCPv6_CLIENT_TI_DHCP6C

pid_t start_ti_dhcp6c (dhcp_params * params)
{
    if (params == NULL)
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    char buff[BUFLEN_256] = {0};

    snprintf(buff, sizeof(buff), "-i %s -p /var/run/%s_dhcp6c.pid -plugin /fss/gw/lib/libgw_dhcp6plg.so", params->ifname, params->ifname);

    pid_t ret = start_exe(TI_DHCP6C_CLIENT_PATH, buff);

    if (collect_waiting_process(ret, TI_DHCP6C_TERMINATE_TIMEOUT) != SUCCESS)
    {
        DBG_PRINT("%s %d: unable to collect pid for %d.\n", __FUNCTION__, __LINE__, ret);
    }

    DBG_PRINT("%s %d: Started ti_dhcp6c. returning pid..\n", __FUNCTION__, __LINE__);
    return get_process_pid (TI_DHCP6C_CLIENT, NULL, true);

}

int stop_ti_dhcp6c (dhcp_params * params)
{
    if ((params == NULL) || (params->ifname == NULL))
    {
        DBG_PRINT("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    pid_t pid = 0;
    pid = get_process_pid(TI_DHCP6C_CLIENT, params->ifname, false);

    if (pid <= 0)
    {
        DBG_PRINT("%s %d: unable to get pid of %s\n", __FUNCTION__, __LINE__, TI_DHCP6C_CLIENT);
        return FAILURE;
    }
    if (signal_process(pid, SIGTERM) != RETURN_OK)
    {
        DBG_PRINT("%s %d: unable to send signal to pid %d\n", __FUNCTION__, __LINE__, pid);
        return FAILURE;
    }

    return SUCCESS;

}

#endif  // DHCPv6_CLIENT_TI_DHCP6C
