#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "servicecontrol_log.h"

bool ServiceControl_Log_Init()
{
    if (access(DEBUG_INI_OVERRIDE_PATH, F_OK) == 0)
    {
        if (rdk_logger_init(DEBUG_INI_OVERRIDE_PATH) != RDK_SUCCESS)
        {
            return false;
        }
    }
    else
    {
        if (rdk_logger_init(DEBUG_INI_NAME) != RDK_SUCCESS)
        {
            return false;
        }
    }
    return true;
}

bool ServiceControl_Log_Deinit()
{
    return (rdk_logger_deinit() == RDK_SUCCESS ? true : false);
}
