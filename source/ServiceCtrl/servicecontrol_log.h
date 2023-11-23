#include <stdbool.h>
#include <stdarg.h>
#include "rdk_debug.h"

/******************************************************************
 * @brief Enables or disables logs of different severity levels.
 *****************************************************************/

#define DEBUG_INI_NAME  "/etc/debug.ini"
#define ARGS_EXTRACT(msg ...) msg

#define  SERVICE_CTRL_LOG(level, msg)  \
    RDK_LOG(level, "LOG.RDK.SERVICECTRL", ARGS_EXTRACT msg);

#define SvcCtrlError(msg)       SERVICE_CTRL_LOG(RDK_LOG_ERROR, msg)
#define SvcCtrlInfo(msg)        SERVICE_CTRL_LOG(RDK_LOG_INFO, msg)
#define SvcCtrlWarning(msg)     SERVICE_CTRL_LOG(RDK_LOG_WARN, msg)
#define SvcCtrlDebug(msg)       SERVICE_CTRL_LOG(RDK_LOG_DEBUG, msg)

bool ServiceControl_Log_Init();
bool ServiceControl_Log_Deinit();
