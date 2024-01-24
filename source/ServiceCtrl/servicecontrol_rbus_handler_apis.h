#include <rbus/rbus.h>
#include "ansc_platform.h"

rbusError_t ServiceControl_Rbus_Init();
rbusError_t ServiceControl_GetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t ServiceControl_SetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options);
