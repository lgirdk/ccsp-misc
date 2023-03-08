#include<stdio.h>
#include<limits.h>
#include<pthread.h>
#include <errno.h> 
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include "gfo_diag.h"
#include "syscfg/syscfg.h"
#include <rbus.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sysevent/sysevent.h>
#include "safec_lib_common.h"

EventSubscriptionDetails gEventSubObj[] = 
{
    {EVENT_SUBSCRIPTION_UNKNOWN,WANMGR_PARAM_NAME_INTERFACE_ACTIVESTATUS},
    {EVENT_SUBSCRIPTION_UNKNOWN,PANDM_PARAM_NAME_DEVICE_NETWORKMODE},
    {EVENT_SUBSCRIPTION_UNKNOWN,MESHAGENT_PARAM_NAME_BACKHAUL_IFNAME},
    {EVENT_SUBSCRIPTION_UNKNOWN,DEVICE_CAPABILITIES},
    {EVENT_SUBSCRIPTION_UNKNOWN,DEVICE_STATUS},
    {EVENT_SUBSCRIPTION_UNKNOWN,WANFAILOVER},
    {EVENT_SUBSCRIPTION_UNKNOWN,XB_ACTIVE_STATUS},
    {EVENT_SUBSCRIPTION_UNKNOWN,XLE_ACTIVE_STATUS},
    {EVENT_SUBSCRIPTION_UNKNOWN,APSTASTATUS},
    {EVENT_SUBSCRIPTION_UNKNOWN,SPLIT_BRAIN_COUNT},
    {EVENT_SUBSCRIPTION_UNKNOWN,OPERATION_STATUS_XLE},
    {EVENT_SUBSCRIPTION_UNKNOWN,WIFI_PARAM_NAME_STA_ACTIVE_CONNECTION}
};

//Glogal Declaration

rbusHandle_t rbus_handle;

timeStamp ts;

int preConfig = 0;
int remoteDeviceActiveStatus = 0;
int operationStatusOfXLE = 0, xbActiveStatus = 0, normalMode = 0, lteWanEnabled = 0;
int failoverDisabled, lteDown, primaryWanIpNotReachable, wFiStaNotConnected, remDevNotDetected,notRouter;
int staConnSuccess = 0, staConnFailed = 0;
pthread_t tid;

static int sysevent_fd 	  = -1;
static token_t sysevent_token = 0;


static struct logger_t log_global_set;

static const char* LOG_LEVELS[] = { LOG_PREFIX_ERROR,
                    LOG_PREFIX_WARNING,
                    LOG_PREFIX_STATUS,
                    LOG_PREFIX_DEBUG };

void printToFile(const int level, const char* message);


//Global functions

// PSM RBUS util apis
static int 
execute_method_cmd
	(
		char *method, 
		rbusObject_t inParams, 
		char** pOutValue
	)
{
    rbusError_t rc = RBUS_ERROR_SUCCESS;
    rbusValue_t value = NULL;
    rbusObject_t outParams = NULL;
    rbusProperty_t prop = NULL;
    char *str_value = NULL;

    rc = rbusMethod_Invoke(rbus_handle, method, inParams, &outParams);
	if(inParams) {
        rbusObject_Release(inParams);
	}

    if(RBUS_ERROR_SUCCESS != rc)
    {
        return -1;
    }

    prop = rbusObject_GetProperties(outParams);
    while(prop)
    {
        value = rbusProperty_GetValue(prop);
        if(value)
        {
            str_value = rbusValue_ToString(value,NULL,0);

            if(str_value)
            {
				if (0 == strcmp("GetPSMRecordValue()", method)) {
					*pOutValue = (char*) malloc(strlen(str_value) + 1);
					strncpy(*pOutValue, str_value, strlen(str_value) + 1);
				}
				free(str_value);
            }
			else {
				rbusObject_Release(outParams);
				return 1;
			}
        }
		else {
			rbusObject_Release(outParams);
			return 1;
		}
        prop = rbusProperty_GetNext(prop);
    }

    rbusObject_Release(outParams);
	return 0;
}

bool
PSM_Get_Record_Value_Rbus
	(
		char*	PsmParamName,
		char**	pOutValue
	)
{
	int ret;
	rbusProperty_t prop = NULL;
	rbusObject_t inParams = NULL;

	rbusObject_Init(&inParams, NULL);
	rbusProperty_Init(&prop, PsmParamName, NULL) ;
	rbusObject_SetProperty(inParams,prop);
	rbusProperty_Release(prop);
	ret = execute_method_cmd("GetPSMRecordValue()", inParams, pOutValue);
	if (ret != 0){
		return false;
	}
	return true;
}


bool
castValueFromString
	(
		char* fromValue,
		void* toValue,
		paramValueType_t ValueType
	)
{
    int ind = -1;
	
	switch(ValueType) 
	{
		case PARAM_BOOLEAN:
			if((strcmp_s("true",strlen("true"),fromValue, &ind) == EOK) && (!ind))
			{
				*((bool*) toValue) = true;
				break;
			}
			else if((strcmp_s("false",strlen("false"),fromValue, &ind) == EOK) && (!ind))
			{
				*((bool*) toValue) = false;
				break;
			}
			else
			{
				return false;
			}
			
		case PARAM_INT:
			*((int*) toValue) = atoi(fromValue);
			break;
			
		case PARAM_UINT:
			*((unsigned int*) toValue) = atoi(fromValue);
			break;

		case PARAM_UINT16:
			*((uint16_t*) toValue) = atoi(fromValue);
			break;

		case PARAM_INT32:
			*((int32_t*) toValue) = atoi(fromValue);
			break;

		case PARAM_STRING:
			strcpy(toValue, fromValue);
			break;
			
		default:
			strcpy(toValue, fromValue);
			break;
	}
	return true;
}


bool
getValueFromPSMDb
    (
        char*                 	ParamName,
        void*                   pValue,
		paramValueType_t		ValueType,
        paramDbName_t           DbName
    )
{
    if (DbName == PSM_DB) {
		char* strValue = NULL;

		if (!PSM_Get_Record_Value_Rbus(ParamName, &strValue)) {
			printf("%s: psm get failed for the parameter '%s'\n", __FUNCTION__, ParamName);
			return false;
		}

		if (strValue != NULL)
		{
			if(!castValueFromString(strValue, pValue, ValueType)){
				return false;
			}	
			free(strValue);
			printf("psm_get success for the parameter '%s'\n", ParamName);
			return true; 
		}
		else
		{
			printf("psm_get failed for the parameter '%s'\n", ParamName);
			return false;
		}
	}
    return false;   
}


int getDeviceSupportedMode()
{
    char pParamValue[256] = {0};    
    getValueFromPSMDb(CAPABILITIES_PSM, pParamValue, PARAM_STRING, PSM_DB);
    if ((strstr(pParamValue,CAP_REM_WAN_CONSUMER)) && (strstr(pParamValue,CAP_ROUTER)))
    {
    	return GM_DSM_RT_REMWANCONS;
    }
    else if ((strstr(pParamValue,CAP_REM_WAN_PROVIDER)) && (strstr(pParamValue,CAP_ROUTER)) && (strstr(pParamValue,CAP_EXTENDER)))
    {
        return GM_DSM_RT_REMWANPROV_EXT;
    }
    else if (strncmp(pParamValue,CAP_EXTENDER,strlen(CAP_EXTENDER)) == 0)
    {
        return GM_DSM_EXTENDER_ONLY;
    }
    return GM_DSM_RT_REMWANCONS;
}


//Get the device type based on the device capabilities 
int getDeviceType()
{
    int capabilities = getDeviceSupportedMode();
    int devicetype = GM_DEVICE_PRIMARY;
    if ((capabilities == GM_DSM_RT_REMWANPROV_EXT)
            ||  (capabilities == GM_DSM_RT_REMWANPROV_CONS_EXT))
    {
        devicetype = GM_DEVICE_BACKUP;
    }
    else if (capabilities == GM_DSM_EXTENDER_ONLY)
    {
        devicetype = GM_DEVICE_EXTENDER;
    }
    
    return devicetype;
}

/* function to convert timespec in seconds*/
static double TimeSpecToSeconds(struct timespec* ts)
{
    return (double)ts->tv_sec + (double)ts->tv_nsec / 1000000000.0;
}

/* rbus datatype to gatewaymanager datatype conversion */
paramValueType_t dtype_convert_rbus(rbusValueType_t rbusValueType)
{
	paramValueType_t datatype = PARAM_NONE;
	switch(rbusValueType)
	{
		case RBUS_BOOLEAN:
			datatype = PARAM_BOOLEAN;
			break;
		case RBUS_INT64:
			datatype = PARAM_INT;
			break;
		case RBUS_UINT64:
			datatype = PARAM_UINT;
			break;
		case RBUS_STRING:
			datatype = PARAM_STRING;
			break;
		case RBUS_CHAR:
			datatype = PARAM_CHAR;
			break;
		case RBUS_BYTE:
			datatype = PARAM_BYTE;
			break;
		case RBUS_INT8:
			datatype = PARAM_INT8;
			break;
		case RBUS_UINT8:
			datatype = PARAM_UINT8;
			break;
		case RBUS_INT16:
			datatype = PARAM_INT16;
			break;
		case RBUS_UINT16:
			datatype = PARAM_UINT16;
			break;
		case RBUS_INT32:
			datatype = PARAM_INT32;
			break;
		case RBUS_UINT32:
			datatype = PARAM_UINT32;
			break;
		case RBUS_SINGLE:
			datatype = PARAM_SINGLE;
			break;
		case RBUS_DOUBLE:
			datatype = PARAM_DOUBLE;
			break;
		case RBUS_NONE:
			datatype = PARAM_NONE;
			break;
		default:
			datatype = PARAM_NONE;
	}

	return 	datatype;
}

/* Get parameter value API */
int getParameterValue (const char *pParamName, char *pReturnVal, paramValueType_t *pRetType )
{
	int					   ret = 0;
	rbusValue_t            value;
	rbusValueType_t        rbusValueType ;
	char                   *pStrVal            = NULL;
    
	if((pReturnVal == NULL) || (pRetType == NULL))
	{
		printf("%s-%d null parameter value/type",__FUNCTION__,__LINE__);
		return 1;
	}

	/* rbus get parameter value */
	if(rbus_handle == NULL)
	{
		return 1;
	}

	/* Init rbus variable */
	rbusValue_Init(&value);

	/* Get the value of a single parameter */
	ret = rbus_get(rbus_handle, pParamName, &value);

	if(ret != RBUS_ERROR_SUCCESS )
	{
		printf("%s-%d Rbus Error code:%d - %s",__FUNCTION__,__LINE__, ret,pParamName);
		return 1;
	}

	rbusValueType = rbusValue_GetType(value);

	/* Update the parameter value */
	if(rbusValueType == RBUS_BOOLEAN)
	{
		if (rbusValue_GetBoolean(value)){
			pStrVal = strdup("true");
		} else {
			pStrVal = strdup("false");
		}
	}
	else
	{
		pStrVal = rbusValue_ToString(value, NULL, 0);
	}
	strncpy( pReturnVal, pStrVal, strlen( pStrVal ) + 1 );

	/* Update the parameter datatype */
	*pRetType = dtype_convert_rbus(rbusValueType);

	/* release rbus variable */
	rbusValue_Release(value);
	free(pStrVal);
	return 0;
}

//read the command output
int read_cmd_output(char *cmd, char *output_buf, int size_buf)
{
    //printf("entering comming output %s\n", cmd);
    FILE *f = NULL;
    char *pos = NULL;
    if (!cmd || (!output_buf) || (size_buf <= 0))
        return -1;
    f = popen(cmd,"r");
    if(f==NULL){
        return -1;
    }
    fgets(output_buf,size_buf,f);
    /* remove trailing newline */
    if((pos = strrchr(output_buf, '\n')) != NULL)
        *pos = '\0';
    pclose(f);
    return 0;
}

/*
 * Close remaining file descriptor and reset global params
 */
void cleanupInternal()
{
    if (log_global_set.out_file) {
        if (!log_global_set.use_stdout) {
            fclose(log_global_set.out_file);
        }

        log_global_set.use_stdout = 0;
        log_global_set.out_file = NULL;
    }
}

/*
 * Print to file which can be a regular text file or STDOUT "file"
 */
void printToFile(const int level, const char* message)
{
    struct tm* current_tm;
    time_t time_now;
    time(&time_now);
    current_tm = localtime(&time_now);

    int res = fprintf(log_global_set.out_file,
              "%02i:%02i:%02i [%s] %s\n"
                , current_tm->tm_hour
                , current_tm->tm_min
                , current_tm->tm_sec
                , LOG_LEVELS[level]
                , message );

    if (res == -1) {
        printf("Unable to write to log file!");
        return;
    }

    fflush(log_global_set.out_file);
}

/*
     Log will be captured in file
 */
int loggerSetLogFile(const char* filename)
{
    cleanupInternal();
   
    log_global_set.out_file = fopen(filename, "a");

    if (log_global_set.out_file == NULL) {
        logError("Failed to open file %s error %s", filename, strerror(errno));
        return -1;
    }

    log_global_set.logger_func = printToFile;

    return 0;
}

/*
 * Logging functions
 */
void logGeneric(const int level, const char* format, va_list args)
{
    char buffer[256];
    vsprintf(buffer, format, args);
    log_global_set.logger_func(level, buffer);
}

void logError(char *format, ...)
{
    va_list args;
    va_start(args, format);
    logGeneric(LOG_LEVEL_ERROR, format, args);
    va_end(args);
}

void logWarning(char *format, ...)
{
    va_list args;
    va_start(args, format);
    logGeneric(LOG_LEVEL_WARNING, format, args);
    va_end(args);
}

void logStatus(char *format, ...)
{
    va_list args;
    va_start(args, format);
    logGeneric(LOG_LEVEL_STATUS, format, args);
    va_end(args);
}

void logDebug(char *format, ...)
{
    va_list args;
    va_start(args, format);
    logGeneric(LOG_LEVEL_DEBUG, format, args);
    va_end(args);
}

int getWanStatusFromParamValue(char *pParamValue)
{
    char *pToken = NULL;
    char *pStatus = NULL;
    char *pSecInterface = "REMOTE";
    int backUpWanStatus = 0;
    int primaryWanStatus = 0;
    int deviceType = getDeviceType();
    if (!pParamValue)
        return WAN_STATUS_UNKNOWN;
    pToken = strtok(pParamValue,"|");
    if (!pToken)
    {
	pToken = pParamValue;
    }
    while (pToken != NULL)
    {
        pStatus = strstr(pToken,",");
        if (strstr(pToken,pSecInterface))
        {
            if (pStatus && (pStatus+1))
            {
                backUpWanStatus = atoi(pStatus+1);
            }
        }
        else
        {
            if (pStatus && (pStatus+1))
            {
                if (deviceType == GM_DEVICE_BACKUP)
                {
                    backUpWanStatus = atoi(pStatus+1);
                }
                else
                {
                    primaryWanStatus = atoi(pStatus+1);
                }
            }
        }

        if (primaryWanStatus && (deviceType == GM_DEVICE_PRIMARY))
        {
            return WAN_STATUS_PRIMARY_UP;
        }

        if (backUpWanStatus && (deviceType == GM_DEVICE_BACKUP))
        {
            return WAN_STATUS_SECONDARY_UP;
        }

        pToken = strtok(NULL,"|");
    }
    if (deviceType == GM_DEVICE_PRIMARY)
    {
        return WAN_STATUS_PRIMARY_DOWN;
    }
    else
    {
        return WAN_STATUS_SECONDARY_DOWN;
    }
}

unsigned int GetStaStatusFromString(char *pStr)
{
    char sta_status[12] = {0};
    if (!pStr)
        return 0;
    memset(sta_status,0,sizeof(sta_status));

    // pStr will have value in this format "020000005A963040CE0C"
    // parse only first 8 character from pStr
    if (strlen(pStr) >= (4 * 2))
    {
        sscanf(pStr,"%08c",sta_status);
        return atoi(sta_status);
    }
    return 0;
}

//Get the STA connection status
int GetWiFiSTAConnStatus()
{
    int numOfInstance = 3;
    int index = 1;
    char paramName[256] = {0};
    char paramValue[32] = {0};
    int retvalue = -1;
    paramValueType_t valueType;
    for (index = 1; index <= numOfInstance; ++index)
    {
        snprintf(paramName,sizeof(paramName),WIFI_GET_PARAM_NAME_INSTANCE_STA_ACTIVE_CONNECTION,index);
        retvalue = getParameterValue(
	               paramName,
                   paramValue,
                   &valueType);
        if (RBUS_ERROR_SUCCESS != retvalue)
        {
            printf("%s get Param %s status failed %d\n", __FUNCTION__,paramName,retvalue);
        }
        else
        {
            printf("%s get Param %s status %d ret.Value %d\n", __FUNCTION__,paramName,GetStaStatusFromString(paramValue),retvalue);
        }
        if (GetStaStatusFromString(paramValue) == wifi_connection_status_connected)
        {
    	    return 2;
        }
    }
    return 1; 
}


void usage(void)
{
    printf("\n*************************************\n");
    printf("Usage: gwdiag failover/restore options\n");
    printf("options:\n");
    printf("gfo_diag restore -m& for Monitor Mode \n");
    printf("gfo_diag failover -m& for Monitor Mode \n");
    printf("gfo_diag failover -n for To dump log \n");
    printf("gfo_diag restore -n to dump the log \n");
    printf("\n*************************************\n");
}


/*
* Read the timeout parameters
*/
void getTimeoutValues()
{
    char buf[100];
    paramValueType_t rmRetType;
	
    int deviceType = getDeviceType();
	
    memset(buf, 0, sizeof(buf));
    if(!getParameterValue(STATION_MODE_TIMEOUT,buf,&rmRetType))
    {
        logStatus("Station Mode Timeout in seconds= %s", buf);
    }

    memset(buf, 0, sizeof(buf));
    if(!getParameterValue(HEALTH_CHK_TIMEOUT,buf,&rmRetType))
    {
        logStatus("Healthcheck Timeout in seconds= %s", buf);
    }
    
    if ((deviceType == GM_DEVICE_BACKUP) || (deviceType == GM_DEVICE_EXTENDER))
    {
        memset(buf, 0, sizeof(buf)); 
        if(!getParameterValue(WANDOWNMODE_TIMEOUT,buf,&rmRetType))
        {
            logStatus("WanDown Mode Timeout in seconds= %s", buf);
        }
    }
}

/*
*  Collect the data before  preGateway failver
*/
void gwDiagPreGfoOrGre()
{
    char buf[100];
    char sn[20] = {0};
    int serialNumber = 0;
    paramValueType_t rmRetType;
    int result = 0;
    
    //Read the Box type from Device properties.
    logStatus("******************************************" );
    logStatus("Gateway failover Precheck");
    logStatus("******************************************" );

     //Model Number
    memset(buf, 0, sizeof(buf));
    result = read_cmd_output("deviceinfo.sh -mo",buf,sizeof(buf));
    if(result == 0)
    {
         logStatus("Device Type - %s", buf );    
    }

    //Read the serial number
    result = read_cmd_output("deviceinfo.sh -sn",sn,sizeof(sn));
    if(result == 0)
    {
        serialNumber = atoi(sn);
        logStatus("Device Serial Number - %d", serialNumber);
    }
    
    //Read device networking mode
    memset(buf, 0, sizeof(buf));
    result = read_cmd_output("deviceinfo.sh -mode",buf,sizeof(buf));
    if(result == 0)
    {
        logStatus("Device Networking Mode - %s", buf);
    }
    
    //Read Failover enable/disable
    memset(buf, 0, sizeof(buf));
    if(!getParameterValue("Device.X_RDK_GatewayManagement.Failover.Enable",buf,&rmRetType))
    {
        int gwFailoverEnabled = atoi(buf);
        if(gwFailoverEnabled)
        {
            logStatus("Gateway Failover Enabled - %d", gwFailoverEnabled);
            failoverDisabled = 0;
        }
        else
        {
            logStatus("Gateway Failover Disabled - %d", gwFailoverEnabled);
            failoverDisabled = 1;
        }
    }

    //Read wanfailover enable/disable
    memset(buf, 0, sizeof(buf));
    if(!getParameterValue(WANFAILOVER,buf,&rmRetType)) 
    {
        if(strcmp(buf,"false") == 0)
        {
            logStatus("Wan Failover is Disabled - %s", buf);
        }
        else
        {
            logStatus("Wan Failover is Enabled - %s", buf);
        }
    }

    //Read Capabilities
    memset(buf, 0, sizeof(buf));
    if(!getParameterValue("Device.X_RDK_Remote.Device.1.Capabilities",buf,&rmRetType))   
    {
        int len = strlen(buf);
        if(len > 0)
        {
            logStatus("Remote Device 1 capabilities - %s", buf);    
            
        }
        else
        {
            logStatus("Remote Device 1 not connected"); 
        }
           
    }
    
    //Read Capabilities
    memset(buf, 0, sizeof(buf));
    if(!getParameterValue("Device.X_RDK_Remote.Device.2.Capabilities",buf,&rmRetType))  
    {
        int len = strlen(buf);
        if(len > 0)
        {
            logStatus("Remote Device 2 capabilities - %s", buf);           
        }
        else
        {
            logStatus("Remote Device 2 not connected");                          
        }
        
    }
    
    //Read operation status of remote device
    memset(buf, 0, sizeof(buf));
    int devType=getDeviceType();
    if ((devType == GM_DEVICE_BACKUP) || (devType == GM_DEVICE_EXTENDER))
    {
        getParameterValue(OPERATION_STATUS_XB,buf,&rmRetType);  
    }
    else
    {
        getParameterValue(OPERATION_STATUS_XLE,buf,&rmRetType);  
    }
    if(strcmp(buf, "true") == 0)
    {
        logStatus("Operation status of remote device is active - %s", buf);           
    }
    else
    {
        logStatus("Operation status of remote device is not active - %s", buf);                          
    }

    //MeshBackhaul Interface Name 
    memset(buf, 0, sizeof(buf));
    if(!getParameterValue(MESHAGENT_PARAM_NAME_BACKHAUL_IFNAME,buf,&rmRetType))  
    {
        logStatus("MeshBackhaul Interface Name - %s", buf);
    }     
    logStatus("******************************************" );
}

/*
* Callback event handler to process rbus events
*/
int CallbackEvent(const char *pParamName, char *pValue)
{
    //get the device type
    int deviceType = getDeviceType();
	
    time_t seconds;
	//capture the time in seconds to print the timestamp
    time(&seconds);

    printf("Value Change %s param name %s param value %s \n",__FUNCTION__,pParamName, pValue);

    //Capture the event based on device capabilities
    if ((deviceType == GM_DEVICE_BACKUP) || (deviceType == GM_DEVICE_EXTENDER))
    {
        if (strstr(pParamName,"Device.WiFi.STA."))
        {
            if (pValue && (GetStaStatusFromString(pValue) == wifi_connection_status_connected))
            {

                ts.staConnTimeSuccess = seconds;
                logStatus("STA_CONN_SUCCESS: %22ld seconds",(seconds - ts.netModeExtender));              
            }
            else
            {
                ts.staConnTimeFailed = seconds;
                logStatus("STA_CONN_FAILED");
            }
        }
        
        //Check for the active interface name
        if (strncmp(WANMGR_PARAM_NAME_INTERFACE_ACTIVESTATUS,pParamName,strlen(WANMGR_PARAM_NAME_INTERFACE_ACTIVESTATUS)) == 0)
        {
            int status = getWanStatusFromParamValue(pValue);
            switch(status)
            {
                case WAN_STATUS_SECONDARY_DOWN:
                {
                    ts.secondaryWanStatusDown = seconds;
                    logStatus("SECONDARY_WAN_STATUS_DOWN: %2s",pValue);
                }
                break;
                case WAN_STATUS_SECONDARY_UP:
                {
                    ts.secondaryWanStatusUp = seconds;
                    logStatus("SECONDARY_WAN_STATUS_UP: %2s",pValue);
                    lteWanEnabled = 1;
                }
                break;
                default:
                break;
            }
        }
        
        //Check for the networking mode event
        if(strncmp(PANDM_PARAM_NAME_DEVICE_NETWORKMODE,pParamName,strlen(PANDM_PARAM_NAME_DEVICE_NETWORKMODE)) == 0)
        {
            unsigned int networkingMode = atoi(pValue);
            if(networkingMode == 0)
            {
                ts.netModeRouter = seconds;
                logStatus("NETWORKING_MODE_SET_ROUTER: %11ld seconds",(seconds - ts.xbHeartbeatFail));
            }
            else
            {
                ts.netModeExtender = seconds;
                logStatus("NETWORKING_MODE_SET_EXTENDER: %16ld seconds",(seconds - ts.splitbrainCount));
            }
        }
        
        //Check for the split brain count
        if(strncmp(SPLIT_BRAIN_COUNT,pParamName,strlen(SPLIT_BRAIN_COUNT)) == 0)
        {
            int splitBrainCount = atoi(pValue);
            if(splitBrainCount == 0)
            {
                ts.cloundCountReset = seconds;
                logStatus("CLOUD_CONTROL_SPLIT_BRAIN_RESTORE_COUNT: %2d",splitBrainCount);
            }
            else
            {
                ts.splitbrainCount = seconds;
                logStatus("CLOUD_CONTROL_SPLIT_BRAIN_RESTORE_COUNT: %2d", splitBrainCount);
                logStatus("XLE_ON_BACKUP_GATEWAY_ACTIVE_TIME_TILL_CLOUD_CTRL_RECEIVED: %ld seconds",(seconds - ts.netModeRouter));
            }
        }
   
        //Check for the XB active status when restore is complete
        if(strncmp(XB_ACTIVE_STATUS,pParamName,strlen(XB_ACTIVE_STATUS)) == 0)
        {
            if (strcmp(pValue,"true") == 0)
            {
                remoteDeviceActiveStatus = 1;
            }     
        }
        
        //Check for the primary gateway status
        if(strncmp(DEVICE_STATUS,pParamName,strlen(DEVICE_STATUS)) == 0)
        {  
            char buf[20] = {0};
            paramValueType_t rmRetType;
            int newValue = atoi(pValue);
           
            switch(newValue)
            {
                case 0:
                { 
                    ts.xbHeartbeatFail = seconds;
                    logStatus("PRIMARY_GW_UNREACHABLE: %15ld seconds", (seconds - ts.staConnTimeFailed) );
                    
                    //Check LTE is DOWN
                    if(!getParameterValue(WANMGR_PARAM_NAME_INTERFACE_ACTIVESTATUS,buf,&rmRetType))
                    {
                        if(strstr(buf,"LTE,0"))   
                        {
                            lteDown = 1;
                        }
                    }
                }
                break;
                case 3:
                {
                    ts.xbHeartbeatDetected = seconds;
                    logStatus("PRIMARY_GW_REACHABLE: %18ld seconds",(seconds - ts.staConnTimeSuccess));
                }
                break;
                default:
                break;
            }
        }
        
        //Check for the XLE active status
        if(strncmp(XLE_ACTIVE_STATUS,pParamName,strlen(XLE_ACTIVE_STATUS)) == 0)
        {
            if(strcmp(pValue,"true") == 0)
            {
                logStatus("GFO_FAILOVER_SUCCESS %18ld seconds", (seconds - ts.netModeRouter));
            }
        }       
    }
    //process the events for XB
    if(deviceType == GM_DEVICE_PRIMARY)
    {
        
        if(strncmp(OPERATION_STATUS_XLE,pParamName,strlen(OPERATION_STATUS_XLE)) == 0)
        {
            if(strcmp(pValue, "true") == 0)
            {
                logStatus("GFO_REMOTE_DEVICE_OP_STATUS %10ld seconds", seconds);
                operationStatusOfXLE = 1;
            }
            else
            {
                logStatus("Operation status of XLE is not Active");
            }
        }
        if(strncmp(XB_ACTIVE_STATUS,pParamName,strlen(XB_ACTIVE_STATUS)) == 0)
        {
            if(strcmp(pValue, "true") == 0)
            {
                logStatus("Primary Gateway is Active in %ld seconds", seconds);
                xbActiveStatus = 1;
            }
            else
            {
                logStatus("Primary Gateway is not Active");
                xbActiveStatus = 0;
            }
        }
        if(strncmp(PANDM_PARAM_NAME_DEVICE_NETWORKMODE,pParamName,strlen(PANDM_PARAM_NAME_DEVICE_NETWORKMODE)) == 0)
        {
            int networkingMode = atoi(pValue);
            if(networkingMode == 0)
            {
                logStatus("NETWORKING_MODE_ROUTER in %6ld seconds", seconds);
            }
        }
        if(strncmp(APSTASTATUS,pParamName,strlen(APSTASTATUS)) == 0)
        {
           
            if(strcmp(pValue,"false") == 0)
            {
                logStatus("AP mode is Active in XB at %ld seconds", seconds);
            }
            else if(strcmp(pValue,"true") == 0)
            {
                logStatus("AP mode is not Active in XB");     
            }
        }
    }
    
    if(strncmp(MESHAGENT_PARAM_NAME_BACKHAUL_IFNAME,pParamName,strlen(MESHAGENT_PARAM_NAME_BACKHAUL_IFNAME)) == 0)
    {
        logStatus("GFO_MESHBACKHAUL_INTERFACE: %s", pValue);
    }   
   return 0;
}

/* Default event handler for  rbusEvent_Subscribe()  */
static void eventHandler(
    rbusHandle_t r_handle,
    rbusEvent_t const* event,
    rbusEventSubscription_t* subscription)
{
    (void)r_handle;
    (void)subscription;

    const char* eventName = event->name;

    rbusValue_t valBuff;
    rbusValueType_t rbusValueType;

    valBuff = rbusObject_GetValue(event->data, NULL );

    if(!valBuff)
    {
        printf("FAIL: value is NULL\n");
    }
    else
    {
        char* newValue = NULL;

        rbusValueType = rbusValue_GetType(valBuff);

        /* Update the parameter value */
		if(rbusValueType == RBUS_BOOLEAN)
		{
			if (rbusValue_GetBoolean(valBuff)){
				newValue = strdup("true");
			} else {
				newValue = strdup("false");
			}
		}
		else
		{
			newValue = rbusValue_ToString(valBuff, NULL, 0);
		}

        printf("\nEvent name %s, Event value %s, Event type %d \n",
                eventName,newValue,rbusValueType);
        if (subscription)
        {
            ClbkHandlerFunc pCallback = (ClbkHandlerFunc)subscription->userData;
            if (pCallback)
            {
				printf("%s: Calling HandlerFunc\n", __FUNCTION__);
                pCallback(eventName,newValue);
            }
        }
		free(newValue);
    }
}


//Set sysconfig to restart the gfo binary after reboot
void setSyscfg()
{
    if (syscfg_set(NULL, "gfo-test", "1") != 0) 
    {
        printf("syscfg_set failed\n");
    }  
    else 
    {         
        if (syscfg_commit() != 0) 
        {
            printf("syscfg_commit failed\n");
        }
    }
}

/*
* clear the syscfg database before program exit
*/
void clearDb()
{
    //copy the log file from nvram2 to rdklogs 
    system("cp -rf /nvram2/GFODiag.txt /rdklogs/logs/GFODiag.txt");
    sleep(1);
    system("rm -rf /nvram2/GFODiag.txt");

    //clear the syscfgdb before process exit
    syscfg_unset(NULL, "gfo-test");
    syscfg_unset(NULL, "preConfig_gfo");
    syscfg_commit();
}

//RbusInit and subscribe for GatewayManager events
rbusError_t diagRbusInit()
{
    int rc = RBUS_ERROR_SUCCESS;
    rc = rbus_open(&rbus_handle, "GFODiag");
    if(rc != RBUS_ERROR_SUCCESS)
    {
        printf("DFO Diag: rbus_open failed: %d\n", rc);
        return rc;
    }
    return rc;
}

//RBus Event Subscription for XLE and XB
void subscribeEvents()
{
    int index = 0;
    int numOfParam = (sizeof(gEventSubObj)/sizeof(gEventSubObj[0]));
    int ret = RBUS_ERROR_BUS_ERROR;
    int numOfParamSuccess = 0;

    while(1)
    {
        //subscribe RBUS events
        for (index = 0; index < numOfParam; ++index)
        {
            if(gEventSubObj[index].subscriptionStatus != EVENT_SUBSCRIPTION_UNKNOWN)
            {
                continue;
            }
            ClbkHandlerFunc pCallback = (ClbkHandlerFunc)CallbackEvent;
            ret = rbusEvent_Subscribe(rbus_handle, gEventSubObj[index].paramName, eventHandler, (char*)pCallback, DEFAULT_RETRY_TIMEOUT);

            if (((ret == RBUS_ERROR_SUCCESS) || 
                (ret == RBUS_ERROR_SUBSCRIPTION_ALREADY_EXIST)) && 
                (gEventSubObj[index].subscriptionStatus == EVENT_SUBSCRIPTION_UNKNOWN))
            {
                gEventSubObj[index].subscriptionStatus = EVENT_SUBSCRIPTION_SUCCESS;
                ++numOfParamSuccess;
            }
        }
        if (numOfParamSuccess == numOfParam)
        {
            break;
        }
        sleep(1);       
    }
}

//Checking for the failover reason events
void *eventHandlerThrd(void *data)
{
    int err;
    char val[64] = {0};
    char name[64] = {0};
    int namelen = sizeof(name);
    async_id_t asyncid;
    async_id_t getnotification_asyncid;
    int vallen  = sizeof(val);
    char failoverbuf[64] = {0};

    pthread_detach(pthread_self());

    sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "gateway_manager", &sysevent_token);

    if(sysevent_fd < 0)
    {
        printf("failed to open sysevent\n");
    }
    else
    {
        printf("sysevent open success****\n");
    }

    sysevent_set_options(sysevent_fd, sysevent_token, "GWMGR_SM_STATUS", TUPLE_FLAG_EVENT);
	sysevent_setnotification(sysevent_fd, sysevent_token, "GWMGR_SM_STATUS",  &asyncid);

    //Temporary fix for failover is disabled event
    sysevent_get(sysevent_fd, sysevent_token, "GWMGR_SM_STATUS", failoverbuf, sizeof(failoverbuf));
    if(strcmp(failoverbuf,"GW_FAILOVER_DISABLED")==0)
	{
        failoverDisabled = 1; 
    }

    while(1)
    {
        err = sysevent_getnotification(sysevent_fd, sysevent_token, name, &namelen, val , &vallen, &getnotification_asyncid);
        if (err)
        {
            printf("sysevent_getnotification failed with error: %d %s\n", err,__FUNCTION__);
        }
        else
        {
            printf("%s Recieved notification event  %s for the reason %s\n",__FUNCTION__,name,val);
            if(strcmp(name,"GWMGR_SM_STATUS")==0)
			{
                if(strcmp(val,"GW_FAILOVER_DISABLED")==0)
			    {
                    failoverDisabled = 1; 
                }
                else if(strcmp(val,"GW_FAILOVER_FAILED_PRIMARYWAN_IP_REACHABLE") == 0)
                {
                    primaryWanIpNotReachable = 1;
                }
                else if(strcmp(val,"GW_RESTORE_FAILED_WIFI_STA_NOTCONNECTED") == 0)
                {
                    wFiStaNotConnected = 1; 
                }
                if(strcmp(val,"GW_RESTORE_FAILED_REMDEV_NOTDETECTED") == 0)
                {
                    remDevNotDetected = 1;
                }
                else if(strcmp(val,"GW_FAILOVER_FAILED_CAP_NOT_ROUTER")== 0)
                {
                    notRouter = 1;
                }
                else
                {
                    printf("No events detected\n");
                }
            }
        }
    }
    return data;
}

int main(int argc, char *argv[])
{
    int rc = RBUS_ERROR_SUCCESS;
    struct timespec start, end;
    double elapsedTime;
    int gwFailoverEnabled = 0;
    paramValueType_t paramRetType;
    char buf[10] = {0};
    int Error;
    

    //Set the log file to store the data
    loggerSetLogFile("/nvram2/GFODiag.txt");

    if(argc < 3)
    {
        logError("enter correct failover or restore option\n");
        usage();
        return -1;
    }

   
    //RBUS init
    rc = diagRbusInit();
    if (rc != RBUS_ERROR_SUCCESS) 
    {
        printf("GFODiag: Rbus initialization failed: %d\n", rc);
        goto exit1;
    }  

    //Check the preconfig is set in syscfg to print preconfig
    if( 0 == syscfg_get( NULL, "preConfig_gfo", buf, sizeof( buf ) ) )
    {
        if(strcmp(buf,"") == 0)
        {
            preConfig = 0;
        }
        else if((strcmp(buf,"1") == 0))
        {
        	preConfig = atoi(buf);
        }
    }

    //Display the precheck information in log before test start 
    if(!preConfig)
    {
        //log precheck data in log file
        gwDiagPreGfoOrGre();
        
        //Record the timeout values in log file         
        getTimeoutValues();
        
        preConfig = 1;
        
        //set config varaible to avoid capturing duplicate info in log when device reboots
        if (syscfg_set(NULL, "preConfig_gfo", "1") != 0) 
        {
            printf("syscfg_set failed\n");
        }  
        else 
        {         
            if (syscfg_commit() != 0) 
            {
                printf("syscfg_commit failed\n");
            }
        }
    }  

    //subscribe for rbus event
    subscribeEvents();

    Error=pthread_create(&tid,NULL,eventHandlerThrd,NULL);
    if (Error)
	{
		printf("eventHandlerThrd error : %d\n",Error);
	}
    else
    {
        printf("eventHandlerThrd thread created successfully\n*****");
    }

    if((strcmp(argv[1], "restore") == 0) && (strcmp(argv[2], "-m")== 0)) 
    {        
 
        //Read Failover enable/disable
        memset(buf, 0, sizeof(buf));
        if(!getParameterValue("Device.X_RDK_GatewayManagement.Failover.Enable",buf,&paramRetType))
        {
            gwFailoverEnabled = atoi(buf);
        }
        
        //Read the syscfg and check if gfo-test is set
        memset(buf, 0, sizeof(buf));
        syscfg_get(NULL, "gfo-test", buf, sizeof(buf));
        
        if((strlen(buf) == 0) && gwFailoverEnabled)
        {
            //Setting gfo-test for temporary to store the execution status
            setSyscfg();
            //reboot the XB
            sleep(1);
            system("reboot");
        }
        else
        {
            printf("*********GW failover is not enabled******\n");
        }
    }
    else if((strcmp(argv[1], "failover") == 0) && (strcmp(argv[2], "-m")== 0)) 
    {   
        //Setting gfo-test for temporary to store the execution status
        setSyscfg();
    }
    else if((strcmp(argv[1], "failover") == 0) && (strcmp(argv[2], "-n")== 0)) 
    {
        //Dump message util data to file
        system("msgq_util 36");
        normalMode = 1;
    }
    else if((strcmp(argv[1], "restore") == 0) && (strcmp(argv[2], "-n")== 0)) 
    {
        //Dump messag queue util data to file
        system("msgq_util 36");
        normalMode = 1;
    }
    else 
    {
        printf("Select valid options\n");
    }
    
    //captrue the time to stop to process after 30 mins
    clock_gettime(CLOCK_MONOTONIC, &start);

    fprintf(log_global_set.out_file ,"%s\n","------------------------------------------------------------------" );
    fprintf(log_global_set.out_file ,"%s\n","                GFO EVENTS FLOW AND STATS                         " );

    fprintf(log_global_set.out_file ,"\n%s\n","EVENTS                                              TIME TAKEN  " );
    fprintf(log_global_set.out_file ,"%s\n","------------------------------------------------------------------" );
  

    while(1)
    {
        // get our current delta time
        clock_gettime(CLOCK_MONOTONIC, &end);

        // compute the elapsed time in seconds
        elapsedTime = TimeSpecToSeconds(&end) - TimeSpecToSeconds(&start);

        if(notRouter)
        {
            logError("GFO_FAILED: CAPAPABILITY_NOT_ROUTER"); 
            goto cleardb;
            break; 
        }

        if(remDevNotDetected)
        {
            logError("GFO_FAILED: GW_RESTORE_FAILED_REMDEV_NOTDETECTED"); 
            goto cleardb;
            break; 
        }

        if(wFiStaNotConnected)
        {
            logError("GFO_FAILED: GW_RESTORE_FAILED_WIFI_STA_NOTCONNECTED"); 
            goto cleardb;
            break;
        }

        if(primaryWanIpNotReachable)
        {
            logError("GFO_FAILED: PRIMARYWAN_IP_REACHABLE"); 
            goto cleardb;
            break;
        }

        if(failoverDisabled)
        {
            logError("GFO_FAILED: FAILOVER_NOT_ENABLED");
            goto cleardb;
            break;
        }

        if(lteDown)
        {
            logError("GFO_FAILED: LTE_DOWN");
            //Added for table formatting purpose
            goto cleardb;
            break;
        }

        if((remoteDeviceActiveStatus == 1) &&(lteWanEnabled == 1))
        {
            logStatus("BACKUP_GW_ACTIVE_TIME: %18ld seconds",(ts.staConnTimeSuccess - ts.netModeRouter));   
            logStatus("GFO_RESTORE_SUCCESS: %19ld seconds",(ts.xbHeartbeatDetected - ts.splitbrainCount));

            //Added for table formatting purpose
            goto cleardb;
            break;
        }
        else if(operationStatusOfXLE == 1)
        {
            logStatus("GFO_RESTORE_SUCCESS ");
            
            //Added for table formatting purpose
            goto cleardb;
            break;
        }    
        else if ((unsigned int)elapsedTime > TIMEOUT || (normalMode == 1))
        {
            goto cleardb;
            break;
        }
		sleep(1);   
    }
    cleardb:
        clearDb();
    exit1:
        rbus_close(rbus_handle);
    return 0;
}
