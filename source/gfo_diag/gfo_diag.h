/*
 * Logging methods
 */
void logError(char* format, ...);
void logWarning(char* format, ...);
void logStatus(char* format, ...);
void logDebug(char* format, ...);

/*
 * Default is LOG_MAX_LEVEL_ERROR_WARNING_STATUS
 */ 

#define LOG_MAX_LEVEL_ERROR 0
#define LOG_MAX_LEVEL_ERROR_WARNING_STATUS 1
#define LOG_MAX_LEVEL_ERROR_WARNING_STATUS_DEBUG 2

void loggerSetLogLevel(const int level);

/*
 * Set target type
 * Default is syslog
 */
void loggerResetState(void);
int loggerSetLogFile(const char* filename);
void loggerSetOutStdout();

#define LOG_LEVEL_ERROR 0
#define LOG_LEVEL_WARNING 1
#define LOG_LEVEL_STATUS 2
#define LOG_LEVEL_DEBUG 3

/*
 * Prefixes for the different logging levels
 */
#define LOG_PREFIX_ERROR "ERROR"
#define LOG_PREFIX_WARNING "WARNING"
#define LOG_PREFIX_STATUS "INFO"
#define LOG_PREFIX_DEBUG "DEBUG"

#define TIMEOUT 1800

/*
* parameter details subscribe
*/

#define WANMGR_PARAM_NAME_INTERFACE_ACTIVESTATUS "Device.X_RDK_WanManager.InterfaceActiveStatus"
#define PANDM_PARAM_NAME_DEVICE_NETWORKMODE "Device.X_RDKCENTRAL-COM_DeviceControl.DeviceNetworkingMode"
#define WIFI_PARAM_NAME_STA_ACTIVE_CONNECTION "Device.WiFi.STA.*.Connection.Status"
#define MESHAGENT_PARAM_NAME_BACKHAUL_IFNAME "Device.X_RDK_MeshAgent.MeshBackHaul.Ifname" 
#define DEVICE_CAPABILITIES "Device.X_RDK_Remote.Device.2.Capabilities"
#define DEVICE_STATUS "Device.X_RDK_Remote.Device.2.Status"
#define WANFAILOVER "Device.X_RDK_WanManager.AllowRemoteInterfaces"
#define XLE_ACTIVE_STATUS "Device.X_RDK_GatewayManagement.Gateway.2.ActiveStatus"
#define XB_ACTIVE_STATUS "Device.X_RDK_GatewayManagement.Gateway.1.ActiveStatus"
#define WIFI_GET_PARAM_NAME_INSTANCE_STA_ACTIVE_CONNECTION "Device.WiFi.STA.%d.Connection.Status"
#define APSTASTATUS "Device.X_RDK_GatewayManagement.ExternalGatewayPresent"
#define STATION_MODE_TIMEOUT "Device.X_RDK_GatewayManagement.StationModeTimeOut"
#define HEALTH_CHK_TIMEOUT "Device.X_RDK_GatewayManagement.HealthCheckTimeout"
#define WANDOWNMODE_TIMEOUT "Device.X_RDK_GatewayManagement.WANDownModeSwitchTimeout"
#define OPERATION_STATUS_XLE "Device.X_RDK_GatewayManagement.Gateway.2.OperationStatus"
#define OPERATION_STATUS_XB "Device.X_RDK_GatewayManagement.Gateway.1.OperationStatus"
#define SPLIT_BRAIN_COUNT "Device.X_RDK_GatewayManagement.GatewayRestoreAttemptCount"
#define CELLULAR_MGR_WAN_STATUS "Device.Cellular.X_RDK_Status"
#define WAN_ENABLE "Device.Cellular.X_RDK_Enable"
#define WIFI_PARAM_NAME_STA_ACTIVE_CONNECTION "Device.WiFi.STA.*.Connection.Status"

//PSM db
#define CAPABILITIES_PSM	"dmsb.GatewayManager.Capabilities"

/* Capabilities */
#define CAP_REM_WAN_PROVIDER "RemWANProv"
#define CAP_REM_WAN_CONSUMER "RemWANCons"
#define CAP_EXTENDER "WiFiExtender"
#define CAP_ROUTER "RT"

typedef enum _DEVICE_TYPE
{
    GM_DEVICE_PRIMARY,
    GM_DEVICE_BACKUP,
    GM_DEVICE_EXTENDER,
    GM_DEVICE_UNKNOWN
}DEVICE_TYPE;

typedef enum _MANAGER_WANSTATUS
{
    WAN_STATUS_PRIMARY_DOWN = 0,
    WAN_STATUS_PRIMARY_UP,
    WAN_STATUS_SECONDARY_DOWN,
    WAN_STATUS_SECONDARY_UP,
    WAN_STATUS_UNKNOWN
}_MANAGER_WANSTATUS;

typedef enum
{
    SYSCFG_DB = 0,
    PSM_DB
} paramDbName_t;

//Device status
#define ACTIVE 3
#define NOTACTIVE 0

//default retry timeout
#define DEFAULT_RETRY_TIMEOUT 5

/*
*/  


typedef enum _DEV_CAPABILITIES
{
    GM_DSM_RT_REMWANCONS = 0,
    GM_DSM_RT_REMWANPROV_CONS_EXT,
    GM_DSM_RT_REMWANPROV_EXT,
    GM_DSM_EXTENDER_ONLY,
    GM_DSM_UNKNOWN
} _DEV_CAPABILITIES;

typedef enum EventSubcription
{
    EVENT_SUBSCRIPTION_UNKNOWN = 0,
    EVENT_SUBSCRIPTION_SUCCESS,
    EVENT_SUBSCRIPTION_FAILED
}EventSubcription;

/*
 * Logger internal sctructure
 */
struct logger_t {
    int max_log_level;
    int use_stdout;
    FILE* out_file;
    void (*logger_func) (const int level, const char*);
};

typedef struct EventSubscriptionDetails
{
    int subscriptionStatus;
    char paramName[256];
}EventSubscriptionDetails;

typedef enum
{
    PARAM_BOOLEAN  = 0,  	 /**< bool true or false */
	PARAM_INT,				 /**< integer */
	PARAM_UINT,				 /**< unsigned integer */
	PARAM_STRING,			 /**< string */
    PARAM_CHAR,              /**< char of size 1 byte*/
    PARAM_BYTE,              /**< unsigned char */
    PARAM_INT8,              /**< 8 bit int */
    PARAM_UINT8,             /**< 8 bit unsigned int */
    PARAM_INT16,             /**< 16 bit int */
    PARAM_UINT16,            /**< 16 bit unsigned int */
    PARAM_INT32,             /**< 32 bit int */
    PARAM_UINT32,            /**< 32 bit unsigned int */
    PARAM_INT64,             /**< 64 bit int */
    PARAM_UINT64,            /**< 64 bit unsigned int */
    PARAM_SINGLE,            /**< 32 bit float */
    PARAM_DOUBLE,            /**< 64 bit float */
    PARAM_NONE
} paramValueType_t;

typedef enum {
    wifi_connection_status_disabled = 0,
    wifi_connection_status_disconnected = 1000000,
    wifi_connection_status_connected = 2000000,
    wifi_connection_status_ap_not_found = 3000000
} wifi_connection_status_t;

//Structure
typedef struct _timeStamp
{
    unsigned long int staConnTimeFailed;
    unsigned long int xbHeartbeatFail;
    unsigned long int xbHeartbeatDetected;
    unsigned long int xleAPModeActive;
    unsigned long int xleApModeNotActive;
    unsigned long int netModeRouter;
    unsigned long int netModeExtender;
    unsigned long int staConnTimeSuccess;
    unsigned long int cloundCountSet;
    unsigned long int cloundCountReset;
    unsigned long int splitbrainCount;
    unsigned long int secondaryWanStatusUp;
    unsigned long int secondaryWanStatusDown;
}timeStamp;
//Function declaration

typedef int (*ClbkHandlerFunc)(const char *pParamName, char *pValue);
int getDeviceSupportedMode();
int getDeviceType();
