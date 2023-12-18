

#define TI_UDHCPC_CLIENT                    "ti_udhcpc"
#define TI_UDHCPC_CLIENT_PATH               "/bin/"TI_UDHCPC_CLIENT
#define TI_UDHCPC_TERMINATE_TIMEOUT  (10 * MSECS_IN_SEC)

pid_t start_ti_udhcpc (dhcp_params * params);
int stop_ti_udhcpc (dhcp_params * params);
