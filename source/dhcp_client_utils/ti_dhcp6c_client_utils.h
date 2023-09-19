

#define TI_DHCP6C_CLIENT                    "ti_dhcp6c"
#define TI_DHCP6C_CLIENT_PATH               "/bin/"TI_DHCP6C_CLIENT
#define TI_DHCP6C_TERMINATE_TIMEOUT  (10 * MSECS_IN_SEC)

pid_t start_ti_dhcp6c (dhcp_params * params);
int stop_ti_dhcp6c (dhcp_params * params);
