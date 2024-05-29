/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include "bridge_creation.h"
#include "bridge_util_hal.h"
#include <unistd.h>
#include <stdint.h>
#ifdef CORE_NET_LIB
#include <libnet.h>
#endif

/*********************************************************************************************

    caller:  CreateBrInterface,DeleteBrInterface,SyncBrInterfaces
    prototype:

        bool
        brctl_interact
            (
				ovs_api_request *request
            );
    	description :
			When OVS is disabled , this function is called to create/delete/update 
			bridge and bridge interfaces

	Argument : 
			ovs_api_request *request  -- It has bridge and iface related data
	return : When success returns true 
***********************************************************************************************/
bool brctl_interact(Gateway_Config_t * gw_config)
{
	char cmd[1024] = {0} ;

	//Gateway_Config * gw_config = (Gateway_Config *) ((request->table_config.config) );
	if (gw_config == NULL )
	{
		return false ;
	}
#if 0
	if ( OVS_INSERT_OPERATION == request->operation )
	{

		if ( gw_config->parent_bridge[0] != '\0' )
		{
			snprintf(cmd,sizeof(cmd),"check_bridge=`brctl show | grep %s` ; if [ \"$check_bridge\" = \"\" ]; \
				then \
				brctl addbr %s ; \
				ifconfig %s up ; \
				fi ;",
				gw_config->parent_bridge,
				gw_config->parent_bridge,
				gw_config->parent_bridge);
				system(cmd);
				memset(cmd,0,sizeof(cmd));

		}

		if ( ( gw_config->if_type == OVS_VLAN_IF_TYPE ) || ( gw_config->if_type == OVS_GRE_IF_TYPE ) )
		{
			snprintf(cmd,sizeof(cmd),"ifconfig %s up;\
				vconfig add %s %d ;\
				ifconfig %s.%d up ;\
				brctl addif %s %s.%d",
				gw_config->parent_ifname,
				gw_config->parent_ifname,
				gw_config->vlan_id,
				gw_config->parent_ifname,
				gw_config->vlan_id,
				gw_config->parent_bridge,
				gw_config->parent_ifname,
				gw_config->vlan_id);
				system(cmd);
				memset(cmd,0,sizeof(cmd));

		}
				
		else
		{
			snprintf(cmd,sizeof(cmd),"brctl addif %s %s ;",gw_config->parent_bridge,gw_config->if_name);
			system(cmd);
		}

		}
#endif

        bridge_util_log("if_cmd:%d if_type:%d\n",gw_config->if_cmd,gw_config->if_type);
		if ( IF_DELETE_CMD_TYPE == gw_config->if_cmd)
		{

			if ( gw_config->if_type == BRIDGE_IF_TYPE_VALUE )
			{

#ifdef CORE_NET_LIB
                struct bridge_info bridge_Init;
				int i=0;
				bridge_util_log("CORE_NET_LIB gw_config->if_name:%s using core net lib\n",gw_config->if_name);
				bridge_get_info(gw_config->if_name,&bridge_Init);
				for(i=0;i<bridge_Init.slave_count;i++)
				{
					bridge_util_log("CORE_NET_LIB slave_name[%d]:%s using core net lib\n",i,bridge_Init.slave_name[i]);
					interface_remove_from_bridge (bridge_Init.slave_name[i]); //or
					interface_delete(bridge_Init.slave_name[i]);
				}
				interface_down(gw_config->if_name);
				bridge_delete(gw_config->if_name);
#else
				snprintf(cmd,sizeof(cmd),"for iface in `brctl show %s | sed '1d' | awk '{print $NF}'` ;\
					do \
					brctl delif %s $iface; \
					done ; \
					ifconfig %s down ; \
					brctl delbr %s ;",
					gw_config->if_name,
					gw_config->if_name,
					gw_config->if_name,
					gw_config->if_name);
				system(cmd);		

#endif
			}
			else if ((gw_config->if_type == VLAN_IF_TYPE_VALUE) || (gw_config->if_type == GRE_IF_TYPE_VALUE ))
			{

#ifdef CORE_NET_LIB
				bridge_util_log("CORE_NET_LIB parent_ifname:%s vlan_id:%d using core net lib\n",gw_config->parent_ifname,gw_config->vlan_id);
				snprintf(cmd,sizeof(cmd),"%s.%d",gw_config->parent_ifname,gw_config->vlan_id);
				interface_remove_from_bridge (cmd);
				memset(cmd,0,sizeof(cmd));
				snprintf(cmd,sizeof(cmd),"%s.%d",gw_config->parent_ifname,gw_config->vlan_id);
				vlan_delete(cmd);
#else
				snprintf(cmd,sizeof(cmd),"brctl delif %s %s.%d ;\
					vconfig rem %s.%d ;",
					gw_config->parent_bridge,
					gw_config->parent_ifname,
					gw_config->vlan_id,
					gw_config->parent_ifname,
					gw_config->vlan_id);
				system(cmd);
#endif		
			}
			else 
			{
#ifdef CORE_NET_LIB
				memset(cmd,0,sizeof(cmd));
				snprintf(cmd,sizeof(cmd),"%s.%d",gw_config->parent_ifname,gw_config->vlan_id);
				bridge_util_log("CORE_NET_LIB cmd:%s %dinterface remove from brdg\n",gw_config->parent_ifname,gw_config->vlan_id);
				interface_remove_from_bridge (cmd);
#else
				snprintf(cmd,sizeof(cmd),"brctl delif %s %s",gw_config->parent_bridge,gw_config->if_name);
				system(cmd);
#endif		
			}


		}
		else if ( BR_REMOVE_CMD_TYPE == gw_config->if_cmd )
		{
				if ( (gw_config->if_type == VLAN_IF_TYPE_VALUE ) || (gw_config->if_type == GRE_IF_TYPE_VALUE) )
				{
#ifdef CORE_NET_LIB
					interface_remove_from_bridge (gw_config->parent_ifname);
					memset(cmd,0,sizeof(cmd));
					snprintf(cmd,sizeof(cmd),"%s.%d",gw_config->parent_ifname,gw_config->vlan_id);
					bridge_util_log("CORE_NET_LIB cmd:parent_ifname:%s vlan_id:%dvlan_delete\n",gw_config->parent_ifname,gw_config->vlan_id);
					vlan_delete(cmd);
#else
					snprintf(cmd,sizeof(cmd),"brctl delif %s %s ;\
						vconfig rem %s.%d ;",
						gw_config->parent_bridge,
						gw_config->parent_ifname,
						gw_config->parent_ifname,
						gw_config->vlan_id);
					system(cmd);
#endif			
				}

				else 
				{
#ifdef CORE_NET_LIB
					interface_remove_from_bridge (gw_config->if_name);	
#else
					snprintf(cmd,sizeof(cmd),"brctl delif %s %s",gw_config->parent_bridge,gw_config->if_name);
					system(cmd);
#endif	
				}
		}
		else if (IF_DOWN_CMD_TYPE == gw_config->if_cmd)
		{
					if ( gw_config->if_name[0] != '\0' )
					{
#ifdef CORE_NET_LIB
						interface_down(gw_config->if_name);
#else
						snprintf(cmd,sizeof(cmd),"ifconfig %s down",gw_config->if_name);
						system(cmd);
#endif
					}
		}
		else if (IF_UP_CMD_TYPE == gw_config->if_cmd )
		{
			if ( gw_config->parent_bridge[0] != '\0' )
			{

#ifdef CORE_NET_LIB
				struct bridge_info check_bridge;
				bridge_util_log("CORE_NET_LIB cmd:%s using core net lib\n",gw_config->parent_bridge);
				bridge_get_info(gw_config->parent_bridge,&check_bridge);
				if(check_bridge.slave_count==0)
				{
					bridge_create(gw_config->parent_bridge);
					interface_up(gw_config->parent_bridge);
				}
#else
				snprintf(cmd,sizeof(cmd),"check_bridge=`brctl show %s` ;\
					if [ \"$check_bridge\" = \"\" ];\
					then \
						brctl addbr %s ;\
						ifconfig %s up ; \
					fi ;",
					gw_config->parent_bridge,
					gw_config->parent_bridge,
					gw_config->parent_bridge);
					system(cmd);
					memset(cmd,0,sizeof(cmd));
#endif
			}

			if ( ( gw_config->if_type == VLAN_IF_TYPE_VALUE ) || ( gw_config->if_type == GRE_IF_TYPE_VALUE ) )
			{
				#ifdef CORE_NET_LIB
				    struct bridge_info bridge_Init;
					char ifname[64],ifname_buf[64];
					int i=0,If_name_status=0;
					bridge_get_info(gw_config->parent_bridge,&bridge_Init);
					snprintf(ifname,sizeof(ifname),"%s.%d",gw_config->if_name,gw_config->vlan_id);
					bridge_util_log("CORE_NET_LIB ifname:%s parent_bridge:%s using core net lib\n",ifname,gw_config->parent_bridge);
					for(i=0;i<bridge_Init.slave_count;i++)
					{
						bridge_util_log("CORE_NET_LIB slave_name:%s using core net lib\n",bridge_Init.slave_name[i]);
						if(strcmp(bridge_Init.slave_name[i],ifname)==0)
						{
							interface_delete(ifname);
						}
						
					}
					memset(&bridge_Init,0,sizeof(bridge_Init));
					bridge_get_info(gw_config->parent_bridge,&bridge_Init);
					for(i=0;i<bridge_Init.slave_count;i++)
					{
						if(strcmp(bridge_Init.slave_name[i],ifname)==0)
						{
							If_name_status=1; // gw_config->if_name,gw_config->vlan_id Interface exist
						}
					}
					if(If_name_status==0) //gw_config->if_name,gw_config->vlan_id not there in bridge
					{
						interface_up(gw_config->parent_ifname); //ifconfig %s up;	
						vlan_create(gw_config->parent_ifname,gw_config->vlan_id); //vconfig add %s %d ;
						snprintf(ifname_buf,sizeof(ifname_buf),"%s.%d",gw_config->parent_ifname,gw_config->vlan_id);
						interface_up(ifname_buf);//ifconfig %s.%d up ;
						interface_up(gw_config->parent_bridge);//ifconfig %s up ;
						interface_add_to_bridge(gw_config->parent_bridge,ifname_buf);//brctl addif %s %s.%d ;
					}
				#else
				snprintf(cmd,sizeof(cmd),"for bridge in `brctl show | cut -f1 | awk 'NF > 0' | sed '1d' | grep -v %s `;\
					do \
					check_if_attached=`brctl show $bridge | grep \"%s.%d\"` ; \
					if [ \"$check_if_attached\" != \"\" ] ;\
					then\
						echo \"deleting %s.%d from $bridge\" ;\
					        brctl delif $bridge %s.%d ; \
					fi ;\
					done ;\
					check_if_exist=`brctl show %s | grep \"%s.%d\"` ; \
					if [ \"$check_if_exist\" = \"\" ]; \
					then \
						ifconfig %s up;\
						vconfig add %s %d ;\
						ifconfig %s.%d up ;\
						ifconfig %s up ;\
						brctl addif %s %s.%d ;\
					fi ;",
					gw_config->parent_bridge,
					gw_config->if_name,
					gw_config->vlan_id,
					gw_config->if_name,
					gw_config->vlan_id,
					gw_config->if_name,
					gw_config->vlan_id,
					gw_config->parent_bridge,
					gw_config->if_name,
					gw_config->vlan_id,
					gw_config->parent_ifname,
					gw_config->parent_ifname,
					gw_config->vlan_id,
					gw_config->parent_ifname,
					gw_config->vlan_id,
					gw_config->parent_bridge,	
					gw_config->parent_bridge,
					gw_config->parent_ifname,
					gw_config->vlan_id);	
				#endif
			}
			else
			{
				#ifdef CORE_NET_LIB
				    struct bridge_info bridge_Init;
					char ifname[64];
					int i=0,If_name_status=0;
					bridge_util_log("CORE_NET_LIB ifname:%s parent_bridge:%s using core net lib\n", gw_config->if_name,gw_config->parent_bridge);
					bridge_get_info(gw_config->parent_bridge,&bridge_Init);
					snprintf(ifname,sizeof(ifname),"%s.",gw_config->if_name);
					for(i=0;i<bridge_Init.slave_count;i++)
					{
						if((strcmp(bridge_Init.slave_name[i],gw_config->if_name)==0)||(strncmp(bridge_Init.slave_name[i],ifname,strlen(ifname))==0))
						{
							interface_delete(gw_config->if_name);// brctl delif $bridge %s ;
						}
					}

					memset(&bridge_Init,0,sizeof(bridge_Init));
					bridge_get_info(gw_config->parent_bridge,&bridge_Init);
					for(i=0;i<bridge_Init.slave_count;i++)
					{
						if((strcmp(bridge_Init.slave_name[i],gw_config->if_name)==0)||(strncmp(bridge_Init.slave_name[i],ifname,strlen(ifname))==0))
						{
							If_name_status=1; // gw_config->if_name Interface exist
						}
					}
					if(If_name_status==0) //gw_config->if_name not there in bridge
					{
						interface_up(gw_config->parent_bridge); //ifconfig %s up;	
						interface_add_to_bridge(gw_config->parent_bridge,gw_config->if_name);//brctl addif %s %s ;
					}
				#else
				snprintf(cmd,sizeof(cmd),"for bridge in `brctl show | cut -f1 | awk 'NF > 0' | sed '1d' | grep -v %s `;\
					do \
					check_if_attached=`brctl show $bridge | grep \"%s\" | grep -v \"%s.\"` ; \
					if [ \"$check_if_attached\" != \"\" ] ;\
						then\
					        echo \"deleting %s from $bridge\" ;\
					        brctl delif $bridge %s ; \
					 fi ;\
					 done ;\
					 check_if_exist=`brctl show %s | grep \"%s\" | grep -v \"%s.\"` ; \
					 if [ \"$check_if_exist\" = \"\" ]; \
					 then \
					 	ifconfig %s up ;\
					    	brctl addif %s %s ;\
					 fi ;",
					 gw_config->parent_bridge,
					 gw_config->if_name,
					 gw_config->if_name,
					 gw_config->if_name,
					 gw_config->if_name,
					 gw_config->parent_bridge,
					 gw_config->if_name,
					 gw_config->if_name,
					 gw_config->parent_bridge,
					 gw_config->parent_bridge,
					 gw_config->if_name);
				#endif	
				}

				#ifndef CORE_NET_LIB
				system(cmd);
				#endif

		}
	return true ;
}
