/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2023 RDK Management
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
#if !defined(_SR213_PRODUCT_REQ_) && !defined (_WNXL11BWL_PRODUCT_REQ_) && !defined (_SCER11BEL_PRODUCT_REQ_)
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <telemetry_busmessage_sender.h>
#include "ccsp_trace.h"
#include "ccsp_memory.h"  // for AnscAllocate/FreeMemory
#include  "safec_lib_common.h"
#include "platform_hal.h"

FILE* logFp = NULL;

#define  FwBk_log( msg ...){ \
                ANSC_UNIVERSAL_TIME ut; \
                AnscGetLocalTime(&ut); \
                if ( logFp != NULL){ \
                fprintf(logFp, "%.2d%.2d%.2d-%.2d:%.2d:%.2d ", ut.Year,ut.Month,ut.DayOfMonth,ut.Hour,ut.Minute,ut.Second); \
                fprintf(logFp, msg);} \
}
#endif

int main()
{
#if !defined(_SR213_PRODUCT_REQ_) && !defined (_WNXL11BWL_PRODUCT_REQ_) && !defined (_SCER11BEL_PRODUCT_REQ_)
    int ret;
    int rc = -1;
    PFW_BANK_INFO pfw_bank=NULL;
    char t2_buff[200]={0};
    t2_init("TandD");
    logFp = fopen("/rdklogs/logs/SelfHeal.txt.0","a+") ;

    //get Active Bank Details
    pfw_bank=AnscAllocateMemory(sizeof(FW_BANK_INFO));
    ret=platform_hal_GetFirmwareBankInfo(ACTIVE_BANK, pfw_bank);
    if(ret == RETURN_ERR)
    {
        if(T2ERROR_SUCCESS != t2_event_d("SYS_ERROR_FW_ACTIVEBANK_FETCHFAILED", 1))
        {
            FwBk_log("FW_BANK_INFO:%d Error: T2 send Failed\n",__LINE__);
        }
        FwBk_log("  SYS_ERROR_FW_ACTIVEBANK_FETCHFAILED\n");
    }
    else
    {
        rc = sprintf_s(t2_buff, sizeof(t2_buff), "%s,%s", pfw_bank->fw_name,pfw_bank->fw_state);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        if(T2ERROR_SUCCESS != t2_event_s("FW_ACTIVEBANK_split", t2_buff))
        {
            FwBk_log("FW_BANK_INFO:%d Error: T2 send Failed\n",__LINE__);
        }
        FwBk_log("{\"FW_ACTIVEBANK_split\" : \"%s,%s\"} \n",pfw_bank->fw_name,pfw_bank->fw_state);
    }
    //re-initialize the variables
    memset(t2_buff,0,sizeof(t2_buff));
    memset( pfw_bank,0,sizeof(FW_BANK_INFO));
    ret=0;

    //get Inactive Bank details
    ret=platform_hal_GetFirmwareBankInfo(INACTIVE_BANK, pfw_bank);
    if(ret == RETURN_ERR)
    {
        if(T2ERROR_SUCCESS != t2_event_d("SYS_ERROR_FW_INACTIVEBANK_FETCHFAILED", 1))
        {
            FwBk_log("FW_BANK_INFO:%d Error: T2 send Failed\n",__LINE__);
        }
        FwBk_log("  SYS_ERROR_FW_INACTIVEBANK_FETCHFAILED\n");
    }
    else
    {
        rc = sprintf_s(t2_buff, sizeof(t2_buff), "%s,%s", pfw_bank->fw_name,pfw_bank->fw_state);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        if(T2ERROR_SUCCESS != t2_event_s("FW_INACTIVEBANK_split", t2_buff))
        {
            FwBk_log("FW_BANK_INFO:%d Error: T2 send Failed\n",__LINE__);
        }
        FwBk_log("{\"FW_INACTIVEBANK_split\" : \"%s,%s\"} \n",pfw_bank->fw_name,pfw_bank->fw_state);
    }
    AnscFreeMemory(pfw_bank);
    fclose(logFp);
    t2_uninit();
#endif
    return 0;
}
