/*
 * If not stated otherwise in this file or this component's Licenses.txt file
 * the following copyright and licenses apply:
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "servicecontrol_rbus_handler_apis.h"
#include "servicecontrol_apis.h"
#include "servicecontrol_log.h"

#include <pthread.h>
#include <stdbool.h>
#include "collection.h"
#include <unistd.h>
// Global variables
queue_t *svc_queue;
pthread_cond_t svcCond;
pthread_mutex_t svcMutex;
pthread_mutex_t gVarMutex;
bool svc_queue_wakeup;
bool exit_svc_queue_loop;

char *g_pServiceList = NULL;
rbusHandle_t g_rbusHandle;

char const* GetParamName(char const* path)
{
    char const* p = path + strlen(path);
    while(p > path && *(p-1) != '.')
        p--;
    return p;
}

int ServiceControl_Init()
{
    int ret = 0;
    SvcCtrlDebug(("In %s\n", __FUNCTION__));
    pthread_mutex_init(&svcMutex, NULL);
    pthread_mutex_init(&gVarMutex, NULL);
    pthread_cond_init(&svcCond, NULL);
    pthread_mutex_lock(&svcMutex);
    g_pServiceList = (char *) malloc(1024*sizeof(char));
    if (g_pServiceList == NULL)
    {
        SvcCtrlError(("%s : memory allocation for g_pServiceList failed.\n", __FUNCTION__));
        ret = -1;
    }
    svc_queue = queue_create();
    if (svc_queue == NULL)
    {
        SvcCtrlError(("Failed to allocate service queue\n"));
        ret = -1;
    }
    svc_queue_wakeup = false;
    exit_svc_queue_loop = false;
    pthread_mutex_unlock(&svcMutex);
    SvcCtrlDebug(("Out %s\n", __FUNCTION__));
    return ret;
}

void ServiceControl_Deinit()
{
    SvcCtrlDebug(("In %s\n", __FUNCTION__));
    // Gracefully exit the thread
    pthread_mutex_lock(&svcMutex);
    free(g_pServiceList);
    exit_svc_queue_loop = true;
    svc_queue_wakeup = true;
    if (svc_queue)
    {
        queue_destroy(svc_queue);
    }
    pthread_mutex_unlock(&svcMutex);
    pthread_cond_signal(&svcCond);
    // Destroy pthread mutex and condition
    pthread_mutex_destroy(&svcMutex);
    pthread_mutex_destroy(&gVarMutex);
    pthread_cond_destroy(&svcCond);
    SvcCtrlDebug(("Out %s\n", __FUNCTION__));
}

void *svc_restart_queue_loop(void *arg)
{
    UNREFERENCED_PARAMETER(arg);
    SvcCtrlDebug(("In %s\n", __FUNCTION__));
    char *queue_data = NULL;
    int result = 0;
    while (1)
    {
        pthread_mutex_lock(&svcMutex);
        while (!svc_queue_wakeup)
        {
            pthread_cond_wait(&svcCond, &svcMutex);
        }
        if (exit_svc_queue_loop)
        {
            pthread_mutex_unlock(&svcMutex);
            break;
        }
        while (queue_count(svc_queue))
        {
            queue_data = queue_pop(svc_queue);
            if (queue_data == NULL)
            {
                continue;
            }
            SvcCtrlInfo(("systemctl restart %s\n", queue_data));
            result = v_secure_system("systemctl restart %s", queue_data);
            if (result == 0)
            {
                SvcCtrlInfo(("Process %s successfully restarted.\n", queue_data));
            }
            else
            {
                SvcCtrlError(("Failed to restart process %s.\n", queue_data));
            }
            free(queue_data);
        }
        svc_queue_wakeup = false;
        pthread_mutex_unlock(&svcMutex);
    }
    SvcCtrlDebug(("Out %s\n", __FUNCTION__));
    return NULL;
}

int spawn_svc_restart_queue_loop()
{
    SvcCtrlDebug(("In %s\n", __FUNCTION__));
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t thr = 0;

    int err = pthread_create(&thr, &attr, &svc_restart_queue_loop, NULL);
    if (err)
    {
        SvcCtrlError(("Failed to start service restart queue loop thread\n"));
        return err;
    }

    pthread_attr_destroy(&attr);
    SvcCtrlDebug(("Out %s\n", __FUNCTION__));
    return err;
}

int push_svc_to_queue(char *buffer)
{
    SvcCtrlDebug(("In %s\n", __FUNCTION__));
    char *queue_data = NULL;
    char *token = NULL;
    pthread_mutex_lock(&svcMutex);
    token = strtok(buffer, ",");
    while (token != NULL)
    {
        queue_data = strdup(token);
        queue_push(svc_queue, queue_data);
        token = strtok(NULL, ",");
    }
    svc_queue_wakeup = true;
    free(buffer);
    pthread_mutex_unlock(&svcMutex);
    pthread_cond_signal(&svcCond);
    SvcCtrlDebug(("Out %s\n", __FUNCTION__));
    return 0;
}

int ServiceControl_Get_Sevice_Restart_List(char *pString)
{
    SvcCtrlDebug(("In %s\n", __FUNCTION__));
    pthread_mutex_lock(&gVarMutex);
    strncpy(pString, g_pServiceList, strlen(g_pServiceList)+1);
    pthread_mutex_unlock(&gVarMutex);
    SvcCtrlInfo(("%s : got string %s\n", __FUNCTION__, pString));
    SvcCtrlDebug(("Out %s\n", __FUNCTION__));
    return 0;
}

int ServiceControl_Set_Sevice_Restart_List(char *pString)
{
    char *services = NULL;
    SvcCtrlDebug(("In %s\n", __FUNCTION__));
    SvcCtrlInfo(("%s : setting string %s\n", __FUNCTION__, pString));
    pthread_mutex_lock(&gVarMutex);
    strncpy(g_pServiceList, pString, strlen(pString)+1);
    services = strdup(g_pServiceList);
    pthread_mutex_unlock(&gVarMutex);
    push_svc_to_queue(services);
    SvcCtrlDebug(("Out %s\n", __FUNCTION__));
    return 0;
}
