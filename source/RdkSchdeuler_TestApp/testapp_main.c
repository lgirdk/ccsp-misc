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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "scheduler_interface.h"
#include "cJSON.h"


void test_json_schedule( char* json_path, char* key)
{
    if (json_path == NULL) {
        printf("Json path is null.\n");
        return;
    }

    if (key == NULL) {
        printf("Json key is null.\n");
        return;
    }

    // Read the JSON data from the file
    FILE *file = fopen(json_path, "r");
    if (!file) {
        printf("Failed to open the file.\n");
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    /* CID 347146 Argument cannot be negative */
    if(file_size < 0)
    {
        printf("File size error \n");
	fclose(file);
	return;
    }

    fseek(file, 0, SEEK_SET);

    char *json_data = (char *)malloc(file_size + 1);

    /* CID 347147 Ignoring number of bytes */
    int num_read = 0;
    if( ( num_read = fread(json_data, 1, file_size, file)) > 0 )
    {
        json_data[file_size] = '\0';
        fclose(file);
    }
    else
    {
        printf("fread failed \n");
        fclose(file);
        free(json_data);
        return;
    }

    // Parse the JSON data
    cJSON *json = cJSON_Parse(json_data);
    if (!json) {
        printf("Failed to parse JSON data.\n");
        free(json_data);
        return;
    }

    // Allocate memory for schedule_info_t
    schedule_info_t *schedule_info = (schedule_info_t *)malloc(sizeof(schedule_info_t));
    memset(schedule_info, 0, sizeof(schedule_info_t));

    // Populate actions list
    cJSON *actions_array = cJSON_GetObjectItem(json, key);
    if (actions_array) {
        int actions_count = cJSON_GetArraySize(actions_array);
        schedule_info->actions_size = actions_count;
        schedule_info->actions = (char **)malloc(sizeof(char *) * actions_count);

        for (int i = 0; i < actions_count; i++) {
            cJSON *action_item = cJSON_GetArrayItem(actions_array, i);
            const char *action_str = action_item->valuestring;
            schedule_info->actions[i] = strdup(action_str); // Make a copy of the string
        }
    }

    // Populate absolute schedule
    cJSON *absolute_array = cJSON_GetObjectItem(json, "absolute");
    if (absolute_array) {
        int absolute_count = cJSON_GetArraySize(absolute_array);
        schedule_info->absolute_size = absolute_count;
        schedule_info->absolute = (input_t *)malloc(sizeof(input_t) * absolute_count);

        for (int i = 0; i < absolute_count; i++) {
            cJSON *entry = cJSON_GetArrayItem(absolute_array, i);
            cJSON *time_item = cJSON_GetObjectItem(entry, "unix_time");
            cJSON *indexes = cJSON_GetObjectItem(entry, "indexes");

            if (time_item && indexes) {
                schedule_info->absolute[i].time = time_item->valueint;

                int absolute_indexes_size =  cJSON_GetArraySize(indexes);

                if(absolute_indexes_size > 0) {
                    schedule_info->absolute[i].action_count = absolute_indexes_size;
                    
                    for (int j=0; j<absolute_indexes_size; j++) {
                        cJSON *index_item = cJSON_GetArrayItem(indexes, j);
                        if (index_item) {
                            schedule_info->absolute[i].action_indexes[j] = index_item->valueint;
                        } else {
                            printf("Failed to get index value.\n");
                        }
                        
                    }
                }
                else {
                    schedule_info->absolute[i].action_count = 0;
                }
            }
        }
    }

    // Populate weekly schedule
    cJSON *weekly_array = cJSON_GetObjectItem(json, "weekly");
    if (weekly_array) {
        int weekly_count = cJSON_GetArraySize(weekly_array);
        schedule_info->weekly_size = weekly_count;
        schedule_info->weekly = (input_t *)malloc(sizeof(input_t) * weekly_count);

        for (int i = 0; i < weekly_count; i++) {
            cJSON *entry = cJSON_GetArrayItem(weekly_array, i);
            cJSON *time_item = cJSON_GetObjectItem(entry, "unix_time");
            cJSON *indexes = cJSON_GetObjectItem(entry, "indexes");

            if (time_item && indexes) {
                schedule_info->weekly[i].time = time_item->valueint;

                int weekly_indexes_size =  cJSON_GetArraySize(indexes);

                if(weekly_indexes_size > 0) {
                    schedule_info->weekly[i].action_count = weekly_indexes_size;
                    
                    for (int j=0; j<weekly_indexes_size; j++) {
                        cJSON *index_item = cJSON_GetArrayItem(indexes, j);
                        if (index_item) {
                            schedule_info->weekly[i].action_indexes[j] = index_item->valueint;
                        } else {
                            printf("Failed to get index value.\n");
                        }
                    }
                }
                else {
                    schedule_info->weekly[i].action_count = 0;
                }
            }
        }
    }

    // Print the populated data for testing
    printf("Time Zone: %s\n", cJSON_GetObjectItem(json, "time_zone")->valuestring);
    printf("Actions:\n");
    for (size_t i = 0; i < schedule_info->actions_size; i++) {
        printf("%s\n", schedule_info->actions[i]);
    }
    printf("Absolute schedule:\n");
    for (size_t i = 0; i < schedule_info->absolute_size; i++) {
        printf("Unix Time: %ld\n", schedule_info->absolute[i].time);
        printf("Action Count: %u\n", schedule_info->absolute[i].action_count);
        for (size_t j = 0; j < schedule_info->absolute[i].action_count; j++) {
            printf("Action Index: %u\n", schedule_info->absolute[i].action_indexes[j]);
        }
    }
    printf("Weekly schedule:\n");
    for (size_t i = 0; i < schedule_info->weekly_size; i++) {
        printf("Unix Time: %ld\n", schedule_info->weekly[i].time);
        printf("Action Count: %u\n", schedule_info->weekly[i].action_count);
        for (size_t j = 0; j < schedule_info->weekly[i].action_count; j++) {
            printf("Action Index: %u\n", schedule_info->weekly[i].action_indexes[j]);
        }
    }

    run_schedule(schedule_info, key);

    // Cleanup
    free(json_data);
    cJSON_Delete(json);
    freeScheduleInfo(schedule_info);

}

void operation(char* actions, char* filename) {
    
    if(filename == NULL) {
        printf("Operation failed, filename is null\n");
        return;
    }

    if (actions != NULL) {
        FILE *outfile;

        printf("Scheduler Actions: %s --> %s\n", filename, actions);

        // open file for writing
        outfile = fopen(filename, "w");
        if (outfile == NULL)
        {
            fprintf(stderr, "\nError opened file\n");
            exit(1);
        }

        fwrite(actions, sizeof(char), strlen(actions), outfile);

        // close file
        fclose(outfile);
    }
    else {
        printf("Deleting file %s\n", filename);
        if (remove(filename) == 0) {
            printf("Deleted successfully\n");
        }
        else {
            printf("Unable to delete the file\n");
        }
    }
}

void schedule_operation_1(char* actions)
{
    printf("%s - writing macs [%s] to file\n", __func__, actions);

    char* filename = "/nvram/scheduler_1.txt";

    operation(actions, filename);
    
}

void schedule_operation_2(char* actions)
{
    printf("%s - writing macs [%s] to file\n", __func__, actions);

    char* filename = "/nvram/scheduler_2.txt";

    operation(actions, filename);
    
}

void schedule_operation_3(char* actions)
{
    printf("%s - writing macs [%s] to file\n", __func__, actions);

    char* filename = "/nvram/scheduler_3.txt";

    operation(actions, filename);
    
}

void schedule_operation_4(char* actions)
{
    printf("%s - writing macs [%s] to file\n", __func__, actions);

    char* filename = "/nvram/scheduler_4.txt";

    operation(actions, filename);
    
}

void schedule_operation_5(char* actions)
{
    printf("%s - writing macs [%s] to file\n", __func__, actions);

    char* filename = "/nvram/scheduler_5.txt";

    operation(actions, filename);
    
}

int main(int argc, char *argv[]) {

    (void) argc;
    (void) argv;

    if (argc < 3) {
        printf("Atlease one json_key and json_path is mandatory.\n");
        printf("Usage: ./rdkSchedulerTestApp <json_filepath_1> <json_key_1> <json_filepath_2> <json_key_2>...<json_filepath_5> <json_key_5>\n");
        return 1;
    }

    char* json_filepath_1 = NULL;
    char* json_filepath_2 = NULL;
    char* json_filepath_3 = NULL;
    char* json_filepath_4 = NULL;
    char* json_filepath_5 = NULL;

    int data_size = 0;

    /* CID 347148 Uninitialized pointer read fix */
    SchedulerData data[5] = {
	                    {NULL, NULL, NULL, schedule_operation_1, 0, 0},
			    {NULL, NULL, NULL, schedule_operation_1, 0, 0},
			    {NULL, NULL, NULL, schedule_operation_1, 0, 0},
			    {NULL, NULL, NULL, schedule_operation_1, 0, 0},
			    {NULL, NULL, NULL, schedule_operation_1, 0, 0}
                            };
    
    printf("Component main getting executed\n");

    SchedulerData data1 =  {
                                .data_file = "/nvram/rdkscheduler/rdk-scheduler1.dat",
                                .md5_file = "/nvram/rdkscheduler/rdk-scheduler1.dat.md5",
                                .max_actions = 0,
                                .scheduler_action = schedule_operation_1,
                                .instanceNum = 0
                            };

    SchedulerData data2 =  {
                                .data_file = "/nvram/rdkscheduler/rdk-scheduler2.dat",
                                .md5_file = "/nvram/rdkscheduler/rdk-scheduler2.dat.md5",
                                .max_actions = 0,
                                .scheduler_action = schedule_operation_2,
                                .instanceNum = 0
                            };

    SchedulerData data3 =  {
                                .data_file = "/nvram/rdkscheduler/rdk-scheduler3.dat",
                                .md5_file = "/nvram/rdkscheduler/rdk-scheduler3.dat.md5",
                                .max_actions = 0,
                                .scheduler_action = schedule_operation_3,
                                .instanceNum = 0
                            };

    SchedulerData data4 =  {
                                .data_file = "/nvram/rdkscheduler/rdk-scheduler4.dat",
                                .md5_file = "/nvram/rdkscheduler/rdk-scheduler4.dat.md5",
                                .max_actions = 0,
                                .scheduler_action = schedule_operation_4,
                                .instanceNum = 0
                            };

    SchedulerData data5 =  {
                                .data_file = "/nvram/rdkscheduler/rdk-scheduler5.dat",
                                .md5_file = "/nvram/rdkscheduler/rdk-scheduler5.dat.md5",
                                .max_actions = 0,
                                .scheduler_action = schedule_operation_5,
                                .instanceNum = 0
                            };


    if(argv[1]) {
        json_filepath_1 = strdup(argv[1]);
        if (argv[2]) {
            data1.scheduler_action_key = strdup(argv[2]);
            data[0] = data1;
        }
        else {
            printf("json key should not be empty for '%s'\n", argv[1]);
            return 1;
        }
    }

    if(argv[3]) {
        json_filepath_2 = strdup(argv[3]);
        if (argv[4]) {
            data2.scheduler_action_key = strdup(argv[4]);
            data[1] = data2;
        }
        else {
            printf("json key should not be empty for '%s'\n", argv[3]);
            return 1;
        }
    }

    if(argv[5]) {
        json_filepath_3 = strdup(argv[5]);
        if (argv[6]) {
            data3.scheduler_action_key = strdup(argv[6]);
            data[2] = data3;
        }
        else {
            printf("json key should not be empty for '%s'\n", argv[5]);
            return 1;
        }
    }

    if(argv[7]) {
        json_filepath_4 = strdup(argv[7]);
        if (argv[8]) {
            data4.scheduler_action_key = strdup(argv[8]);
            data[3] = data4;
        }
        else {
            printf("json key should not be empty for '%s'\n", argv[7]);
            return 1;
        }
    }

    if(argv[9]) {
        json_filepath_5 = strdup(argv[9]);
        if (argv[10]) {
            data5.scheduler_action_key = strdup(argv[10]);
            data[4] = data5;
        }
        else {
            printf("json key should not be empty for '%s'\n", argv[9]);
            return 1;
        }
    }

    data_size = (argc-1)/2;

    if (0 != scheduler_init(data, data_size, "")) {
        printf("Scheduler init failed\n");
    }

    sleep(1);

    if(data_size >= 1) {
        printf("Running scheduler for '%s'\n", argv[2]);
        test_json_schedule( json_filepath_1, data1.scheduler_action_key);
        free(json_filepath_1);
        free(data1.scheduler_action_key);
    }

    if(data_size >= 2) {
        printf("Running scheduler for '%s'\n", argv[4]);
        test_json_schedule( json_filepath_2, data2.scheduler_action_key);
        free(json_filepath_2);
        free(data2.scheduler_action_key);
    }

    if(data_size >= 3) {
        printf("Running scheduler for '%s'\n", argv[6]);
        test_json_schedule( json_filepath_3, data3.scheduler_action_key);
        free(json_filepath_3);
        free(data3.scheduler_action_key);
    }

    if(data_size >= 4) {
        printf("Running scheduler for '%s'\n", argv[8]);
        test_json_schedule( json_filepath_4, data4.scheduler_action_key);
        free(json_filepath_4);
        free(data4.scheduler_action_key);
    }

    if(data_size == 5) {
        printf("Running scheduler for '%s'\n", argv[10]);
        test_json_schedule( json_filepath_5, data5.scheduler_action_key);
        free(json_filepath_5);
        free(data5.scheduler_action_key);
    }

    while(1) {}

    return 0;
}
