/*****************************************************************************
*
* Copyright 2020 Liberty Global B.V.
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
*****************************************************************************/

/****************************************************************************/
/*                          HEADERS:                                        */
/****************************************************************************/

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syscfg/syscfg.h>
#include <glib.h>

/****************************************************************************/
/*                          DEFINES:                                        */
/****************************************************************************/

#define BBHM_DEF_FILE "/usr/ccsp/config/bbhm_def_cfg.xml"
#define BBHM_CUS_DEF_FILE "/etc/utopia/defaults/lg_bbhm_cust_%d.xml"
#define BBHM_NEW_DEF_FILE "/tmp/lg_bbhm_def_cfg.xml"

typedef struct node
{
    char *line;
} node_t;

/****************************************************************************
 * Name          : saveListToFile
 * Purpose       : Save the contents in a linked list to a file
 * Parameters    :
 *   node_head - First node in a linked-list
 *   filename  - Filename to save the contents of a linked-list
 * Return Values : 0 on success, -1 on error
 ****************************************************************************/
int saveListToFile(GList *node_head, char *filename)
{
    GList *element = node_head;
    node_t *tmp = NULL;
    int rc = -1;

    FILE *fptr = fopen(filename, "w");
    if (fptr != NULL && element != NULL)
    {
        while (element != NULL)
        {
            tmp = element->data;
            if (tmp->line)
                fprintf(fptr, "%s", tmp->line);
            element = g_list_next(element);
        }
        /* Complete the file by adding </Provision> at the end */
        fprintf(fptr, "</Provision>\n");
        rc = 0;
    }
    if (fptr)
        fclose(fptr);

    return rc;
}

/****************************************************************************
 * Name          : createNode
 * Purpose       : Create a node and populate it with the given data.
 * Parameters    :
 *   node      - Address of the node
 *   data      - Line which has to be added to the node
 * Return Values : void
 ****************************************************************************/
void createNode(node_t **node, char *data)
{
    *node = (node_t *)malloc(sizeof(node_t));
    if (*node != NULL)
    {
        (*node)->line = NULL;
        if (data != NULL)
        {
            (*node)->line = (char *)malloc((strlen(data) + 1) * sizeof(char));
            if ((*node)->line != NULL)
            {
                strncpy((*node)->line, data, strlen(data));
                (*node)->line[strlen(data)] = '\0';
            }
        }
    }
}

/****************************************************************************
 * Name          : parseFile
 * Purpose       : Read from a file line by line and add it to a linked-list
 * Parameters    :
 *   node_head - Address of the first node in a linked-list
 *   file_name - Name of the file which has to be added to a linked-list
 * Return Values : 0 on success, -1 on error
 ****************************************************************************/
int parseFile(char *file_name, GList **node_head)
{
    FILE *sfp;
    int count;
    char *line = NULL;
    size_t line_len = 0;
    node_t *node;
    int i = 0;

    if ((sfp = fopen(file_name, "r")) == NULL)
    {
        printf("%s: Skipping %s - %s\n", __func__, file_name, strerror(errno));
        return -1;
    }

    while (0 < (count = getline(&line, &line_len, sfp)))
    {
        node = NULL;
        /* Don't save </Provision> line in linked list */
        if (strstr(line, "</Provision>"))
        {
            continue;
        }

        createNode(&node, line);
        if (node != NULL)
        {
            /* Instead of append, prepend it and reverse it finally. This will reduce the iteration time */
            *node_head = g_list_prepend(*node_head, node);
        }
    }

    if (line)
        free(line);
    if (sfp)
        fclose(sfp);
    return 0;
}

/****************************************************************************
 * Name          : clearNode
 * Purpose       : Helper api to free a node of a linked-list
 * Parameters    :
 *   node      - Address of a node in the linked-list
 * Return Values : void
 ****************************************************************************/
void clearNode(gpointer node)
{
    node_t *tmp = (node_t *)(node);
    if (NULL != tmp)
    {
        if (NULL != tmp->line)
        {
            free(tmp->line);
            tmp->line = NULL;
        }
        free(tmp);
        tmp = NULL;
    }
}

/****************************************************************************
 * Name          : clearAlNodes
 * Purpose       : Api to free a linked-list
 * Parameters    :
 *   node_head - Address of the first node in a linked-list
 * Return Values : void
 ****************************************************************************/
void clearAlNodes(GList **node_head)
{
    g_list_free_full(*node_head, &clearNode);
}

/****************************************************************************
 * Name          : comparePattern
 * Purpose       : Helper api to search for a particular pattern from a node
 * Parameters    :
 *   node      - Address of a node in the linked-list
 *   pattern   - String which has to be compared
 * Return Values : 0 on success, -1 on error
 ****************************************************************************/
gint comparePattern(gconstpointer node, gconstpointer pattern)
{
    node_t *tmp = (node_t *)node;
    char *tmp_pattern = (char *)pattern;
    if (tmp && tmp->line && tmp_pattern)
    {
        if (NULL != strstr(tmp->line, tmp_pattern))
        {
            return 0;
        }
        else
        {
            return -1;
        }
    }
    return -1;
}

/****************************************************************************
 * Name          : insertOrReplaceNode
 * Purpose       : Search for the given pattern in the linked-list. If found replace the old line
 *                 with new line. If not found, add the new line at the beginning of the linked-list
 * Parameters    :
 *   node_head - Address of the first node in a linked-list
 *   pattern   - String which has to be compared
 *   line      - Line which has to be added to the linked-list
 * Return Values : void
****************************************************************************/
void insertOrReplaceNode(GList **node_head, char *pattern, char *line)
{
    GList *match = NULL;

    /* Create a node with the current line */
    node_t *node = NULL;
    createNode(&node, line);

    /* If node_head is null, then match will be null. In this case only add the customer-specific file to the linked-list */
    match = g_list_find_custom(*node_head, pattern, (GCompareFunc)comparePattern);
    if (NULL != match)
    {
        if (node != NULL)
            *node_head = g_list_insert_before(*node_head, match, node);

        *node_head = g_list_remove_link(*node_head, match);
        clearNode(match->data);
        g_list_free(match);
        match = NULL;
    }
    else
    {
        if (node != NULL)
            *node_head = g_list_prepend(*node_head, node);
    }
}

/****************************************************************************
 * Name          : applyCustomerDefaults
 * Purpose       : Read from the given file and add/replace the nodes from the linked-list
 *                 based on the content.
 * Parameters    :
 *   node_head - Address of the first node in a linked-list. node_head will be null if
 *               base defaults file parsing failed.
 *   src       - String which has to be compared
 * Return Values : 0 on success, -1 on error
****************************************************************************/
int applyCustomerDefaults(const char *src, GList **node_head)
{
    FILE *sfp;
    int count = 0;
    char *line = NULL;
    size_t line_len = 0;

    if ((sfp = fopen(src, "r")) == NULL)
    {
        printf("%s: Skipping %s - %s\n", __func__, src, strerror(errno));
        return -1;
    }

    while (0 < (count = getline(&line, &line_len, sfp)))
    {
        char *unmodified_line = (char *)malloc(count + 1);
        if (unmodified_line != NULL)
        {
            memcpy(unmodified_line, line, count);
            unmodified_line[count] = '\0';
        }

        /* Parse the name from a line. Example of a line:  <Record name="ClientSteerEnable" type="astr">False</Record> */
        char *_ptr = strtok(line, " ");
        char *name = strtok(NULL, " ");

        if (name == NULL)
        {
            if (unmodified_line)
                free(unmodified_line);
            continue;
        }

        insertOrReplaceNode(node_head, name, unmodified_line);

        if (unmodified_line)
            free(unmodified_line);
    }

    if (sfp)
        fclose(sfp);
    if (line)
        free(line);
    return 0;
}

int main(int argc, char **argv)
{
    int rc = -1;
    char cus_buff[4] = {0};
    char cus_def_file[50] = {0};
    int customer_index = 0;
    if (argc == 1)
    {
        GList *node_head = NULL;
        int default_parsed = parseFile(BBHM_DEF_FILE, &node_head);

        if (syscfg_init() == 0)
        {
            syscfg_get(NULL, "Customer_Index", cus_buff, sizeof(cus_buff));
            customer_index = atoi(cus_buff);
            if (customer_index > 0)
            {
                /* If "/usr/ccsp/config/bbhm_def_cfg.xml" file parsing failed,
                we still need to parse "/etc/utopia/defaults/lg_bbhm_cust_%d.xml" file.
                Since lg_bbhm_cust_%d.xml file doesn't contain the first line as "<Provision>",
                add "<Provision>" as the first node in linked-list. */
                if (default_parsed == -1)
                {
                    node_t *node = NULL;
                    char heading[] = "<Provision>\n";
                    createNode(&node, heading);
                    if (node != NULL)
                        node_head = g_list_prepend(node_head, node);
                }

                snprintf(cus_def_file, sizeof(cus_def_file), BBHM_CUS_DEF_FILE, customer_index);
                applyCustomerDefaults(cus_def_file, &node_head);
            }
        }

        node_head = g_list_reverse(node_head);
        rc = saveListToFile(node_head, BBHM_NEW_DEF_FILE);
        clearAlNodes(&node_head);
        node_head = NULL;
    }

    return rc;
}
