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
#include <rdk_linkedlist.h>

/****************************************************************************/
/*                          DEFINES:                                        */
/****************************************************************************/

/* 
   Explicit freeing may be useful to prevent warnings when testing with
   Valgrind etc, but in the normal case it's more efficient to let all
   allocated memory be freed automatically when the application exits.
*/
//#define FREE_MEMORY_BEFORE_EXIT

typedef struct node
{
    char *line;
}
node_t;

/****************************************************************************
 * Name          : saveListToFile
 * Purpose       : Save the contents in a linked list to a file
 * Parameters    :
 *   node_head - First node in a linked-list
 *   filename  - Filename to save the contents of a linked-list
 * Return Values : 0 on success, -1 on error
 ****************************************************************************/
static int saveListToFile (rdkList_t *node_head, char *filename)
{
    FILE *fptr;
    rdkList_t *element;

    if ((fptr = fopen(filename, "w")) == NULL)
    {
        return -1;
    }

    element = node_head;

    while (element != NULL)
    {
        node_t *tmp = element->m_pUserData;

        if (tmp->line)
        {
            fprintf(fptr, "%s", tmp->line);
        }

        element = rdk_list_find_next_node(element);
    }

    /*
       Complete the file by adding </Provision> at the end.
    */
    fprintf(fptr, "</Provision>\n");

    fclose(fptr);

    return 0;
}

/****************************************************************************
 * Name          : createNode
 * Purpose       : Create a node and populate it with the given data.
 * Parameters    :
 *   node      - Address of the node
 *   data      - Line which has to be added to the node
 * Return Values : void
 ****************************************************************************/
static void createNode (node_t **node, char *data)
{
    *node = malloc(sizeof(node_t));

    if (*node == NULL)
    {
        return;
    }

    if (data == NULL)
    {
        (*node)->line = NULL;
    }
    else
    {
        (*node)->line = strdup(data);
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
static int parseFile (char *file_name, rdkList_t **node_head)
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
            *node_head = rdk_list_prepend_node(*node_head, node);
        }
    }

    if (line)
        free(line);

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
static void clearNode (void *node)
{
    node_t *tmp = (node_t *)(node);

    if (tmp != NULL)
    {
        if (tmp->line != NULL)
        {
            free(tmp->line);
            tmp->line = NULL;
        }

        free(tmp);
    }
}

#if defined (FREE_MEMORY_BEFORE_EXIT)

/****************************************************************************
 * Name          : clearAllNodes
 * Purpose       : Api to free a linked-list
 * Parameters    :
 *   node_head - Address of the first node in a linked-list
 * Return Values : void
 ****************************************************************************/
static clearAllNodes (rdkList_t **node_head)
{
    rdk_list_free_all_nodes_custom(*node_head, &clearNode);
}

#endif

/****************************************************************************
 * Name          : comparePattern
 * Purpose       : Helper api to search for a particular pattern from a node
 * Parameters    :
 *   node      - Address of a node in the linked-list
 *   pattern   - String which has to be compared
 * Return Values : 0 on success, -1 on error
 ****************************************************************************/
static int comparePattern (const void *node, const void *pattern)
{
    node_t *tmp = (node_t *)node;
    char *tmp_pattern = (char *)pattern;

    if (tmp && tmp->line && tmp_pattern)
    {
        if (strstr(tmp->line, tmp_pattern) != NULL)
        {
            return 0;
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
static void insertOrReplaceNode (rdkList_t **node_head, char *pattern, char *line)
{
    rdkList_t *match = NULL;

    /* Create a node with the current line */
    node_t *node = NULL;
    createNode(&node, line);

    /* If node_head is null, then match will be null. In this case only add the customer-specific file to the linked-list */
    match = rdk_list_find_node_custom(*node_head, pattern, (fnRDKListCustomCompare)comparePattern);
    if (match != NULL)
    {
        if (node != NULL)
            *node_head = rdk_list_add_node_before(*node_head, match, node);

        *node_head = rdk_list_remove_node(*node_head, match);
        clearNode(match->m_pUserData);
        rdk_list_free_all_nodes(match);
        match = NULL;
    }
    else
    {
        if (node != NULL)
            *node_head = rdk_list_prepend_node(*node_head, node);
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
static int applyCustomerDefaults (const char *src, rdkList_t **node_head)
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

    while ((count = getline(&line, &line_len, sfp)) > 0)
    {
        char *unmodified_line = malloc(count + 1);

        if (unmodified_line == NULL)
        {
            break;
        }

        memcpy(unmodified_line, line, count + 1);

        /* Parse the name from a line. Example of a line:  <Record name="ClientSteerEnable" type="astr">False</Record> */
        char *_ptr = strtok(line, " ");
        char *name = strtok(NULL, " ");

        if (name != NULL)
        {
            insertOrReplaceNode(node_head, name, unmodified_line);
        }

        free(unmodified_line);
    }

    if (line)
        free(line);

    fclose(sfp);

    return 0;
}

int main (int argc, char **argv)
{
    char cus_buff[8];
    char cus_def_file[50];
    int customer_index;
    int rc = -1;
    rdkList_t *node_head = NULL;

    parseFile("/usr/ccsp/config/bbhm_def_cfg.xml", &node_head);

    /*
       If parsing the main .xml file failed then manually add "<Provision>" as
       the first node in the linked-list (since the customer specific .xml
       files expect to be appended to an .xml file which includes one and so
       don't include one of their own).
       This is quite an obscure corner case. In reality, any failure to parse
       the main .xml file should probably be a fatal error...
    */
    if (node_head == NULL)
    {
        node_t *node = NULL;
        char *heading = "<Provision>\n";

        createNode(&node, heading);
        if (node != NULL)
        {
            node_head = rdk_list_prepend_node(node_head, node);
        }
    }

    if (syscfg_get(NULL, "Customer_Index", cus_buff, sizeof(cus_buff)) == 0)
    {
        customer_index = atoi(cus_buff);

        if (customer_index > 0)
        {
            snprintf(cus_def_file, sizeof(cus_def_file), "/etc/utopia/defaults/lg_bbhm_cust_%d.xml", customer_index);
            applyCustomerDefaults(cus_def_file, &node_head);
        }
    }

    /*
       As an optimisation, nodes are prepended to the list during parsing, and
       so need to be reversed before writing to the outut file...
    */
    node_head = rdk_list_reverse(node_head);

    rc = saveListToFile(node_head, "/tmp/lg_bbhm_def_cfg.xml");

#if defined (FREE_MEMORY_BEFORE_EXIT)
    clearAllNodes(&node_head);
#endif

    return rc;
}
