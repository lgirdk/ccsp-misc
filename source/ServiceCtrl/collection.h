/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2023 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
**************************************************************************/

#ifndef _COLLECTION_H_
#define _COLLECTION_H_

#include <stdint.h>
#include <stdbool.h>

typedef struct element_t {
    void     *data;
    struct element_t *next;
} element_t;

typedef struct {
    element_t    *head;
    uint32_t count;
} queue_t;

// queue operations
queue_t     *queue_create    (void);
void        queue_destroy    (queue_t *q);
int8_t        queue_push        (queue_t *q, void *data);
void        *queue_pop        (queue_t *q);
void        *queue_remove      (queue_t *q, uint32_t n);
void        *queue_peek     (queue_t *q, uint32_t n);
uint32_t     queue_count        (queue_t *q);

#endif // _COLLECTION_H_

