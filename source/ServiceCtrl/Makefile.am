# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2023 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
bin_PROGRAMS = ServiceCtrl
ServiceCtrl_SOURCES = collection.c servicecontrol_log.c servicecontrol_apis.c servicecontrol_dml.c servicecontrol_rbus_handler_apis.c servicecontrol_main.c
ServiceCtrl_CPPFLAGS = -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus
ServiceCtrl_LDFLAGS = -lrbus -lpthread -lsecure_wrapper -lrdkloggers
