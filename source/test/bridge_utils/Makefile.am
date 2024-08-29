##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2020 RDK Management
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

AM_CFLAGS = -D_GNU_SOURCE
AM_CFLAGS += -fPIC -fno-exceptions -Os -Wall -Wextra

AM_CXXFLAGS = -std=c++11 -lstdc++fs

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = bridgeUtils_gtest.bin

bridgeUtils_gtest_bin_CPPFLAGS = -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/gtest \
                                 -I${top_srcdir}/gtest/include \
                                 -I${top_srcdir}/source \
                                 -I${top_srcdir}/source/include \
                                 -I$(top_srcdir)/source/bridge_utils/include \
                                 -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/ccsp \
                                 -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/ovsagent \
                                 -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/dbus-1.0 \
                                 -I${PKG_CONFIG_SYSROOT_DIR}$(libdir)/dbus-1.0/include \
                                 -I${PKG_CONFIG_SYSROOT_DIR}$(includedir) \
                                 $(DBUS_CFLAGS)

bridgeUtils_gtest_bin_SOURCES = bridgeUtilsTest.cpp \
                                gtest_main.cpp \
                                $(top_srcdir)/source/bridge_utils/bridge_utils_bin/bridge_util.c \
                                $(top_srcdir)/source/bridge_utils/bridge_utils_bin/bridge_creation.c \
                                mocks/mock_ovs.cpp \
                                mocks/mock_bridge_util_generic.cpp

bridgeUtils_gtest_bin_LDFLAGS = -lgtest -lgmock -lgcov -lrt -lpthread

bridgeUtils_gtest_bin_LDADD = \
    $(HOME)/usr/local/lib/libmock_fd.la \
    $(HOME)/usr/local/lib/libmock_util.la \
    $(HOME)/usr/local/lib/libmock_sysevent.la \
    $(HOME)/usr/local/lib/libmock_syscfg.la \
    $(HOME)/usr/local/lib/libmock_socket.la \
    $(HOME)/usr/local/lib/libmock_psm.la \
    $(HOME)/usr/local/lib/libmock_file_io.la \
    $(HOME)/usr/local/lib/libmock_secure_wrapper.la \
    $(HOME)/usr/local/lib/libmock_privilege.la \
    $(HOME)/usr/local/lib/libmock_ccsp_common.la

AM_CFLAGS += -fprofile-arcs -ftest-coverage
AM_CXXFLAGS += -fprofile-arcs -ftest-coverage
bridgeUtils_gtest_bin_LDFLAGS += --coverage

if CORE_NET_LIB_FEATURE_SUPPORT
bridgeUtils_gtest_bin_LDFLAGS += -lnet
endif
