/*
* If not stated otherwise in this file or this component's LICENSE file the
* following copyright and licenses apply:
*
* Copyright 2020 RDK Management
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

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <experimental/filesystem>
#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include <mocks/mock_syscfg.h>
#include <mocks/mock_file_io.h>
#include <mocks/mock_psm.h>
#include <mocks/mock_socket.h>
#include <mocks/mock_sysevent.h>
#include <mocks/mock_fd.h>
#include <mocks/mock_util.h>
#include "mocks/mock_ovs.h"
#include <mocks/mock_messagebus.h>
#include <mocks/mock_securewrapper.h>
#include <mocks/mock_ansc_memory.h>
#include <mocks/mock_cap.h>
#include "mocks/mock_bridge_util_generic.h"
#include <mocks/mock_base_api.h>
#include <mocks/mock_usertime.h>
#include <mocks/mock_ansc_wrapper_api.h>
#include <mocks/mock_trace.h>

using namespace std;
using std::experimental::filesystem::exists;

extern "C"
{
#include "bridge_util.h"
#include "bridge_util_hal.h"
}

extern int ovsEnable, bridgeUtilEnable, skipWiFi, skipMoCA, eb_enable;
extern int wan_mode;
extern int InstanceNumber;
extern int MocaIsolation_Enabled;
extern char Cmd_Opr[32];
extern char primaryBridgeName[64];

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;

SyscfgMock * g_syscfgMock = NULL;
FileIOMock * g_fileIOMock = NULL;
SocketMock * g_socketMock = NULL;
SyseventMock * g_syseventMock = NULL;
PsmMock * g_psmMock = NULL;
FileDescriptorMock * g_fdMock = NULL;
MessageBusMock * g_messagebusMock = NULL;
UtilMock * g_utilMock = NULL;
OvsMock * g_ovsMock = NULL;
BridgeUtilsGenericMock * g_bridgeUtilsGenericMock = NULL;
SecureWrapperMock * g_securewrapperMock = NULL;
CapMock * g_capMock                     = NULL;
AnscMemoryMock * g_anscMemoryMock       = NULL;
BaseAPIMock * g_baseapiMock = NULL;
UserTimeMock * g_usertimeMock = NULL;
AnscWrapperApiMock * g_anscWrapperApiMock = NULL;
TraceMock * g_traceMock = NULL;

class BridgeUtilsTestFixture : public ::testing::TestWithParam<int> {
    protected:
        SyscfgMock mockedSyscfg;
        FileIOMock mockedFileIO;
        SocketMock mockedSocket;
        SyseventMock mockedSysevent;
        PsmMock mockedPsm;
        FileDescriptorMock mockedFd;
        MessageBusMock mockedMsgbus;
        UtilMock  mockedUtil;
        OvsMock mockedOvs;
	    BridgeUtilsGenericMock mockedGeneric;
        SecureWrapperMock mockedsecurewrapper;
        CapMock mockedcapMock;                
        AnscMemoryMock mockedanscMemoryMock;
        BaseAPIMock mockedbaseapi;
        UserTimeMock mockedUsertime;
        AnscWrapperApiMock mockedAnscWrapperApi;
        TraceMock mockedTrace;

        BridgeUtilsTestFixture()
        {
            g_syscfgMock = &mockedSyscfg;
            g_fileIOMock = &mockedFileIO;
            g_socketMock = &mockedSocket;
            g_syseventMock = &mockedSysevent;
            g_psmMock = &mockedPsm;
            g_fdMock = &mockedFd;
            g_messagebusMock = &mockedMsgbus;
            g_utilMock = &mockedUtil;
            g_ovsMock = &mockedOvs;
	    g_bridgeUtilsGenericMock = &mockedGeneric;
            g_securewrapperMock      = &mockedsecurewrapper;
            g_capMock                = &mockedcapMock;	
	    g_anscMemoryMock        =  &mockedanscMemoryMock;
            g_baseapiMock = &mockedbaseapi;
	    g_usertimeMock = &mockedUsertime;
            g_anscWrapperApiMock = &mockedAnscWrapperApi;
            g_traceMock = &mockedTrace;

        }

        virtual ~BridgeUtilsTestFixture()
        {
            g_syscfgMock = NULL;
            g_fileIOMock = NULL;
            g_socketMock = NULL;
            g_syseventMock = NULL;
            g_psmMock = NULL;
            g_fdMock = NULL;
            g_messagebusMock = NULL;
            g_utilMock = NULL;
            g_ovsMock = NULL;
	    g_bridgeUtilsGenericMock = NULL;
            g_securewrapperMock    = NULL;
            g_capMock              = NULL ;	 
            g_anscMemoryMock        = NULL ;
            g_baseapiMock = NULL;
            g_usertimeMock = NULL;
            g_anscWrapperApiMock = NULL;
            g_traceMock = NULL;
        }
        virtual void SetUp()
        {
            bridge_util_log("%s %s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_info()->test_case_name(),
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
        }

        virtual void TearDown()
        {
            bridge_util_log("%s %s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_info()->test_case_name(),
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
        }
};

TEST (BridgeUtils, getMTU)
{
    EXPECT_EQ(1600, getMTU(MESH));
    EXPECT_EQ(1600, getMTU(MESH_BACKHAUL));
    EXPECT_EQ(0, getMTU(ETH_BACKHAUL));
    EXPECT_EQ(0, getMTU(PRIVATE_LAN));
    EXPECT_EQ(0, getMTU(HOME_SECURITY));
    EXPECT_EQ(0, getMTU(HOTSPOT_2G));
    EXPECT_EQ(0, getMTU(HOTSPOT_5G));
    EXPECT_EQ(0, getMTU(LOST_N_FOUND));
    EXPECT_EQ(0, getMTU(HOTSPOT_SECURE_2G));
    EXPECT_EQ(0, getMTU(HOTSPOT_SECURE_5G));
    EXPECT_EQ(0, getMTU(MOCA_ISOLATION));
}

TEST_F(BridgeUtilsTestFixture, Initialize)
{
    char expectedCmd[64] = {0};
    memset(expectedCmd,0,sizeof(expectedCmd));
    snprintf(expectedCmd,sizeof(expectedCmd),"touch %s",BRIDGE_UTIL_RUNNING);
    EXPECT_CALL(*g_messagebusMock, CCSP_Message_Bus_Init(_, _, _, _, _))
          .Times(1)
          .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
	 .Times(1)
         .WillOnce(Return(0));
    EXPECT_EQ(0, Initialize());
}

TEST_F(BridgeUtilsTestFixture, InitializeMessageBusFail)
{
    char expectedCmd[64] = {0};
    memset(expectedCmd,0,sizeof(expectedCmd));
    snprintf(expectedCmd,sizeof(expectedCmd),"touch %s",BRIDGE_UTIL_RUNNING);
    EXPECT_CALL(*g_messagebusMock, CCSP_Message_Bus_Init(_, _, _, _, _))
	  .Times(1)
	  .WillOnce(Return(-1));
    EXPECT_EQ(FAILED, Initialize());
}

TEST_F(BridgeUtilsTestFixture, InitializeSyseventopenFail)
{
    char expectedCmd[64] = {0};
    snprintf(expectedCmd, sizeof(expectedCmd), "touch %s", BRIDGE_UTIL_RUNNING);
    EXPECT_CALL(*g_messagebusMock, CCSP_Message_Bus_Init(_, _, _, _, _))
          .Times(1)
          .WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _))
         .Times(1)
         .WillOnce(Return(-1));
    EXPECT_EQ(FAILED, Initialize());
}

ACTION_TEMPLATE(SetArgNPointeeTo, HAS_1_TEMPLATE_PARAMS(unsigned, uIndex), AND_2_VALUE_PARAMS(pData, uiDataSize))
{
    memcpy(std::get<uIndex>(args), pData, uiDataSize);
}

ACTION_P(SetPsmValueArg4, value)
{
    *static_cast<char**>(arg4) = strdup(*value);
}

TEST_F(BridgeUtilsTestFixture, getXfinityEnableStatus)
{
    char paramName[] = "dmsb.hotspot.enable";
    char expectedValue[] = "1";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue),
            ::testing::Return(100)
        ));
    EXPECT_EQ(1, getXfinityEnableStatus());
}

TEST_F(BridgeUtilsTestFixture, getXfinityEnableStatusPsmFail)
{
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, _, _, _))
        .Times(1)
        .WillOnce(Return(192));
    EXPECT_EQ(0, getXfinityEnableStatus());
}

TEST_F(BridgeUtilsTestFixture, checkIfExists)
{
    char input[] = "brlan0";
    EXPECT_CALL(*g_socketMock, socket(_, _, _))
        .Times(1)
        .WillOnce(Return(10));
    EXPECT_CALL(*g_fdMock, ioctl(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    EXPECT_CALL(*g_socketMock, close(_))
        .Times(1)
        .WillOnce(Return(0));
    EXPECT_EQ(INTERFACE_EXIST, checkIfExists(input));
}

TEST_F(BridgeUtilsTestFixture, checkIfExistsFailure)
{
    char input[] = "blan22";
    EXPECT_CALL(*g_socketMock, socket(_, _, _))
        .Times(1)
        .WillOnce(Return(-1));
    EXPECT_EQ(INTERFACE_NOT_EXIST, checkIfExists(input));
}

// Test case for ovsEnable = 1
TEST_F(BridgeUtilsTestFixture, checkIfExistsInBridgeOvsEnable) {
    char bridge[] = "brlan0";
    char iface[] = "nmoca0";
    // Set ovsEnable to 1
    ovsEnable = 1; 
    FILE *expectedFd = (FILE *)0xffffffff;
    char expectedIfList[] = "nmoca0 ";
    char expectedCmd[128];
    snprintf(expectedCmd, sizeof(expectedCmd), "ovs-vsctl list-ifaces %s | grep %s | tr '\n' ' ' ", bridge, iface);

    EXPECT_CALL(*g_securewrapperMock, v_secure_popen(StrEq("r"), testing::HasSubstr("ovs-vsctl list-ifaces"), _))
        .WillOnce(Return(expectedFd));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd))
        .Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(expectedIfList, expectedIfList + strlen(expectedIfList) + 1),
            Return(static_cast<char*>(expectedIfList))
        ));

    EXPECT_CALL(*g_securewrapperMock, v_secure_pclose(expectedFd))
        .WillOnce(Return(0));

    EXPECT_EQ(INTERFACE_EXIST, checkIfExistsInBridge(iface, bridge));
}

// Test case for ovsEnable = 0
TEST_F(BridgeUtilsTestFixture, checkIfExistsInBridgeOvsDisable) {
    char bridge[] = "brlan0";
    char iface[] = "wl0";
    // Set ovsEnable to 0
    ovsEnable = 0; 
    FILE *expectedFd = (FILE *)0xffffffff;
    char expectedIfList[] = "wl0 wl1";
    char expectedCmd[128];
    snprintf(expectedCmd, sizeof(expectedCmd), "brctl show %s | sed '1d' | awk '{print $NF}' | grep %s | tr '\n' ' ' ", bridge, iface);

    EXPECT_CALL(*g_securewrapperMock, v_secure_popen(StrEq("r"), testing::HasSubstr("brctl show"), _))
        .WillOnce(Return(expectedFd));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd))
        .Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(expectedIfList, expectedIfList + strlen(expectedIfList) + 1),
            Return(static_cast<char*>(expectedIfList))
        ));

    EXPECT_CALL(*g_securewrapperMock, v_secure_pclose(expectedFd))
        .WillOnce(Return(0));

    EXPECT_EQ(INTERFACE_EXIST, checkIfExistsInBridge(iface, bridge));
}

// Test case for failure in v_secure_popen
TEST_F(BridgeUtilsTestFixture, checkIfExistsInBridgePopenFailure) {
    char bridge[] = "brlan0";
    char iface[] = "wl0";
    // Set ovsEnable to 1
    ovsEnable = 1; 
    EXPECT_CALL(*g_securewrapperMock, v_secure_popen(StrEq("r"), _, _))
        .WillOnce(Return(nullptr)); 
    EXPECT_EQ(INTERFACE_NOT_EXIST, checkIfExistsInBridge(iface, bridge));
}

TEST(BridgeUtils, removeIfaceFromList)
{
    char IfList[] = "wl0 wl11 moca0 ath0 eth3";
    char expected[] = "wl0 wl11 moca0  eth3";
    char expectedCmd[4096] = {0} ;
    removeIfaceFromList(IfList, "ath0");
    EXPECT_STREQ(IfList, expected);
    removeIfaceFromList(IfList, "");
    EXPECT_STREQ(IfList, IfList);
}

TEST_F(BridgeUtilsTestFixture, enableMoCaIsolationSettingsPSMFail) {
    bridgeDetails bridgeInfo = {};
    strncpy(bridgeInfo.bridgeName, "brlan0", sizeof(bridgeInfo.bridgeName) - 1);

    const char* paramNames[] = {
        "dmsb.MultiLAN.MoCAIsoLation_l3net",
        "dmsb.l3net.0.V4Addr",
        "dmsb.l2net.1.Name",
        "dmsb.l3net.0.V4SubnetMask"
    };

    for (const auto& paramName : paramNames) {
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(Return(9005));
    }

    const char* expectedCommand = "ip link set %s allmulticast on ;\
        ifconfig %s %s ; \
        ip link set %s up ; \
        echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts ; \
        sysctl -w net.ipv4.conf.all.arp_announce=3 ; \
        ip rule add from all iif %s lookup all_lans ; \
        echo 0 > /proc/sys/net/ipv4/conf/%s/rp_filter ;\
        touch %s ;";

    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::HasSubstr("ip link set "), _))
        .Times(1)
        .WillOnce(Return(0));

    enableMoCaIsolationSettings(&bridgeInfo);

    EXPECT_STREQ(primaryBridgeName, "");
}

TEST_F(BridgeUtilsTestFixture, enableMoCaIsolationSettings) 
{
    char ipaddr[64] = {};
    bridgeDetails bridgeInfo = {};
    strncpy(bridgeInfo.bridgeName, "brlan0", sizeof(bridgeInfo.bridgeName) - 1);

    struct Param {
        const char* name;
        const char* expectedValue;
    };

    Param params[] = {
        {"dmsb.MultiLAN.MoCAIsoLation_l3net", "9"},
        {"dmsb.l3net.9.V4Addr", "192.168.10.12"},
        {"dmsb.l3net.9.V4SubnetMask", "255.255.255.0"},
        {"dmsb.l2net.1.Name", "brlan0"}
    };

    for (int i = 0; i < 4; ++i) {
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(params[i].name), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetPsmValueArg4(&params[i].expectedValue),
                ::testing::Return(100)
            ));
    }

    char expectedCommand[1024] = {};
    snprintf(expectedCommand, sizeof(expectedCommand), 
        "ip link set %s allmulticast on ;\t"
        "ifconfig %s %s ; \t"
        "ip link set %s up ; \t"
        "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts ; \t"
        "sysctl -w net.ipv4.conf.all.arp_announce=3 ; \t"
        "ip rule add from all iif %s lookup all_lans ; \t"
        "echo 0 > /proc/sys/net/ipv4/conf/'%s'/rp_filter ;\t"
        "touch %s",
        bridgeInfo.bridgeName,
        bridgeInfo.bridgeName,
        "192.168.10.12",
        bridgeInfo.bridgeName,
        bridgeInfo.bridgeName,
        bridgeInfo.bridgeName,
        LOCAL_MOCABR_UP_FILE);


    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::HasSubstr("ip link set brlan0 allmulticast on ;\t    \tifconfig brlan0 192.168.10.12 ; \t    \tip link set brlan0 up ; \t"), _))
        .Times(1)
        .WillOnce(Return(0));

    enableMoCaIsolationSettings(&bridgeInfo);
    EXPECT_STREQ(primaryBridgeName, params[3].expectedValue);
}

TEST_F(BridgeUtilsTestFixture, disableMoCaIsolationSettings) 
{
    bridgeDetails bridgeInfo;
    memset(&bridgeInfo, 0, sizeof(bridgeDetails));
    strncpy(bridgeInfo.bridgeName, "brlan0", sizeof(bridgeInfo.bridgeName) - 1);

    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::HasSubstr("ip link set "), _))
        .Times(1)
        .WillOnce(Return(0));

    disableMoCaIsolationSettings(&bridgeInfo);
}

TEST_F(BridgeUtilsTestFixture, getIfList)
{
    InstanceNumber = 1;
    
    struct ParamFormatExpectedValue {
        const char* format;
        const char* expectedValue;
    };

    ParamFormatExpectedValue params[] = {
        {"dmsb.l2net.%d.Name", "brlan0"},
        {"dmsb.l2net.%d.Vid", "100"},
        {"dmsb.l2net.%d.Members.Link", "link0 link1"},
        {"dmsb.l2net.%d.Members.Eth", "eth0 eth1"},
        {"dmsb.l2net.%d.Members.Moca", "moca0 moca1 moca2"},
        {"dmsb.l2net.%d.Members.WiFi", "wifi0"},
        {"dmsb.l2net.%d.Members.Gre", ""},
        {"dmsb.l2net.%d.Members.VirtualParentIfname", ""}
    };

    const int numParams = sizeof(params) / sizeof(params[0]);

    for (int i = 0; i < numParams; ++i) {
        char paramName[128] = {0};
        snprintf(paramName, sizeof(paramName), params[i].format, InstanceNumber);
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetPsmValueArg4(&params[i].expectedValue),
                ::testing::Return(100)
            ));
    }

    bridgeDetails bridgeInfo;
    memset(&bridgeInfo, 0, sizeof(bridgeDetails));
    EXPECT_EQ(0, getIfList(&bridgeInfo));
    EXPECT_STREQ(bridgeInfo.bridgeName, params[0].expectedValue);
    EXPECT_EQ(bridgeInfo.vlanID, atoi(params[1].expectedValue));
    EXPECT_STREQ(bridgeInfo.vlan_name, params[2].expectedValue);
    EXPECT_STREQ(bridgeInfo.ethIfList, params[3].expectedValue);
    EXPECT_STREQ(bridgeInfo.MoCAIfList, params[4].expectedValue);
    EXPECT_STREQ(bridgeInfo.WiFiIfList, params[5].expectedValue);
    EXPECT_STREQ(bridgeInfo.GreIfList, params[6].expectedValue);
}

TEST_F(BridgeUtilsTestFixture, getIfListSkipMoca)
{
    InstanceNumber = 2;
    skipMoCA = 1;
    
    struct ParamInfo {
        const char* format;
        const char* expectedValue;
    };

    ParamInfo paramInfos[] = {
        {"dmsb.l2net.%d.Name", "brlan1"},
        {"dmsb.l2net.%d.Vid", "101"},
        {"dmsb.l2net.%d.Members.Link", "link0 link1"},
        {"dmsb.l2net.%d.Members.Eth", "eth0 eth1"},
        {"dmsb.l2net.%d.Members.VirtualParentIfname", ""},
        {"dmsb.l2net.%d.Members.WiFi", "wifi0"},
        {"dmsb.l2net.%d.Members.Gre", ""}
    };

    const int numParams = sizeof(paramInfos) / sizeof(paramInfos[0]);

    for (int i = 0; i < numParams; ++i) {
        char paramName[128] = {0};
        snprintf(paramName, sizeof(paramName), paramInfos[i].format, InstanceNumber);
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetPsmValueArg4(&paramInfos[i].expectedValue),
                ::testing::Return(100)
            ));
    }

    bridgeDetails bridgeInfo;
    memset(&bridgeInfo, 0, sizeof(bridgeDetails));
    EXPECT_EQ(0, getIfList(&bridgeInfo));
    EXPECT_STREQ(bridgeInfo.bridgeName, paramInfos[0].expectedValue);
    EXPECT_EQ(bridgeInfo.vlanID, atoi(paramInfos[1].expectedValue));
    EXPECT_STREQ(bridgeInfo.vlan_name, paramInfos[2].expectedValue);
    EXPECT_STREQ(bridgeInfo.ethIfList, paramInfos[3].expectedValue);
    EXPECT_STREQ(bridgeInfo.MoCAIfList, "");  // MoCA list should be empty
    EXPECT_STREQ(bridgeInfo.WiFiIfList, paramInfos[5].expectedValue);
    EXPECT_STREQ(bridgeInfo.GreIfList, paramInfos[6].expectedValue);
}

TEST_F(BridgeUtilsTestFixture, getIfListSkipWifi)
{
    InstanceNumber = 3;
    skipWiFi = 1;
    skipMoCA = 0;

    struct ParamInfo {
        const char* format;
        const char* expectedValue;
    };

    ParamInfo paramInfos[] = {
        {"dmsb.l2net.%d.Name", "brlan2"},
        {"dmsb.l2net.%d.Vid", "100"},
        {"dmsb.l2net.%d.Members.Link", "link0 link1"},
        {"dmsb.l2net.%d.Members.Eth", "eth0 eth1"},
        {"dmsb.l2net.%d.Members.Moca", "moca0 moca1 moca2"},
        {"dmsb.l2net.%d.Members.VirtualParentIfname", ""},
        {"dmsb.l2net.%d.Members.Gre", ""}
    };

    const int numParams = sizeof(paramInfos) / sizeof(paramInfos[0]);

    for (int i = 0; i < numParams; ++i) {
        char paramName[128] = {0};
        snprintf(paramName, sizeof(paramName), paramInfos[i].format, InstanceNumber);
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetPsmValueArg4(&paramInfos[i].expectedValue),
                ::testing::Return(100)
            ));
    }

    bridgeDetails bridgeInfo;
    memset(&bridgeInfo, 0, sizeof(bridgeDetails));
    EXPECT_EQ(0, getIfList(&bridgeInfo));
    EXPECT_STREQ(bridgeInfo.bridgeName, paramInfos[0].expectedValue);
    EXPECT_EQ(bridgeInfo.vlanID, atoi(paramInfos[1].expectedValue));
    EXPECT_STREQ(bridgeInfo.vlan_name, paramInfos[2].expectedValue);
    EXPECT_STREQ(bridgeInfo.ethIfList, paramInfos[3].expectedValue);
    EXPECT_STREQ(bridgeInfo.MoCAIfList, paramInfos[4].expectedValue);
    EXPECT_STREQ(bridgeInfo.WiFiIfList, "");  // WiFi list should be empty
    EXPECT_STREQ(bridgeInfo.GreIfList, paramInfos[6].expectedValue);
}

TEST_F(BridgeUtilsTestFixture, getIfListPsmFail)
{
    InstanceNumber = 1;
    skipMoCA = 0;
    skipWiFi = 0;

    struct ParamInfo {
        const char* format;
    };

    ParamInfo paramInfos[] = {
        {"dmsb.l2net.%d.Name"},
        {"dmsb.l2net.%d.Vid"},
        {"dmsb.l2net.%d.Members.Link"},
        {"dmsb.l2net.%d.Members.Eth"},
        {"dmsb.l2net.%d.Members.Moca"},
        {"dmsb.l2net.%d.Members.WiFi"},
        {"dmsb.l2net.%d.Members.Gre"},
        {"dmsb.l2net.%d.Members.VirtualParentIfname"}
    };

    for (const auto& paramInfo : paramInfos) {
        char paramName[128] = {0};
        snprintf(paramName, sizeof(paramName), paramInfo.format, InstanceNumber);
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(Return(9005));
    }

    bridgeDetails bridgeInfo;
    memset(&bridgeInfo, 0, sizeof(bridgeDetails));
    EXPECT_EQ(0, getIfList(&bridgeInfo));

    char expectedValue[128] = {0};
    EXPECT_STREQ(bridgeInfo.bridgeName, expectedValue);
    EXPECT_EQ(bridgeInfo.vlanID, 0);
    EXPECT_STREQ(bridgeInfo.vlan_name, expectedValue);
    EXPECT_STREQ(bridgeInfo.ethIfList, expectedValue);
    EXPECT_STREQ(bridgeInfo.MoCAIfList, expectedValue);
    EXPECT_STREQ(bridgeInfo.WiFiIfList, expectedValue);
    EXPECT_STREQ(bridgeInfo.GreIfList, expectedValue);
}

TEST_F(BridgeUtilsTestFixture, wait_for_gre_ready)
{
    char greIf[] = "gre0 gre1";
    char GreState[64] = {0} , greSysName[128] = {0};
    snprintf(greSysName,sizeof(greSysName),"if_%s-status","gre0");
    strcpy(GreState, "ready");
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(greSysName), _, _))
	 .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(GreState), sizeof(GreState)),
            ::testing::Return(0)
        ));
    
    EXPECT_EQ(0, wait_for_gre_ready(greIf));
}

TEST_F(BridgeUtilsTestFixture, wait_for_gre_ready_syseventFailed)
{
    char greIf[] = "gre0 gre1";
    char GreState[64] = {0} , greSysName[128] = {0}, GreState1[64] = {0};
    snprintf(greSysName,sizeof(greSysName),"if_%s-status","gre0");
    strcpy(GreState, "waiting");
    strcpy(GreState1, "ready");
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(greSysName), _, _))
	 .Times(4)
        .WillOnce(Return(-1))
        .WillOnce(Return(-1))
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(GreState), sizeof(GreState)),
            ::testing::Return(0)
        ))
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<3>(std::begin(GreState1), sizeof(GreState1)),
            ::testing::Return(0)
        ));
    
    EXPECT_EQ(0, wait_for_gre_ready(greIf));
}

TEST_F(BridgeUtilsTestFixture, assignIpToBridge)
{
    char bridgeName[] = "brlan10";
    char l3netName[] = "dmsb.MultiLAN.MeshBhaul_l3net";

    char paramName1[128] = {0};
    snprintf(paramName1, sizeof(paramName1), "dmsb.MultiLAN.MeshBhaul_l3net");
    char expectedValue1[128] = "9";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName1), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue1),
            ::testing::Return(100)
        ));

    char paramName2[128] = {0};
    snprintf(paramName2, sizeof(paramName2), "dmsb.l3net.%d.V4Addr", 9);
    char expectedValue2[128] = "192.168.10.11";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName2), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue2),
            ::testing::Return(100)
        ));

    char paramName3[128] = {0};
    snprintf(paramName3, sizeof(paramName3), "dmsb.l3net.%d.V4SubnetMask", 9);
    char expectedValue3[128] = "192.168.255.255";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName3), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue3),
            ::testing::Return(100)
        ));

    char expectedCmd[256] = {0};
    snprintf(expectedCmd, sizeof(expectedCmd), "ifconfig %s %s netmask %s up", bridgeName, expectedValue2, expectedValue3);

    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq(expectedCmd),_))
        .Times(1)
        .WillOnce(Return(0));

    assignIpToBridge(bridgeName, l3netName);
}

TEST_F(BridgeUtilsTestFixture, assignIpToBridgeNoSubnet)
{
    char bridgeName[] = "br403";
    char l3netName[] = "dmsb.MultiLAN.Lnf_l3net";

    char paramName1[128] = {0};
    snprintf(paramName1,sizeof(paramName1), "dmsb.MultiLAN.Lnf_l3net");
    char expectedValue1[128] = "6";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName1), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue1),
            ::testing::Return(100)
        ));

    char paramName2[128] = {0};
    snprintf(paramName2,sizeof(paramName2), "dmsb.l3net.%d.V4Addr", 6);
    char expectedValue2[128] = "192.168.10.9";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName2), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue2),
            ::testing::Return(100)
        ));
    
    char paramName3[128] = {0};
    snprintf(paramName3,sizeof(paramName3), "dmsb.l3net.%d.V4SubnetMask", 6);
    char expectedValue3[128] = "";
    memset(expectedValue3, 0, sizeof(expectedValue3));
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName3), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue3),
            ::testing::Return(100)
        ));
    char expectedCmd[216] = {0};
    snprintf(expectedCmd,sizeof(expectedCmd),"ifconfig %s %s",bridgeName,expectedValue2);
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq(expectedCmd), _))
        .Times(1)
        .WillOnce(Return(1));
    assignIpToBridge(bridgeName, l3netName);
}

TEST_F(BridgeUtilsTestFixture, assignIpToBridgePsmFail)
{
    char bridgeName[] = "br403";
    char l3netName[] = "dmsb.MultiLAN.Lnf_l3net";

    char paramName1[128] = {0};
    snprintf(paramName1,sizeof(paramName1), "dmsb.MultiLAN.Lnf_l3net");
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName1), _, _))
        .Times(1)
        .WillOnce(Return(9005));

    assignIpToBridge(bridgeName, l3netName);
}

TEST_F(BridgeUtilsTestFixture, getCurrentIfListOvsEnable)
{
    using namespace testing; 

    ovsEnable = 1;
    char bridgeName[] = "brlan0";
    char expectedIfList[] = "ath0 ath1 lan0 lbr0 nmoca0 ";
    char ifList[TOTAL_IFLIST_SIZE] = {0};

    FILE* expectedFd = reinterpret_cast<FILE*>(0x12345678);
    char expectedCmd[128] = {0};
    snprintf(expectedCmd, sizeof(expectedCmd), "ovs-vsctl list-ifaces %s | tr '\n' ' ' ", bridgeName);

    EXPECT_CALL(*g_securewrapperMock, v_secure_popen(StrEq("r"), StrEq(expectedCmd), _))
        .Times(1)
        .WillOnce(Return(expectedFd));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd))
        .Times(1)
        .WillOnce(DoAll(SetArrayArgument<0>(expectedIfList, expectedIfList + strlen(expectedIfList)), Return(expectedIfList)));

    EXPECT_CALL(*g_securewrapperMock, v_secure_pclose(expectedFd))
        .Times(1)
        .WillOnce(Return(0));

    getCurrentIfList(bridgeName, ifList);

    ASSERT_STREQ(expectedIfList, ifList);
}

TEST_F(BridgeUtilsTestFixture, getCurrentIfListBridgeUtilsEnable)
{
    using namespace testing; 
    ovsEnable = 0;
    bridgeUtilEnable = 1;
    char bridge[] = "brlan1";
    char ifList[TOTAL_IFLIST_SIZE] = {0};
    char expectedCmd[128] = {0} ;
    snprintf(expectedCmd,sizeof(expectedCmd),"brctl show %s | sed '1d' | awk '{print $NF}' | tr '\n' ' ' ",bridge);
    char expectedIfList[] = "wl01 wl11 gre0 ";
    FILE * expectedFd = (FILE *)0xffffffff;
    EXPECT_CALL(*g_securewrapperMock, v_secure_popen(StrEq("r"), HasSubstr(expectedCmd), _))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd));
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedIfList), sizeof(expectedIfList)),
            ::testing::Return((char*)expectedIfList)
        ));
    EXPECT_CALL(*g_securewrapperMock, v_secure_pclose(expectedFd)) 
       .Times(1)
       .WillOnce(::testing::Return(0));
    getCurrentIfList(bridge, ifList);
    EXPECT_STREQ(expectedIfList, ifList);
}

TEST_F(BridgeUtilsTestFixture, getCurrentIfListPopenFail)
{
    ovsEnable = 0;
    bridgeUtilEnable = 1;
    char bridge[] = "brlan1";
    /* CID :249149 Out-of-bounds access (OVERRUN) */
    char ifList[TOTAL_IFLIST_SIZE] = {0};

    char expectedCmd[128] = {0} ;
    snprintf(expectedCmd,sizeof(expectedCmd),"brctl show %s | sed '1d' | awk '{print $NF}' | tr '\n' ' ' ",bridge);
    char expectedIfList[216] = {0};
    memset(expectedIfList, 0, sizeof(expectedIfList));
    FILE * expectedFd = (FILE *)0x00000000;
    EXPECT_CALL(*g_securewrapperMock, v_secure_popen(StrEq("r"), StrEq(expectedCmd), _))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd));

    getCurrentIfList(bridge, ifList);
    EXPECT_STREQ(expectedIfList, ifList);
}

TEST_F(BridgeUtilsTestFixture, getCurrentIfListFail)
{
    ovsEnable = 0;
    bridgeUtilEnable = 0;
    char bridge[] = "brlan1";
    char ifList[TOTAL_IFLIST_SIZE] = {0};
    char expectedIfList[216] = {0};
    memset(expectedIfList, 0, sizeof(expectedIfList));
    getCurrentIfList(bridge, ifList);
    EXPECT_STREQ(expectedIfList, ifList);
}

TEST_F(BridgeUtilsTestFixture, getSettingsPsmWan)
{
    ::testing::InSequence seq;
    InstanceNumber = PRIVATE_LAN;
    wan_mode = 0;
    skipMoCA = 0;
    skipWiFi = 0;

    struct Param {
        char name[128];
        char value[128];
    };

    Param params[] = {
        {"selected_wan_mode", "2"},
        {"bridge_mode", "0"},
        {"HomeSecurityEthernet4Flag", "0"},
        {"mesh_ovs_enable", "true"},
        {"bridge_util_enable", "false"},
        {"eth_wan_enabled", "false"},
        {"NonRootSupport", "false"},
        {"eb_enable", "true"},
        {"dmsb.l2net.EthWanInterface", "eth3"},
        {"dmsb.l2net.HomeNetworkIsolation", "0"}
    };

    for (int i = 0; i < sizeof(params)/sizeof(params[0]); ++i) {
        if (i < 8) {
            EXPECT_CALL(*g_syscfgMock, syscfg_get( _, StrEq(params[i].name), _, _))
                .Times(1)
                .WillOnce(::testing::DoAll(
                    SetArgNPointeeTo<2>(std::begin(params[i].value), sizeof(params[i].value)),
                    ::testing::Return(0)
                ));
        } 
        else 
        {
            EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(params[i].name), _, _))
                .Times(1)
                .WillOnce(::testing::DoAll(
                    SetPsmValueArg4(&params[i].value),
                    ::testing::Return(100)
                ));
        }
    }

    getSettings();

    EXPECT_EQ(wan_mode, atoi(params[0].value));
    EXPECT_EQ(DeviceMode, atoi(params[1].value));
    EXPECT_EQ(PORT2ENABLE, atoi(params[2].value));
    EXPECT_EQ(ovsEnable, (strcmp(params[3].value, "true") == 0)?1:0);
    EXPECT_EQ(bridgeUtilEnable, (strcmp(params[4].value, "true") == 0)?1:0);
    EXPECT_STREQ(ethWanIfaceName, params[8].value);
    EXPECT_EQ(ethWanEnabled, (strcmp(params[5].value, "true") == 0)?1:0);
    EXPECT_EQ(eb_enable, (strcmp(params[7].value, "true") == 0)?1:0);
    EXPECT_EQ(MocaIsolation_Enabled, atoi(params[9].value));
    EXPECT_EQ(skipWiFi, 0);
    EXPECT_EQ(skipMoCA, 0);
}


TEST_F(BridgeUtilsTestFixture, getSettingsFail)
{
    InstanceNumber = PRIVATE_LAN;
    ovsEnable = 0;
    wan_mode = 0;
    skipMoCA = 0;
    skipWiFi = 0;
    eb_enable = 0;

    const char* paramNames[] = {
        "selected_wan_mode",
        "bridge_mode",
        "HomeSecurityEthernet4Flag",
        "mesh_ovs_enable",
        "bridge_util_enable",
        "eth_wan_enabled",
        "NonRootSupport",
        "eb_enable"
    };

    for (int i = 0; i < sizeof(paramNames)/sizeof(paramNames[0]); i++) {
        EXPECT_CALL(*g_syscfgMock, syscfg_get( _, StrEq(paramNames[i]), _, _))
            .Times(1)
            .WillOnce(Return(-1));
    }

    char paramName9[128] = {0};
    snprintf(paramName9,sizeof(paramName9), "dmsb.l2net.EthWanInterface");
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName9), _, _))
        .Times(1)
        .WillOnce(Return(-1));

    char paramName10[128] = {0};
    snprintf(paramName10,sizeof(paramName10), "dmsb.l2net.HomeNetworkIsolation");
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName10), _, _))
        .Times(1)
        .WillOnce(Return(-1));

    getSettings();

    EXPECT_EQ(wan_mode, 0);
    EXPECT_EQ(DeviceMode, 0);
    EXPECT_EQ(PORT2ENABLE, 0);
    EXPECT_EQ(bridgeUtilEnable, 0);
    EXPECT_EQ(ethWanEnabled, 0);
    EXPECT_EQ(eb_enable, 0);
    EXPECT_EQ(MocaIsolation_Enabled, 0);
    EXPECT_EQ(skipWiFi, 0);
    EXPECT_EQ(skipMoCA, 0);
}

TEST_F(BridgeUtilsTestFixture, getSettings)
{
    InstanceNumber = PRIVATE_LAN;

    struct Param {
        char paramName[128];
        char expectedValue[128];
    } params[] = {
        {"selected_wan_mode", "1"},
        {"bridge_mode", "1"},
        {"HomeSecurityEthernet4Flag", "1"},
        {"mesh_ovs_enable", "true"},
        {"bridge_util_enable", "true"},
        {"eth_wan_iface_name", "eth0"},
        {"eth_wan_enabled", "true"},
        {"NonRootSupport", "false"},
        {"eb_enable", "true"},
    };

    for (const auto& param : params) {
        EXPECT_CALL(*g_syscfgMock, syscfg_get( _, StrEq(param.paramName), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetArgNPointeeTo<2>(std::begin(param.expectedValue), sizeof(param.expectedValue)),
                ::testing::Return(0)
            ));
    }

    char paramName10[128] = {0};
    snprintf(paramName10,sizeof(paramName10), "dmsb.l2net.HomeNetworkIsolation");
    char expectedValue10[128] = "1";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName10), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue10),
            ::testing::Return(100)
        ));

    getSettings();

    EXPECT_EQ(wan_mode, atoi(params[0].expectedValue));
    EXPECT_EQ(DeviceMode, atoi(params[1].expectedValue));
    EXPECT_EQ(PORT2ENABLE, atoi(params[2].expectedValue));
    EXPECT_EQ(ovsEnable, (strcmp(params[3].expectedValue, "true") == 0)?1:0);
    EXPECT_EQ(bridgeUtilEnable, (strcmp(params[4].expectedValue, "true") == 0)?1:0);
    EXPECT_STREQ(ethWanIfaceName, params[5].expectedValue);
    EXPECT_EQ(ethWanEnabled, (strcmp(params[6].expectedValue, "true") == 0)?1:0);
    EXPECT_EQ(eb_enable, (strcmp(params[8].expectedValue, "true") == 0)?1:0);
    EXPECT_EQ(MocaIsolation_Enabled, atoi(expectedValue10));
    EXPECT_EQ(skipWiFi, 1);
    EXPECT_EQ(skipMoCA, 1);
}

ACTION_P(SetGwConfigArg1, value)
{
    *static_cast<void**>(arg1) = *value;
}

TEST_F(BridgeUtilsTestFixture, AddOrDeletePortOvsUp)
{
    char bridgeName[] = "brlan0";
    char iface[] = "ath0";
    ovsEnable = 1;
    Gateway_Config *pGwConfig = NULL;
    pGwConfig = (Gateway_Config*) malloc(sizeof(Gateway_Config));
    memset(pGwConfig, 0, sizeof(Gateway_Config));
    pGwConfig->if_type = OVS_OTHER_IF_TYPE;
    pGwConfig->mtu = DEFAULT_MTU;
    pGwConfig->vlan_id = DEFAULT_VLAN_ID;
    pGwConfig->if_cmd = OVS_IF_UP_CMD;
    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config( _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetGwConfigArg1((void **)&pGwConfig),
            ::testing::Return(true)
        ));
    EXPECT_CALL(*g_ovsMock, ovs_agent_api_interact( _, _))
        .Times(1)
        .WillOnce(Return(true));
    AddOrDeletePort(bridgeName, iface, OVS_IF_UP_CMD);
}


TEST_F(BridgeUtilsTestFixture, AddOrDeletePortOvsRemove)
{
    char bridgeName[] = "brlan0";
    char iface[] = "ath0";
    ovsEnable = 1;
    Gateway_Config *pGwConfig = NULL;
    pGwConfig = (Gateway_Config*) malloc(sizeof(Gateway_Config));
    memset(pGwConfig, 0, sizeof(Gateway_Config));
    pGwConfig->if_type = OVS_OTHER_IF_TYPE;
    pGwConfig->mtu = DEFAULT_MTU;
    pGwConfig->vlan_id = DEFAULT_VLAN_ID;
    pGwConfig->if_cmd = OVS_IF_UP_CMD;
    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config( _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetGwConfigArg1((void **)&pGwConfig),
            ::testing::Return(true)
        ));
    EXPECT_CALL(*g_ovsMock, ovs_agent_api_interact( _, _))
        .Times(1)
        .WillOnce(Return(true));
    AddOrDeletePort(bridgeName, iface, OVS_BR_REMOVE_CMD);
}


TEST_F(BridgeUtilsTestFixture, AddOrDeletePortOvsFailGetConfig)
{
    char bridgeName[] = "brlan0";
    char iface[] = "ath0";
    ovsEnable = 1;
    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config( _, _))
        .Times(1)
        .WillOnce(Return(false));
    AddOrDeletePort(bridgeName, iface, OVS_BR_REMOVE_CMD);
}

TEST_F(BridgeUtilsTestFixture, AddOrDeletePortBridgeUtilsUp) {
    char bridgeName[] = "brlan0";
    char iface[] = "ath0";
    ovsEnable = 0;
    bridgeUtilEnable = 1;
    char expectedCmd[1024] = {0};
    snprintf(expectedCmd, sizeof(expectedCmd), "check_bridge=`brctl show %s` ;\t\t\t\t\tif [ \"$check_bridge\" = \"\" ];\t\t\t\t\tthen \t\t\t\t\t\tbrctl addbr %s ;\t\t\t\t\t\tifconfig %s up ; \t\t\t\t\tfi ;",
             bridgeName, bridgeName, bridgeName);

    EXPECT_CALL(*g_utilMock, system(StrEq(expectedCmd)))
        .Times(1)
        .WillOnce(Return(0));

    char expectedCmd1[1024] = {0};
    snprintf(expectedCmd1, sizeof(expectedCmd1), "for bridge in `brctl show | cut -f1 | awk 'NF > 0' | sed '1d' | grep -v %s `;\t\t\t\t\tdo \t\t\t\t\tcheck_if_attached=`brctl show $bridge | grep \"%s\" | grep -v \"%s.\"` ; \t\t\t\t\tif [ \"$check_if_attached\" != \"\" ] ;\t\t\t\t\t\tthen\t\t\t\t\t        echo \"deleting %s from $bridge\" ;\t\t\t\t\t        brctl delif $bridge %s ; \t\t\t\t\t fi ;\t\t\t\t\t done ;\t\t\t\t\t check_if_exist=`brctl show %s | grep \"%s\" | grep -v \"%s.\"` ; \t\t\t\t\t if [ \"$check_if_exist\" = \"\" ]; \t\t\t\t\t then \t\t\t\t\t \tifconfig %s up ;\t\t\t\t\t    \tbrctl addif %s %s ;\t\t\t\t\t fi ;",
             bridgeName, iface, iface, iface, iface, bridgeName, iface, iface, bridgeName, bridgeName, iface);

    EXPECT_CALL(*g_utilMock, system(StrEq(expectedCmd1)))
        .Times(1)
        .WillOnce(Return(0));

    AddOrDeletePort(bridgeName, iface, OVS_IF_UP_CMD);
}

TEST_F(BridgeUtilsTestFixture, AddOrDeletePortBridgeUtilsDelete)
{
    char bridgeName[] = "brlan0";
    char iface[] = "ath0";
    ovsEnable = 0;
    bridgeUtilEnable = 1;
    char expectedCmd[216] = {0};
    memset(expectedCmd,0,sizeof(expectedCmd));
    snprintf(expectedCmd,sizeof(expectedCmd),"brctl delif %s %s",bridgeName,iface);
    EXPECT_CALL(*g_utilMock, system(StrEq(expectedCmd)))
        .Times(1)
        .WillOnce(Return(1));
    
    AddOrDeletePort(bridgeName, iface, OVS_BR_REMOVE_CMD);
}

TEST_F(BridgeUtilsTestFixture, AddOrDeletePortFail)
{
    /* CID :249134 Destination buffer too small (STRING_OVERFLOW) */
    char bridgeName[64] = "";
    char iface[] = "ath0";
    AddOrDeletePort(bridgeName, iface, OVS_BR_REMOVE_CMD);
    strcpy(bridgeName, "brlan123");
    memset(iface, 0, sizeof(iface));
    AddOrDeletePort(bridgeName, iface, OVS_IF_UP_CMD);
}

TEST_F(BridgeUtilsTestFixture, AddOrDeletePortOvsFail)
{
    char bridgeName[] = "brlan0";
    char iface[] = "ath0";
    ovsEnable = 1;
    Gateway_Config *pGwConfig = NULL;
    pGwConfig = (Gateway_Config*) malloc(sizeof(Gateway_Config));
    memset(pGwConfig, 0, sizeof(Gateway_Config));
    pGwConfig->if_type = OVS_OTHER_IF_TYPE;
    pGwConfig->mtu = DEFAULT_MTU;
    pGwConfig->vlan_id = DEFAULT_VLAN_ID;
    pGwConfig->if_cmd = OVS_IF_UP_CMD;
    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config( _, _))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetGwConfigArg1((void **)&pGwConfig),
            ::testing::Return(true)))
        .WillOnce(::testing::DoAll(
            SetGwConfigArg1((void **)&pGwConfig),
            ::testing::Return(true)
        ));
    EXPECT_CALL(*g_ovsMock, ovs_agent_api_interact( _, _))
        .Times(2)
        .WillOnce(Return(false))
        .WillOnce(Return(true));
    AddOrDeletePort(bridgeName, iface, OVS_IF_UP_CMD);
}

TEST_F(BridgeUtilsTestFixture, removeIfaceFromBridge)
{
    ovsEnable = 1;
    DeviceMode = 0;
    bridgeDetails bridgeInfo;
    memset(&bridgeInfo, 0, sizeof(bridgeDetails));
    strncpy(bridgeInfo.bridgeName,"brlan1",sizeof(bridgeInfo.bridgeName)-1);
    strncpy(bridgeInfo.vlan_name,"link0",sizeof(bridgeInfo.vlan_name)-1);
    bridgeInfo.vlanID = 101;
    strncpy(bridgeInfo.ethIfList,"eth0",sizeof(bridgeInfo.ethIfList)-1);
    strncpy(bridgeInfo.MoCAIfList,"moca0",sizeof(bridgeInfo.MoCAIfList)-1);
    strncpy(bridgeInfo.GreIfList,"gre0",sizeof(bridgeInfo.GreIfList)-1);
    strncpy(bridgeInfo.WiFiIfList,"wl0",sizeof(bridgeInfo.WiFiIfList)-1);
    char ifacesList[218] = "eth0 wl0 ath0 gre0 link1";

    Gateway_Config *pGwConfig = NULL;
    pGwConfig = (Gateway_Config*) malloc(sizeof(Gateway_Config));
    memset(pGwConfig, 0, sizeof(Gateway_Config));
    pGwConfig->if_type = OVS_OTHER_IF_TYPE;
    pGwConfig->mtu = DEFAULT_MTU;
    pGwConfig->vlan_id = DEFAULT_VLAN_ID;
    pGwConfig->if_cmd = OVS_IF_UP_CMD;
    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config( _, _))
        .Times(3)
        .WillOnce(::testing::DoAll(
            SetGwConfigArg1((void **)&pGwConfig),
            ::testing::Return(true)
        ))
	.WillOnce(::testing::DoAll(
            SetGwConfigArg1((void **)&pGwConfig),
            ::testing::Return(true)
        ))
        .WillOnce(::testing::DoAll(
            SetGwConfigArg1((void **)&pGwConfig),
            ::testing::Return(true)
        ));
    EXPECT_CALL(*g_ovsMock, ovs_agent_api_interact( _, _))
        .Times(3)
        .WillOnce(Return(true))
	.WillOnce(Return(true))
        .WillOnce(Return(true));

    removeIfaceFromBridge(&bridgeInfo, ifacesList);
    EXPECT_EQ(need_wifi_gw_refresh, 1);
    EXPECT_EQ(need_switch_gw_refresh, 1);
}

TEST_F(BridgeUtilsTestFixture, CreateBrInterface)
{
    char event[64] = {0}, value[64] = {0};
    InstanceNumber = 1;
    ovsEnable = 1;
    DeviceMode = 0;
    ethWanEnabled = 0;
    wan_mode = 1;
    skipMoCA = 0;
    skipWiFi = 0;

    const char* paramNames[] = {
        "dmsb.l2net.%d.Name",
        "dmsb.l2net.%d.Vid",
        "dmsb.l2net.%d.Members.Link",
        "dmsb.l2net.%d.Members.Eth",
        "dmsb.l2net.%d.Members.Moca",
        "dmsb.l2net.%d.Members.WiFi",
        "dmsb.l2net.%d.Members.Gre",
        "dmsb.l2net.%d.Members.VirtualParentIfname"
    };

    const char* expectedValues[] = {
        "brlan1",
        "101",
        "",
        "",
        "",
        "wifi0 wifi1",
        "",
        ""
    };

    snprintf(event, sizeof(event), "multinet_%d-status", InstanceNumber);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq("partial"), _))
        .Times(1)
        .WillOnce(Return(0));

    for (int i = 0; i < sizeof(paramNames) / sizeof(paramNames[0]); ++i) {
        char paramName[128] = {0};
        snprintf(paramName, sizeof(paramName), paramNames[i], InstanceNumber);
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetPsmValueArg4(&expectedValues[i]),
                ::testing::Return(100)
            ));
    }

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePreConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePostConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    char event1[64] = {0} , value1[64] = {0};
    snprintf(event1,sizeof(event1),"multinet_%d-name",InstanceNumber);
    strcpy(value1, "brlan1");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event1), StrEq(value1), _))
	 .Times(1)
        .WillOnce(Return(0));
    char event2[64] = {0} , value2[64] = {0};
    snprintf(event2,sizeof(event2),"multinet_%d-vid",InstanceNumber);
    snprintf(value2,sizeof(value2),"%d",101);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event2), StrEq(value2), _))
	 .Times(1)
        .WillOnce(Return(0));

    // OVS interactions
    Gateway_Config *pGwConfig = (Gateway_Config*) malloc(sizeof(Gateway_Config));
    memset(pGwConfig, 0, sizeof(Gateway_Config));
    pGwConfig->if_type = OVS_OTHER_IF_TYPE;
    pGwConfig->mtu = DEFAULT_MTU;
    pGwConfig->vlan_id = DEFAULT_VLAN_ID;
    pGwConfig->if_cmd = OVS_IF_UP_CMD;

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config(_, _))
        .Times(2) 
        .WillRepeatedly(::testing::DoAll(
            SetGwConfigArg1((void **)&pGwConfig),
            ::testing::Return(true)
        ));
    EXPECT_CALL(*g_ovsMock, ovs_agent_api_interact(_, _))
        .Times(2) 
        .WillRepeatedly(Return(true));

    snprintf(event, sizeof(event), "multinet_%d-localready", InstanceNumber);
    strcpy(value, "1");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
        .Times(1)
        .WillOnce(Return(0));

    snprintf(event, sizeof(event), "multinet_%d-status", InstanceNumber);
    strcpy(value, "ready");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
        .Times(1)
        .WillOnce(Return(0));

    snprintf(event, sizeof(event), "firewall-restart");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), _, _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(CreateBrInterface(), 0);

    free(pGwConfig);
}



TEST_F(BridgeUtilsTestFixture, CreateBrInterfaceInst1ETHWAN)
{
    char event[64] = {0} , value[64] = {0};
    InstanceNumber = 1;
    ovsEnable = 1;
    DeviceMode = 1;
    ethWanEnabled = 1;
    wan_mode = 0;
    skipMoCA = 1;
    skipWiFi = 1;
    strncpy(ethWanIfaceName,"eth3",sizeof(ethWanIfaceName)-1);
    snprintf(event,sizeof(event),"multinet_%d-status",InstanceNumber);
    strcpy(value, "partial");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
        .Times(1)
        .WillOnce(Return(0));

    struct ParamNameFormatExpectedValue {
        const char* format;
        const char* expectedValue;
    };

    ParamNameFormatExpectedValue params[] = {
        {"dmsb.l2net.%d.Name", "brlan1"},
        {"dmsb.l2net.%d.Vid", "101"},
        {"dmsb.l2net.%d.Members.Link", ""},
        {"dmsb.l2net.%d.Members.Eth", ""},
        {"dmsb.l2net.%d.Members.Gre", ""},
        {"dmsb.l2net.%d.Members.VirtualParentIfname", ""}
    };

    for (int i = 0; i < sizeof(params) / sizeof(params[0]); ++i) {
        char paramName[128] = {0};
        snprintf(paramName, sizeof(paramName), params[i].format, InstanceNumber);
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetPsmValueArg4(&params[i].expectedValue),
                ::testing::Return(100)
            ));
    }
    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePreConfigVendorGeneric(_, _))
	 .Times(1)
        .WillOnce(Return(0));
    
    char event1[64] = {0} , value1[64] = {0};
    snprintf(event1,sizeof(event1),"multinet_%d-name",InstanceNumber);
    strcpy(value1, "brlan1");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event1), StrEq(value1), _))
	 .Times(1)
        .WillOnce(Return(0));
    char event2[64] = {0} , value2[64] = {0};
    snprintf(event2,sizeof(event2),"multinet_%d-vid",InstanceNumber);
    snprintf(value2,sizeof(value2),"%d",101);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event2), StrEq(value2), _))
	 .Times(1)
        .WillOnce(Return(0));

    Gateway_Config *pGwConfig = NULL;
    pGwConfig = (Gateway_Config*) malloc(sizeof(Gateway_Config));
    memset(pGwConfig, 0, sizeof(Gateway_Config));
    pGwConfig->if_type = OVS_OTHER_IF_TYPE;
    pGwConfig->mtu = DEFAULT_MTU;
    pGwConfig->vlan_id = DEFAULT_VLAN_ID;
    pGwConfig->if_cmd = OVS_IF_UP_CMD;

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config(_, _))
        .Times(1) 
        .WillRepeatedly(::testing::DoAll(
            SetGwConfigArg1((void **)&pGwConfig),
            ::testing::Return(true)
        ));
    EXPECT_CALL(*g_ovsMock, ovs_agent_api_interact(_, _))
        .Times(1) 
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePostConfigVendorGeneric(_, _))
	 .Times(1)
        .WillOnce(Return(0));
    char event21[64] = {0} , value21[64] = {0};
    snprintf(event21,sizeof(event21),"multinet_%d-localready",InstanceNumber);
    strcpy(value21, "1");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event21), StrEq(value21), _))
	 .Times(1)
        .WillOnce(Return(0));
    char event3[64] = {0} , value3[64] = {0};
    snprintf(event3,sizeof(event3),"multinet_%d-status",InstanceNumber);
    strcpy(value3, "ready");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event3), StrEq(value3), _))
	 .Times(1)
        .WillOnce(Return(0));
    char event4[64] = {0} ;
    snprintf(event4,sizeof(event4),"firewall-restart");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event4), _, _))
	 .Times(1)
        .WillOnce(Return(0));
    CreateBrInterface();
}

TEST_F(BridgeUtilsTestFixture, CreateBrInterfaceLnF)
{
    char event[64] = {0}, value[64] = {0};
    InstanceNumber = 6;
    ovsEnable = 1;
    DeviceMode = 1;
    ethWanEnabled = 1;
    wan_mode = 0;
    skipMoCA = 1;
    skipWiFi = 0;
    BridgeOprInPropgress = 1;

    // Set initial event
    snprintf(event, sizeof(event), "multinet_%d-status", InstanceNumber);
    strcpy(value, "partial");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
        .Times(1)
        .WillOnce(Return(0));

    struct ParamNameExpectedValue {
        const char* name;
        const char* expectedValue;
    };

    ParamNameExpectedValue params[] = {
        {"dmsb.l2net.%d.Name", "br106"},
        {"dmsb.l2net.%d.Vid", "106"},
        {"dmsb.l2net.%d.Members.Link", ""},
        {"dmsb.l2net.%d.Members.Eth", ""},
        {"dmsb.l2net.%d.Members.WiFi", "wifi0 wifi1 wifi2 wifi3"},
        {"dmsb.l2net.%d.Members.Gre", ""},
        {"dmsb.l2net.%d.Members.VirtualParentIfname", ""}
    };

    for (int i = 0; i < sizeof(params) / sizeof(params[0]); ++i) {
        char paramName[128] = {0};
        snprintf(paramName, sizeof(paramName), params[i].name, InstanceNumber);
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetPsmValueArg4(&params[i].expectedValue),
                ::testing::Return(100)
            ));
    }

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePreConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    const char* eventNames[] = {
        "multinet_%d-name",
        "multinet_%d-vid"
    };

    const char* eventValues[] = {
        "br106",
        "106"
    };

    for (int i = 0; i < sizeof(eventNames) / sizeof(eventNames[0]); ++i) {
        snprintf(event, sizeof(event), eventNames[i], InstanceNumber);
        strcpy(value, eventValues[i]);
        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
            .Times(1)
            .WillOnce(Return(0));
    }

    Gateway_Config* pGwConfig = (Gateway_Config*)malloc(sizeof(Gateway_Config));
    memset(pGwConfig, 0, sizeof(Gateway_Config));
    pGwConfig->if_type = OVS_OTHER_IF_TYPE;
    pGwConfig->mtu = DEFAULT_MTU;
    pGwConfig->vlan_id = DEFAULT_VLAN_ID;
    pGwConfig->if_cmd = OVS_IF_UP_CMD;

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config(_, _))
        .Times(4)
        .WillRepeatedly(::testing::DoAll(
            SetGwConfigArg1((void**)&pGwConfig),
            ::testing::Return(true)
        ));
    EXPECT_CALL(*g_ovsMock, ovs_agent_api_interact(_, _))
        .Times(4)
        .WillRepeatedly(Return(true));

    char expectedValue111[128] = "8";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.LnF_l3net"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue111),
            ::testing::Return(100)
        ));

    char paramName21[128] = {0};
    snprintf(paramName21, sizeof(paramName21), "dmsb.l3net.%d.V4Addr", 8);
    char expectedValue21[128] = "192.168.10.11";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName21), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue21),
            ::testing::Return(100)
        ));

    char paramName31[128] = {0};
    snprintf(paramName31,sizeof(paramName31), "dmsb.l3net.%d.V4SubnetMask", 8);
    char expectedValue31[128] = "";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName31), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue31),
            ::testing::Return(100)
        ));

    char expectedCmd123[216] = {0};
    snprintf(expectedCmd123, sizeof(expectedCmd123), "ifconfig %s %s", eventValues[0], expectedValue21); \
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::HasSubstr(expectedCmd123), _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePostConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    snprintf(event, sizeof(event), "multinet_%d-localready", InstanceNumber);
    strcpy(value, "1");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
        .Times(1)
        .WillOnce(Return(0));

    snprintf(event, sizeof(event), "multinet_%d-status", InstanceNumber);
    strcpy(value, "ready");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
        .Times(1)
        .WillOnce(Return(0));

    snprintf(event, sizeof(event), "firewall-restart");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), _, _))
        .Times(1)
        .WillOnce(Return(0));

    CreateBrInterface();
}

TEST_F(BridgeUtilsTestFixture, CreateBrInterfaceMocaIsolation)
{
    char event[64] = {0}, value[64] = {0};
    InstanceNumber = MOCA_ISOLATION;
    ovsEnable = 1;
    DeviceMode = 0;
    ethWanEnabled = 0;
    wan_mode = 0;
    skipMoCA = 0;
    skipWiFi = 0;
    BridgeOprInPropgress = 1;
    MocaIsolation_Enabled = 1;

    snprintf(event, sizeof(event), "multinet_%d-status", InstanceNumber);
    strcpy(value, "partial");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
        .Times(1)
        .WillOnce(Return(0));

    struct ParamNameExpectedValue {
        const char* name;
        const char* expectedValue;
    };

    ParamNameExpectedValue params[] = {
        {"dmsb.l2net.%d.Name", "brlan1"},
        {"dmsb.l2net.%d.Vid", "101"},
        {"dmsb.l2net.%d.Members.Link", ""},
        {"dmsb.l2net.%d.Members.Eth", ""},
        {"dmsb.l2net.%d.Members.Moca", "moca0"},
        {"dmsb.l2net.%d.Members.WiFi", "wifi0 wifi1"},
        {"dmsb.l2net.%d.Members.Gre", ""},
        {"dmsb.l2net.%d.Members.VirtualParentIfname", ""}
    };

    for (int i = 0; i < sizeof(params) / sizeof(params[0]); ++i) {
        char paramName[128] = {0};
        snprintf(paramName, sizeof(paramName), params[i].name, InstanceNumber);
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetPsmValueArg4(&params[i].expectedValue),
                ::testing::Return(100)
            ));
    }

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePreConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    char event1[64] = {0}, value1[64] = {0};
    snprintf(event1, sizeof(event1), "multinet_%d-name", InstanceNumber);
    strcpy(value1, "brlan1");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event1), StrEq(value1), _))
        .Times(1)
        .WillOnce(Return(0));

    char event2[64] = {0}, value2[64] = {0};
    snprintf(event2, sizeof(event2), "multinet_%d-vid", InstanceNumber);
    snprintf(value2, sizeof(value2), "%d", 101);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event2), StrEq(value2), _))
        .Times(1)
        .WillOnce(Return(0));

    Gateway_Config *pGwConfig = NULL;
    pGwConfig = (Gateway_Config*)malloc(sizeof(Gateway_Config));
    memset(pGwConfig, 0, sizeof(Gateway_Config));
    pGwConfig->if_type = OVS_OTHER_IF_TYPE;
    pGwConfig->mtu = DEFAULT_MTU;
    pGwConfig->vlan_id = DEFAULT_VLAN_ID;
    pGwConfig->if_cmd = OVS_IF_UP_CMD;

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_interact(_, _))
        .Times(3) 
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config(_, _))
        .Times(3) 
        .WillRepeatedly(::testing::DoAll(
            SetGwConfigArg1((void**)&pGwConfig),
            ::testing::Return(true)
        ));

    char expectedValue111[128] = "7";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.MoCAIsoLation_l3net"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue111),
            ::testing::Return(100)
        ));

    char paramName21[128] = {0};
    snprintf(paramName21, sizeof(paramName21), "dmsb.l3net.%d.V4Addr", 7);
    char expectedValue21[128] = "169.254.30.1";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName21), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue21),
            ::testing::Return(100)
        ));

    char paramName41[128] = {0};
    snprintf(paramName41, sizeof(paramName41), "dmsb.l3net.%d.V4SubnetMask", 7);
    char expectedValue41[128] = "";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName41), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue41),
            ::testing::Return(100)
        ));

    char paramName31[128] = {0};
    snprintf(paramName31, sizeof(paramName31), "dmsb.l2net.%d.Name", PRIVATE_LAN);
    char expectedValue31[128] = "brlan0";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName31), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue31),
            ::testing::Return(100)
        ));

    char expectedCmd123[512] = {0};
    snprintf(expectedCmd123, sizeof(expectedCmd123), "ip link set %s allmulticast on ; \
        ifconfig %s %s ; \
        ip link set %s up ; \
        echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts ; \
        sysctl -w net.ipv4.conf.all.arp_announce=3 ; \
        ip rule add from all iif %s lookup all_lans ; \
        echo 0 > /proc/sys/net/ipv4/conf/%s/rp_filter ; \
        touch /tmp/MoCABridge_up",
        value1,
        value1,
        expectedValue21,
        value1,
        value1,
        value1);

    const char* expectedCmd124 = "ip link set brlan1 allmulticast on ;\t    \tifconfig brlan1 169.254.30.1 ; \t    \tip link set brlan1 up ; \t    \techo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts ; \t    \tsysctl -w net.ipv4.conf.all.arp_announce=3 ; \t    \tip rule add from all iif brlan1";
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(StrEq(expectedCmd124), _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePostConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    char event21[64] = {0}, value21[64] = {0};
    snprintf(event21, sizeof(event21), "multinet_%d-localready", InstanceNumber);
    strcpy(value21, "1");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event21), StrEq(value21), _))
        .Times(1)
        .WillOnce(Return(0));

    char event3[64] = {0}, value3[64] = {0};
    snprintf(event3, sizeof(event3), "multinet_%d-status", InstanceNumber);
    strcpy(value3, "ready");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event3), StrEq(value3), _))
        .Times(1)
        .WillOnce(Return(0));

    char event4[64] = {0};
    snprintf(event4, sizeof(event4), "firewall-restart");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event4), _, _))
        .Times(1)
        .WillOnce(Return(0));

    CreateBrInterface();
}

TEST_F(BridgeUtilsTestFixture, CreateBrInterfaceMesh)
{
    char event[64] = {0} , value[64] = {0};
    InstanceNumber = MESH_BACKHAUL;
    ovsEnable = 1;
    DeviceMode = 0;
    ethWanEnabled = 0;
    wan_mode = 0;
    skipMoCA = 0;
    skipWiFi = 0;
    BridgeOprInPropgress = 1;
    snprintf(event,sizeof(event),"multinet_%d-status",InstanceNumber);
    strcpy(value, "partial");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
        .Times(1)
        .WillOnce(Return(0));
    struct Param {
        char name[128];
        char expectedValue[128];
    };

    Param params[] = {
        {"dmsb.l2net.%d.Name", "br403"},
        {"dmsb.l2net.%d.Vid", "1060"},
        {"dmsb.l2net.%d.Members.Link", ""},
        {"dmsb.l2net.%d.Members.Eth", ""},
        {"dmsb.l2net.%d.Members.Moca", ""},
        {"dmsb.l2net.%d.Members.WiFi", ""},
        {"dmsb.l2net.%d.Members.Gre", ""},
        {"dmsb.l2net.%d.Members.VirtualParentIfname", ""}
    };

    for (int i = 0; i < sizeof(params)/sizeof(Param); i++) {
        char paramName[128] = {0};
        snprintf(paramName, sizeof(paramName), params[i].name, InstanceNumber);
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetPsmValueArg4(&params[i].expectedValue),
                ::testing::Return(100)
            ));
    }
    
    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePreConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));
    
    char event1[64] = {0}, value1[64] = {0};
    snprintf(event1,sizeof(event1),"multinet_%d-name",InstanceNumber);
    strcpy(value1, "br403");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event1), StrEq(value1), _))
        .Times(1)
        .WillOnce(Return(0));
    
    char event2[64] = {0}, value2[64] = {0};
    snprintf(event2,sizeof(event2),"multinet_%d-vid",InstanceNumber);
    snprintf(value2,sizeof(value2),"%d",1060);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event2), StrEq(value2), _))
        .Times(1)
        .WillOnce(Return(0));
    
    Gateway_Config *pGwConfig = NULL;
    pGwConfig = (Gateway_Config*) malloc(sizeof(Gateway_Config));
    memset(pGwConfig, 0, sizeof(Gateway_Config));
    pGwConfig->if_type = OVS_OTHER_IF_TYPE;
    pGwConfig->mtu = DEFAULT_MTU;
    pGwConfig->vlan_id = DEFAULT_VLAN_ID;
    pGwConfig->if_cmd = OVS_IF_UP_CMD;

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config( _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetGwConfigArg1((void **)&pGwConfig),
            ::testing::Return(true)
        ));
    EXPECT_CALL(*g_ovsMock, ovs_agent_api_interact( _, _))
        .Times(1)
        .WillOnce(Return(true));

    char expectedValue111[128] = "9";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq("dmsb.MultiLAN.MeshBhaul_l3net"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue111),
            ::testing::Return(100)
        ));

    char paramName21[128] = {0};
    snprintf(paramName21, sizeof(paramName21), "dmsb.l3net.%d.V4Addr", 9);
    char expectedValue21[128] = "192.168.245.254";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName21), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue21),
            ::testing::Return(100)
        ));

    char paramName31[128] = {0};
    snprintf(paramName31, sizeof(paramName31), "dmsb.l3net.%d.V4SubnetMask", 9);
    char expectedValue31[128] = "255.255.255.0"; // Default Subnet Mask
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName31), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue31),
            ::testing::Return(100)
        ));

    char expectedCmd123[216] = {0};
    snprintf(expectedCmd123, sizeof(expectedCmd123), "ifconfig %s %s", "br403", expectedValue21);
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::HasSubstr(expectedCmd123), _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePostConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));
    
    char event21[64] = {0}, value21[64] = {0};
    snprintf(event21, sizeof(event21), "multinet_%d-localready", InstanceNumber);
    strcpy(value21, "1");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event21), StrEq(value21), _))
        .Times(1)
        .WillOnce(Return(0));
    
    char event3[64] = {0}, value3[64] = {0};
    snprintf(event3, sizeof(event3), "multinet_%d-status", InstanceNumber);
    strcpy(value3, "ready");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event3), StrEq(value3), _))
        .Times(1)
        .WillOnce(Return(0));
    
    char event4[64] = {0};
    snprintf(event4, sizeof(event4), "firewall-restart");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event4), _, _))
        .Times(1)
        .WillOnce(Return(0));

    CreateBrInterface();
}

TEST_F(BridgeUtilsTestFixture, CreateBrInterfaceMeshWiFi2G)
{
    char event[64] = {0}, value[64] = {0};
    InstanceNumber = MESH_WIFI_BACKHAUL_2G;
    ovsEnable = 1;
    DeviceMode = 0;
    ethWanEnabled = 0;
    wan_mode = 0;
    skipMoCA = 0;
    skipWiFi = 0;
    snprintf(event, sizeof(event), "multinet_%d-status", InstanceNumber);
    strcpy(value, "partial");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
        .Times(1)
        .WillOnce(Return(0));

    struct Param {
        char name[128];
        char expectedValue[128];
    };

    Param params[] = {
        {"dmsb.l2net.%d.Name", "brlan112"},
        {"dmsb.l2net.%d.Vid", "112"},
        {"dmsb.l2net.%d.Members.Link", ""},
        {"dmsb.l2net.%d.Members.Eth", ""},
        {"dmsb.l2net.%d.Members.Moca", ""},
        {"dmsb.l2net.%d.Members.WiFi", "wifi0"},
        {"dmsb.l2net.%d.Members.Gre", ""},
        {"dmsb.l2net.%d.Members.VirtualParentIfname", ""}
    };

    for (int i = 0; i < sizeof(params)/sizeof(Param); i++) {
        char paramName[128] = {0};
        snprintf(paramName, sizeof(paramName), params[i].name, InstanceNumber);
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetPsmValueArg4(&params[i].expectedValue),
                ::testing::Return(100)
            ));
    }

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePreConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    char event1[64] = {0}, value1[64] = {0};
    snprintf(event1, sizeof(event1), "multinet_%d-name", InstanceNumber);
    strcpy(value1, "brlan112");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event1), StrEq(value1), _))
        .Times(1)
        .WillOnce(Return(0));

    char event2[64] = {0}, value2[64] = {0};
    snprintf(event2, sizeof(event2), "multinet_%d-vid", InstanceNumber);
    snprintf(value2, sizeof(value2), "%d", 112);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event2), StrEq(value2), _))
        .Times(1)
        .WillOnce(Return(0));

    Gateway_Config *pGwConfig = NULL;
    pGwConfig = (Gateway_Config*) malloc(sizeof(Gateway_Config));
    memset(pGwConfig, 0, sizeof(Gateway_Config));
    pGwConfig->if_type = OVS_OTHER_IF_TYPE;
    pGwConfig->mtu = DEFAULT_MTU;
    pGwConfig->vlan_id = DEFAULT_VLAN_ID;
    pGwConfig->if_cmd = OVS_IF_UP_CMD;

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config(_, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetGwConfigArg1((void **)&pGwConfig),
            ::testing::Return(true)
        ));

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_interact(_, _))
        .Times(1)
        .WillOnce(Return(true));

    char expectedValue111[128] = "10";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.MeshWiFiBhaul_2G_l3net"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue111),
            ::testing::Return(100)
        ));

    char paramName21[128] = {0};
    snprintf(paramName21, sizeof(paramName21), "dmsb.l3net.%d.V4Addr", 10);
    char expectedValue21[128] = "169.254.0.1";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName21), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue21),
            ::testing::Return(100)
        ));

    char paramName31[128] = {0};
    snprintf(paramName31, sizeof(paramName31), "dmsb.l3net.%d.V4SubnetMask", 10);
    char expectedValue31[128] = "255.255.255.0";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName31), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue31),
            ::testing::Return(100)
        ));

    char expectedCmd123[216] = {0};
    snprintf(expectedCmd123, sizeof(expectedCmd123), "ifconfig %s %s netmask %s up", "brlan112", expectedValue21, expectedValue31);
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::HasSubstr(expectedCmd123), _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePostConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    char event21[64] = {0}, value21[64] = {0};
    snprintf(event21, sizeof(event21), "multinet_%d-localready", InstanceNumber);
    strcpy(value21, "1");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event21), StrEq(value21), _))
        .Times(1)
        .WillOnce(Return(0));

    char event3[64] = {0}, value3[64] = {0};
    snprintf(event3, sizeof(event3), "multinet_%d-status", InstanceNumber);
    strcpy(value3, "ready");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event3), StrEq(value3), _))
        .Times(1)
        .WillOnce(Return(0));

    char event4[64] = {0};
    snprintf(event4, sizeof(event4), "firewall-restart");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event4), _, _))
        .Times(1)
        .WillOnce(Return(0));

    CreateBrInterface();
}


TEST_F(BridgeUtilsTestFixture, CreateBrInterfaceMeshWiFi5G)
{
    using namespace testing;
    InstanceNumber = MESH_WIFI_BACKHAUL_5G;
    ovsEnable = 1;
    DeviceMode = 0;
    ethWanEnabled = 0;
    wan_mode = 0;
    skipMoCA = 0;
    skipWiFi = 0;

    char event[64] = {0}, value[64] = {0};
    snprintf(event, sizeof(event), "multinet_%d-status", InstanceNumber);
    strcpy(value, "partial");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
        .Times(1)
        .WillOnce(Return(0));

    struct Param {
        const char* name;
        const char* expectedValue;
    };

    Param params[] = {
        {"dmsb.l2net.%d.Name", "brlan113"},
        {"dmsb.l2net.%d.Vid", "113"},
        {"dmsb.l2net.%d.Members.Link", ""},
        {"dmsb.l2net.%d.Members.Eth", ""},
        {"dmsb.l2net.%d.Members.Moca", ""},
        {"dmsb.l2net.%d.Members.WiFi", "wifi0"},
        {"dmsb.l2net.%d.Members.Gre", ""},
        {"dmsb.l2net.%d.Members.VirtualParentIfname", ""}
    };

    for (int i = 0; i < sizeof(params)/sizeof(Param); i++) {
        char paramName[128] = {0};
        snprintf(paramName, sizeof(paramName), params[i].name, InstanceNumber);
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetPsmValueArg4(&params[i].expectedValue),
                ::testing::Return(100)
        ));
    }

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePreConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    const char* syseventParams[] = {
        "multinet_%d-name",
        "multinet_%d-vid"
    };

    const char* syseventValues[] = {
        "brlan113",
        "113"
    };

    for (int i = 0; i < 2; ++i) {
        char event[64] = {0}, value[64] = {0};
        snprintf(event, sizeof(event), syseventParams[i], InstanceNumber);
        snprintf(value, sizeof(value), "%s", syseventValues[i]);
        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
            .Times(1)
            .WillOnce(Return(0));
    }

    Gateway_Config *pGwConfig = (Gateway_Config*) malloc(sizeof(Gateway_Config));
    memset(pGwConfig, 0, sizeof(Gateway_Config));
    pGwConfig->if_type = OVS_OTHER_IF_TYPE;
    pGwConfig->mtu = DEFAULT_MTU;
    pGwConfig->vlan_id = DEFAULT_VLAN_ID;
    pGwConfig->if_cmd = OVS_IF_UP_CMD;

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config(_, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetGwConfigArg1((void**)&pGwConfig),
            ::testing::Return(true)
        ));

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_interact(_, _))
        .Times(1)
        .WillOnce(Return(true));

    char expectedValue111[128] = "11";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.MultiLAN.MeshWiFiBhaul_5G_l3net"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&expectedValue111),
            ::testing::Return(100)
        ));

    const char* l3netParams[] = {
        "dmsb.l3net.%d.V4Addr",
        "dmsb.l3net.%d.V4SubnetMask"
    };

    const char* l3netExpectedValues[] = {
        "169.254.1.1",
        "255.255.255.0"
    };

    for (int i = 0; i < 2; ++i) {
        char paramName[128] = {0};
        snprintf(paramName, sizeof(paramName), l3netParams[i], 11);
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetPsmValueArg4(&l3netExpectedValues[i]),
                ::testing::Return(100)
            ));
    }

    char expectedCmd123[216] = {0};
    snprintf(expectedCmd123, sizeof(expectedCmd123), "ifconfig %s %s netmask %s up", params[0].expectedValue, l3netExpectedValues[0], l3netExpectedValues[1]);
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::HasSubstr(expectedCmd123), _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePostConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    const char* finalEvents[] = {
        "multinet_%d-localready",
        "multinet_%d-status",
        "firewall-restart"
    };

    const char* finalValues[] = {
        "1",
        "ready"
    };

    for (int i = 0; i < 2; ++i) {
        char event[64] = {0}, value[64] = {0};
        snprintf(event, sizeof(event), finalEvents[i], InstanceNumber);
        strcpy(value, finalValues[i]);
        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
            .Times(1)
            .WillOnce(Return(0));
    }

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(finalEvents[2]), _, _))
        .Times(1)
        .WillOnce(Return(0));

    CreateBrInterface();
    free(pGwConfig);
}

TEST_F(BridgeUtilsTestFixture, CreateBrInterfaceHotspot2G)
{
    InstanceNumber = HOTSPOT_2G;
    ovsEnable = 1;
    DeviceMode = 0;
    ethWanEnabled = 0;
    wan_mode = 0;
    skipMoCA = 0;
    skipWiFi = 0;

    char event[64] = {0}, value[64] = {0};
    snprintf(event, sizeof(event), "multinet_%d-status", InstanceNumber);
    strcpy(value, "partial");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
        .Times(1)
        .WillOnce(Return(0));

    struct Param {
        const char* name;
        const char* expectedValue;
    };

    Param params[] = {
        {"dmsb.l2net.%d.Name", "brlan2"},
        {"dmsb.l2net.%d.Vid", "102"},
        {"dmsb.l2net.%d.Members.Link", ""},
        {"dmsb.l2net.%d.Members.Eth", ""},
        {"dmsb.l2net.%d.Members.Moca", ""},
        {"dmsb.l2net.%d.Members.WiFi", "wifi0"},
        {"dmsb.l2net.%d.Members.Gre", "gre0"},
        {"dmsb.l2net.%d.Members.VirtualParentIfname", ""}
    };

    for (int i = 0; i < sizeof(params)/sizeof(Param); i++) {
        char paramName[128] = {0};
        snprintf(paramName, sizeof(paramName), params[i].name, InstanceNumber);
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetPsmValueArg4(&params[i].expectedValue),
                ::testing::Return(100)
            ));
    }

    char hotspotEnableValue[] = "1";
    char expectedHotspotValue[] = "0";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.hotspot.enable"), _, _))
        .WillRepeatedly(::testing::DoAll(
            SetPsmValueArg4(&expectedHotspotValue),
            ::testing::Return(100)
        ));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePreConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePostConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    char event1[64] = {0}, value1[64] = {0};
    snprintf(event1, sizeof(event1), "multinet_%d-name", InstanceNumber);
    strcpy(value1, "brlan2");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event1), StrEq(value1), _))
        .Times(1)
        .WillOnce(Return(0));

    char event2[64] = {0}, value2[64] = {0};
    snprintf(event2, sizeof(event2), "multinet_%d-vid", InstanceNumber);
    snprintf(value2, sizeof(value2), "%d", 102);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event2), StrEq(value2), _))
        .Times(1)
        .WillOnce(Return(0));

    Gateway_Config *pGwConfig = (Gateway_Config*) malloc(sizeof(Gateway_Config));
    memset(pGwConfig, 0, sizeof(Gateway_Config));
    pGwConfig->if_type = OVS_OTHER_IF_TYPE;
    pGwConfig->mtu = DEFAULT_MTU;
    pGwConfig->vlan_id = DEFAULT_VLAN_ID;
    pGwConfig->if_cmd = OVS_IF_UP_CMD;

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config(_, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetGwConfigArg1((void**)&pGwConfig),
            ::testing::Return(true)
        ));

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_interact(_, _))
        .Times(1)
        .WillOnce(Return(true));

    const char* eventFormats[] = {
        "multinet_%d-localready",
        "multinet_%d-status",
        "firewall-restart"
    };

    const char* values[] = {
        "1",
        "ready",
        NULL
    };

    int times[] = {
        1,
        1,
        1
    };

    for (int i = 0; i < sizeof(eventFormats)/sizeof(eventFormats[0]); i++) {
        char event[64] = {0};
        snprintf(event, sizeof(event), eventFormats[i], InstanceNumber);
        if (values[i]) {
            char value[64] = {0};
            strcpy(value, values[i]);
            EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
                .Times(times[i])
                .WillOnce(Return(0));
        } 
        else 
        {
            EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), _, _))
                .Times(times[i])
                .WillOnce(Return(0));
        }
    }

    CreateBrInterface();
    free(pGwConfig);
}

TEST_F(BridgeUtilsTestFixture, CreateBrInterfaceHotspotSecure5G)
{
    using namespace testing;
    InstanceNumber = HOTSPOT_SECURE_5G;
    ovsEnable = 1;
    DeviceMode = 0;
    ethWanEnabled = 0;
    wan_mode = 0;
    skipMoCA = 0;
    skipWiFi = 0;

    char event[64] = {0}, value[64] = {0};
    snprintf(event, sizeof(event), "multinet_%d-status", InstanceNumber);
    strcpy(value, "partial");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
        .Times(1)
        .WillOnce(Return(0));

    struct Param {
        const char* name;
        const char* expectedValue;
    };

    Param params[] = {
        {"dmsb.l2net.%d.Name", "brlan5"},
        {"dmsb.l2net.%d.Vid", "105"},
        {"dmsb.l2net.%d.Members.Link", ""},
        {"dmsb.l2net.%d.Members.Eth", ""},
        {"dmsb.l2net.%d.Members.Moca", ""},
        {"dmsb.l2net.%d.Members.WiFi", "wifi0"},
        {"dmsb.l2net.%d.Members.Gre", "gre0"},
        {"dmsb.l2net.%d.Members.VirtualParentIfname", ""}
    };

for (int i = 0; i < sizeof(params) / sizeof(params[0]); ++i) {
    char paramName[128] = {0};
    snprintf(paramName, sizeof(paramName), params[i].name, InstanceNumber);
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&params[i].expectedValue),
            ::testing::Return(100)
        ));
}

    const char* hotspotParam = "dmsb.hotspot.enable";
    char expectedHotspotValue[] = "0";
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(hotspotParam), _, _))
        .Times(2)
        .WillRepeatedly(::testing::DoAll(
            SetPsmValueArg4(&expectedHotspotValue),
            ::testing::Return(100)
        ));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePreConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    const char* syseventParams[] = {
        "multinet_%d-name",
        "multinet_%d-vid"
    };

    const char* syseventValues[] = {
        "brlan5",
        "105"
    };

    for (int i = 0; i < 2; ++i) {
        char event[64] = {0}, value[64] = {0};
        snprintf(event, sizeof(event), syseventParams[i], InstanceNumber);
        snprintf(value, sizeof(value), "%s", syseventValues[i]);
        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
            .Times(1)
            .WillOnce(Return(0));
    }

    Gateway_Config* pGwConfig = (Gateway_Config*)malloc(sizeof(Gateway_Config));
    memset(pGwConfig, 0, sizeof(Gateway_Config));
    pGwConfig->if_type = OVS_OTHER_IF_TYPE;
    pGwConfig->mtu = DEFAULT_MTU;
    pGwConfig->vlan_id = DEFAULT_VLAN_ID;
    pGwConfig->if_cmd = OVS_IF_UP_CMD;

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config(_, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetGwConfigArg1((void**)&pGwConfig),
            ::testing::Return(true)
        ));

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_interact(_, _))
        .Times(1)
        .WillOnce(Return(true));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePostConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    const char* finalEvents[] = {
        "multinet_%d-localready",
        "multinet_%d-status",
        "firewall-restart"
    };

    const char* finalValues[] = {
        "1",
        "ready"
    };

    for (int i = 0; i < 2; ++i) {
        char event[64] = {0}, value[64] = {0};
        snprintf(event, sizeof(event), finalEvents[i], InstanceNumber);
        strcpy(value, finalValues[i]);
        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
            .Times(1)
            .WillOnce(Return(0));
    }

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(finalEvents[2]), _, _))
        .Times(1)
        .WillOnce(Return(0));

    CreateBrInterface();
}

TEST_F(BridgeUtilsTestFixture, DeleteBrInterface)
{
    using namespace testing;
    InstanceNumber = LOST_N_FOUND;
    BridgeOprInPropgress = DELETE_BRIDGE;
    ovsEnable = 1;
    DeviceMode = 0;
    ethWanEnabled = 0;
    wan_mode = 0;
    skipMoCA = 0;
    skipWiFi = 0;

    char event[64] = {0}, value[64] = {0};
    snprintf(event, sizeof(event), "multinet_%d-status", InstanceNumber);
    strcpy(value, "stopping");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
        .Times(1)
        .WillOnce(Return(0));

    struct Param {
        const char* name;
        const char* expectedValue;
    };

    Param params[] = {
        {"dmsb.l2net.%d.Name", "br106"},
        {"dmsb.l2net.%d.Vid", "106"},
        {"dmsb.l2net.%d.Members.Link", ""},
        {"dmsb.l2net.%d.Members.Eth", ""},
        {"dmsb.l2net.%d.Members.Moca", ""},
        {"dmsb.l2net.%d.Members.WiFi", "wifi0 wifi1 wifi2 wifi3"},
        {"dmsb.l2net.%d.Members.Gre", ""},
        {"dmsb.l2net.%d.Members.VirtualParentIfname", ""}
    };

    for (int i = 0; i < sizeof(params) / sizeof(params[0]); ++i) {
        char paramName[128] = {0};
        snprintf(paramName, sizeof(paramName), params[i].name, InstanceNumber);
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetPsmValueArg4(&params[i].expectedValue),
                ::testing::Return(100)
            ));
    }

    char expectedCmd[256] = {0};
    snprintf(expectedCmd, sizeof(expectedCmd), "ip link set %s down", params[0].expectedValue);
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(::testing::HasSubstr(expectedCmd), _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePreConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    Gateway_Config* pGwConfig = (Gateway_Config*)malloc(sizeof(Gateway_Config));
    memset(pGwConfig, 0, sizeof(Gateway_Config));
    pGwConfig->if_type = OVS_OTHER_IF_TYPE;
    pGwConfig->mtu = DEFAULT_MTU;
    pGwConfig->vlan_id = DEFAULT_VLAN_ID;
    pGwConfig->if_cmd = OVS_IF_UP_CMD;

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config(_, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetGwConfigArg1((void**)&pGwConfig),
            ::testing::Return(true)
        ));

    EXPECT_CALL(*g_ovsMock, ovs_agent_api_interact(_, _))
        .Times(1)
        .WillOnce(Return(true));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePostConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    const char* events[] = {
        "multinet_%d-localready",
        "multinet_%d-status",
        "firewall-restart"
    };

    const char* values[] = {
        "0",
        "stopped"
    };

    for (int i = 0; i < 2; ++i) {
        char event[64] = {0}, value[64] = {0};
        snprintf(event, sizeof(event), events[i], InstanceNumber);
        strcpy(value, values[i]);
        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
            .Times(1)
            .WillOnce(Return(0));
    }

    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(events[2]), _, _))
        .Times(1)
        .WillOnce(Return(0));

    DeleteBrInterface();
    free(pGwConfig);
}

TEST_F(BridgeUtilsTestFixture, SyncBrInterfaces)
{
    using namespace testing;
    InstanceNumber = HOME_SECURITY;
    BridgeOprInPropgress = CREATE_BRIDGE;
    ovsEnable = 1;
    DeviceMode = 0;
    ethWanEnabled = 0;
    wan_mode = 0;
    skipMoCA = 0;
    skipWiFi = 0;

    struct Param {
        const char* name;
        const char* expectedValue;
    };

    Param params[] = {
        {"dmsb.l2net.%d.Name", "brlan1"},
        {"dmsb.l2net.%d.Vid", "101"},
        {"dmsb.l2net.%d.Members.Link", ""},
        {"dmsb.l2net.%d.Members.Eth", ""},
        {"dmsb.l2net.%d.Members.Moca", ""},
        {"dmsb.l2net.%d.Members.WiFi", "wifi0 wifi1"},
        {"dmsb.l2net.%d.Members.Gre", ""},
        {"dmsb.l2net.%d.Members.VirtualParentIfname", ""}
    };

    char event[64] = {0}, value[64] = {0};
    snprintf(event, sizeof(event), "multinet_%d-status", InstanceNumber);
    strcpy(value, "partial");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
        .Times(1)
        .WillOnce(Return(0));

    for (int i = 0; i < sizeof(params) / sizeof(params[0]); ++i) {
        char paramName[128] = {0};
        snprintf(paramName, sizeof(paramName), params[i].name, InstanceNumber);
        EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(paramName), _, _))
            .Times(1)
            .WillOnce(::testing::DoAll(
                SetPsmValueArg4(&params[i].expectedValue),
                ::testing::Return(100)
            ));
    }

    const char* events[] = {
        "multinet_%d-name",
        "multinet_%d-vid"
    };

    const char* values[] = {
        "brlan1",
        "101"
    };

    for (int i = 0; i < sizeof(events) / sizeof(events[0]); ++i) {
        char event[64] = {0}, value[64] = {0};
        snprintf(event, sizeof(event), events[i], InstanceNumber);
        if (i == 1) {
            snprintf(value, sizeof(value), "%d", atoi(values[i]));
        } else {
            strcpy(value, values[i]);
        }
        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
            .Times(1)
            .WillOnce(Return(0));
    }

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePreConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    char expectedCmd[256] = {0};
    snprintf(expectedCmd, sizeof(expectedCmd), "ovs-vsctl list-ifaces %s | tr '\n' ' ' ", params[0].expectedValue);
    char expectedIfList[] = "wifi0 wifi1";
    FILE* expectedFd = (FILE*)0xffffffff;

    EXPECT_CALL(*g_securewrapperMock, v_secure_popen(StrEq("r"), StrEq(expectedCmd), _))
        .Times(1)
        .WillOnce(Return(expectedFd));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd))
        .Times(1)
        .WillOnce(DoAll(SetArrayArgument<0>(expectedIfList, expectedIfList + strlen(expectedIfList)), Return(expectedIfList)));

    EXPECT_CALL(*g_securewrapperMock, v_secure_pclose(expectedFd))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePostConfigVendorGeneric(_, _))
        .Times(1)
        .WillOnce(Return(0));

    char event21[64] = {0}, value21[64] = {0};
    snprintf(event21, sizeof(event21), "multinet_%d-localready", InstanceNumber);
    strcpy(value21, "1");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event21), StrEq(value21), _))
        .Times(1)
        .WillOnce(Return(0));

    char event3[64] = {0}, value3[64] = {0};
    snprintf(event3, sizeof(event3), "multinet_%d-status", InstanceNumber);
    strcpy(value3, "ready");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event3), StrEq(value3), _))
        .Times(1)
        .WillOnce(Return(0));

    char event4[64] = {0};
    snprintf(event4, sizeof(event4), "firewall-restart");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event4), _, _))
        .Times(1)
        .WillOnce(Return(0));

    SyncBrInterfaces();
}


TEST_F(BridgeUtilsTestFixture, SyncBrInterfacesBridgeMode)
{
    using namespace testing;
    InstanceNumber = 1;
    BridgeOprInPropgress = CREATE_BRIDGE;
    ovsEnable = 1;
    DeviceMode = 1;
    ethWanEnabled = 1;
    wan_mode = 0;
    skipMoCA = 0;
    skipWiFi = 0;

    struct ParamData {
        char paramName[128];
        char expectedValue[128];
    } params[] = {
        {"dmsb.l2net.%d.Name", "brlan0"},
        {"dmsb.l2net.%d.Vid", "100"},
        {"dmsb.l2net.%d.Members.Link", "link0 link1"},
        {"dmsb.l2net.%d.Members.Eth", "eth0 eth1"},
        {"dmsb.l2net.%d.Members.Moca", "moca0 moca1 moca2"},
        {"dmsb.l2net.%d.Members.WiFi", "wifi0"},
        {"dmsb.l2net.%d.Members.Gre", ""},
        {"dmsb.l2net.%d.Members.VirtualParentIfname", ""}
    };

    char event[64] = {0} , value[64] = {0};
    snprintf(event,sizeof(event),"multinet_%d-status",InstanceNumber);
    strcpy(value, "partial");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event), StrEq(value), _))
     .Times(1)
        .WillOnce(Return(0));

    for (int i = 0; i < sizeof(params)/sizeof(params[0]); ++i) {
    char expectedParamName[256];
    snprintf(expectedParamName, sizeof(expectedParamName), params[i].paramName, InstanceNumber);
    snprintf(params[i].paramName, sizeof(params[i].paramName), params[i].paramName, InstanceNumber);
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2( _, _, StrEq(expectedParamName), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&params[i].expectedValue),
            ::testing::Return(100)
        ));
    }

    char event1[64] = {0} , value1[64] = {0};
    snprintf(event1,sizeof(event1),"multinet_%d-name",InstanceNumber);
    strcpy(value1, "brlan0");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event1), StrEq(value1), _))
	 .Times(1)
        .WillOnce(Return(0));
    char event2[64] = {0} , value2[64] = {0};
    snprintf(event2,sizeof(event2),"multinet_%d-vid",InstanceNumber);
    snprintf(value2,sizeof(value2),"%d",100);
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event2), StrEq(value2), _))
	 .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePreConfigVendorGeneric(_, _))
	 .Times(1)
        .WillOnce(Return(0));
    char expectedCmd[256] = {0};
    memset(expectedCmd,0,sizeof(expectedCmd));
    snprintf(expectedCmd, sizeof(expectedCmd), "ovs-vsctl list-ifaces brlan0 | tr '\n' ' ' ");
    char expectedIfList[] = "wifi0 wifi1 nmoca0";
    FILE * expectedFd = (FILE *)0xffffffff;
    
    EXPECT_CALL(*g_securewrapperMock, v_secure_popen(StrEq("r"), StrEq(expectedCmd), _))
        .Times(1)
        .WillOnce(Return(expectedFd));
    
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd))
        .Times(1)
        .WillOnce(DoAll(SetArrayArgument<0>(expectedIfList, expectedIfList + strlen(expectedIfList)), Return(expectedIfList)));
    
    EXPECT_CALL(*g_securewrapperMock, v_secure_pclose(expectedFd))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_bridgeUtilsGenericMock, HandlePostConfigVendorGeneric(_, _))
	 .Times(1)
        .WillOnce(Return(0));
    Gateway_Config *pGwConfig = NULL;
    pGwConfig = (Gateway_Config*) malloc(sizeof(Gateway_Config));
    memset(pGwConfig, 0, sizeof(Gateway_Config));
    pGwConfig->if_type = OVS_OTHER_IF_TYPE;
    pGwConfig->mtu = DEFAULT_MTU;
    pGwConfig->vlan_id = DEFAULT_VLAN_ID;
    pGwConfig->if_cmd = OVS_IF_UP_CMD;
    EXPECT_CALL(*g_ovsMock, ovs_agent_api_get_config(_, _))
    .Times(9)
    .WillRepeatedly(Return(false));

        char event21[64] = {0} , value21[64] = {0};
    snprintf(event21,sizeof(event21),"multinet_%d-localready",InstanceNumber);
    strcpy(value21, "1");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event21), StrEq(value21), _))
	 .Times(1)
        .WillOnce(Return(0));
    char event3[64] = {0} , value3[64] = {0};
    snprintf(event3,sizeof(event3),"multinet_%d-status",InstanceNumber);
    strcpy(value3, "ready");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event3), StrEq(value3), _))
	 .Times(1)
        .WillOnce(Return(0));
    char event4[64] = {0} ;
    snprintf(event4,sizeof(event4),"firewall-restart");
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq(event4), _, _))
	 .Times(1)
        .WillOnce(Return(0));
    SyncBrInterfaces();
}
