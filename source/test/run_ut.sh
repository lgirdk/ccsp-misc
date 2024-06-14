#!/bin/bash
####################################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:
#
# Copyright 2024 RDK Management
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
####################################################################################
# Function to print logs
log() {
    echo " "
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
    echo " "
}

#Storing current directory path
PWD=$(pwd)

# Initialize branch variable with an if-else statement
if [ -z "$BRANCH" ]; then
    branch="stable2"
    log "BRANCH variable is unset; defaulting to 'stable2'"
else
    branch=$BRANCH
    log "Using branch: $branch"
fi

if git clone ssh://gerrit.teamccp.com:29418/rdk/rdkb/components/opensource/ccsp/RdkbGMock/generic RdkbGMock -b $branch; then
log "Entering into RdkbGMock directory..."
cd RdkbGMock
  log "Start Running RdkbGMock Dependency Component Script ..."
  if ./docker_scripts/run_dependency.sh; then
      log "Done Running RdkbGMock Dependency Component Script."
  else
      log "Failed to run Run RdkbGMock Dependency Component Script."
      cd ..
      rm -rf RdkbGMock
      exit 1
  fi
fi
log "Coming out of RdkbGMock directory and Removing it..."
cd ..
rm -rf RdkbGMock

log "Start Running UT Script..."
# Run autogen.sh
log "Running autogen.sh..."
if ./autogen.sh; then
    log "autogen.sh executed successfully."
else
    log "Failed to run autogen.sh"
    exit 1
fi

# Run configure with specific options
log "Running configure with options --enable-gtestapp and --enable-unitTestDockerSupport..."
if ./configure --enable-gtestapp --enable-unitTestDockerSupport; then
    log "Configuration successful."
else
    log "Configuration failed."
    exit 1
fi

# Run make for specific target
log "Running make for bridgeUtils_gtest.bin..."
if make -C source/test/bridge_utils; then
    log "Make operation completed successfully."
else
    log "Make operation failed."
    exit 1
fi
log "Completed running UT script."


log "Preparing to run the Gtest Binary"
if [ -f "./source/test/bridge_utils/bridgeUtils_gtest.bin" ]; then
    log "Running bridgeUtils_gtest.bin"
    ./source/test/bridge_utils/bridgeUtils_gtest.bin
    log "Completed Test Execution"
else
    log "bridgeUtils_gtest.bin does not exist, cannot run tests"
    exit 1
fi

log "Starting Gcov for code coverage analysis"
# Capture initial coverage data
if lcov --directory . --capture --output-file coverage.info; then
    log "Initial coverage data captured successfully"
else
    log "Failed to capture initial coverage data"
    exit 1
fi

# Removing unwanted coverage paths
if lcov --remove coverage.info "${PWD}/source/test/*" --output-file coverage.info && \
   lcov --remove coverage.info '/usr/*' --output-file coverage.info; then
    log "Filtered out test and system library coverage data"
else
    log "Failed to filter coverage data"
    exit 1
fi

# Generating HTML report
if genhtml coverage.info --output-directory out; then
    log "Gcov report generated in 'out' directory"
else
    log "Failed to generate Gcov report"
    exit 1
fi
log "Completed Gcov report analysis"

log "All operations completed for UT successfully"