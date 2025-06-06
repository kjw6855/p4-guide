#! /bin/bash
# Copyright 2024 Andy Fingerhut
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0


env_var_error() {
    1>&2 echo "You must set environment variable PYPKG_TESTLIB"
    1>&2 echo "to the path of a directory containing the collection"
    1>&2 echo "Python packages called 'testlib', e.g. the directory"
    1>&2 echo "'testlib' inside of your copy of the p4-guide repository."
}

if [ -z $PYPKG_TESTLIB ]
then
    env_var_error
    exit 1
fi

if [ ! -d ${PYPKG_TESTLIB} ]
then
    1>&2 echo "PYPKG_TESTLIB=${PYPKG_TESTLIB}"
    1>&2 echo "is not the name of a directory."
    1>&2 echo ""
    env_var_error
    exit 1
fi

T="`realpath ${PYPKG_TESTLIB}/backends/dpdk`"
if [ x"${PYTHONPATH}" == "x" ]
then
    P="${T}"
else
    P="${T}:${PYTHONPATH}"
fi

set -x
`which ptf` \
    --pypath "$P" \
    -i 0@TAP0 \
    -i 1@TAP1 \
    -i 2@TAP2 \
    -i 3@TAP3 \
    -i 4@TAP4 \
    -i 5@TAP5 \
    -i 6@TAP6 \
    -i 7@TAP7 \
    --test-params="grpcaddr='localhost:9559';device_id=1;p4info='out/dash_pipeline.p4Info.txt'" \
    --test-dir ptf-tests-using-base-test
set +x

echo ""
echo "PTF test finished."
