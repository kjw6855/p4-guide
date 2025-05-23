// Copyright 2022 Andy Fingerhut
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#include "before-ingress.p4"

{
    bit<8> tmp1;
    bit<8> tmp2;

    action foo (in bit<8> x, out bit<8> y) { y = (x >> 2); }
    action foo (inout bit<8> x) { x = (x >> 3); }

    table t1 {
        actions = { NoAction; foo; }
        key = { hdr.ethernet.etherType: exact; }
        default_action = foo(tmp1, tmp2);
        size = 512;
    }
    table t2 {
        actions = { NoAction; foo; }
        key = { hdr.ethernet.etherType: exact; }
        default_action = foo(tmp1);
        size = 128;
    }
    apply {
        tmp1 = hdr.ethernet.srcAddr[7:0];
        tmp2 = hdr.ethernet.dstAddr[7:0];
        t1.apply();
        t2.apply();
        // This is here simply to ensure that the compiler cannot
        // optimize away the effects of t1 and t2, which can only
        // assign values to variables tmp1 and tmp2.
        hdr.ethernet.etherType = (bit<16>) (tmp1 - tmp2);
    }
}

#include "after-ingress.p4"
