/* -*- mode: P4_16 -*- */
/*
Copyright 2017 Cisco Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
*/

#include "headers.p4"
#include "mid_ingress_5.p4"

control midIngressImpl4(inout headers_t hdr,
                    inout metadata_t meta,
                    inout standard_metadata_t stdmeta)
{
    // Why bother creating an action that just does one function call?
    // That is, why not just use 'mark_to_drop' as one of the possible
    // actions when defining a table?  Because the P4_16 compiler does
    // not allow function calls to be used directly as actions of
    // tables.  You must use actions explicitly defined with the
    // 'action' keyword like below.

    midIngressImpl5() impl;

    action my_drop() {
        meta.drop_ctl = 1;
        mark_to_drop(stdmeta);
    }

    action set_l2ptr(bit<32> l2ptr) {
        meta.fwd_metadata.l2ptr = l2ptr;
    }
    table ipv4_da_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_l2ptr;
            my_drop;
        }
        default_action = my_drop;
    }

    action set_bd_dmac_intf(bit<24> bd, bit<48> dmac, bit<9> intf) {
        meta.fwd_metadata.out_bd = bd;
        hdr.ethernet.dstAddr = dmac;
        stdmeta.egress_spec = intf;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    table mac_da {
        key = {
            meta.fwd_metadata.l2ptr: exact;
        }
        actions = {
            set_bd_dmac_intf;
            my_drop;
        }
        default_action = my_drop;
    }

    apply {
        ipv4_da_lpm.apply();
        mac_da.apply();

        if (meta.drop_ctl == 0) {
            impl.apply(hdr, meta, stdmeta);
        }
    }
}
