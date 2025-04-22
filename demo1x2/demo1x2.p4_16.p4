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

#include <core.p4>
#include <v1model.p4>
#include "headers.p4"
#include "mid_ingress.p4"

parser parserImpl(packet_in packet,
                  out headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t stdmeta)
{
    const bit<16> ETHERTYPE_IPV4 = 16w0x0800;

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control ingressImpl(inout headers_t hdr,
                    inout metadata_t meta,
                    inout standard_metadata_t stdmeta)
{
    midIngressImpl() impl;

    apply {
        impl.apply(hdr, meta, stdmeta);
    }
}


control egressImpl(inout headers_t hdr,
                   inout metadata_t meta,
                   inout standard_metadata_t stdmeta)
{
    action my_drop() {
        mark_to_drop(stdmeta);
    }
    action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    table send_frame {
        key = {
            meta.fwd_metadata.out_bd: exact;
        }
        actions = {
            rewrite_mac;
            my_drop;
        }
        default_action = my_drop;
    }

    apply {
        send_frame.apply();
    }
}

control deparserImpl(packet_out packet,
                     in headers_t hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

control verifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        verify_checksum(hdr.ipv4.isValid() && hdr.ipv4.ihl == 5,
            { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control updateChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(hdr.ipv4.isValid() && hdr.ipv4.ihl == 5,
            { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch(parserImpl(),
         verifyChecksum(),
         ingressImpl(),
         egressImpl(),
         updateChecksum(),
         deparserImpl()) main;
