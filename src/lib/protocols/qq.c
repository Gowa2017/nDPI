/*
 * qq.c
 *
 * Copyright (C) 2009-2011
 * Copyright (C) 2011-18 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_QQ

#include "ndpi_api.h"

enum CLIENT_TYPE { MAC = 1, ANDROID, WIN };

static void
ndpi_int_qq_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                           struct ndpi_flow_struct             *flow /* , */
                           /* ndpi_protocol_type_t protocol_type */) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QQ,
                               NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}
static const char *
get_session(struct ndpi_flow_struct *flow, char *session, int len) {
    struct in_addr addr;
    addr.s_addr = flow->saddr;
    // if (ntohs(*((uint16_t *)&flow->saddr)) != 0xc0a8) { return; };
    char src_addr[16];
    char dst_addr[16];
    inet_ntop(AF_INET, (void *)&addr, src_addr, 16);
    addr.s_addr = flow->daddr;
    inet_ntop(AF_INET, (void *)&addr, dst_addr, 16);
    snprintf(session, len, "[%s]%s:%d -> %s:%d",
             flow->l4_proto == IPPROTO_UDP ? "UDP" : "TCP", src_addr,
             ntohs(flow->sport), dst_addr, ntohs(flow->dport));
    return session;
}

void ndpi_search_qq(struct ndpi_detection_module_struct *ndpi_struct,
                    struct ndpi_flow_struct             *flow) {
    struct ndpi_packet_struct *packet = &ndpi_struct->packet;

    NDPI_LOG_DBG(ndpi_struct, "search QQ\n");
    char session[1024];
    // prt_session(flow);
    // fprintf(stderr, "\t%x,%x, proto: %d\n", packet->payload[0],
    //         packet->payload[packet->payload_packet_len - 1], flow->l4_proto
    //         == IPPROTO_UDP);
    if (packet->payload_packet_len < 4) { return; }
    if ((flow->l4_proto == IPPROTO_UDP) && (packet->payload_packet_len > 11) &&
        // ((ntohs(flow->dport) == 8000) || (ntohs(flow->sport == 8000))) &&
        (packet->payload[0] == 0x2) &&
        (packet->payload[packet->payload_packet_len - 1] == 0x3)) {
        uint16_t cmd = ntohs(get_u_int16_t(packet->payload, 3));
        // only test heart message and receive message;
        if (!((cmd == 0x0002) || (cmd == 0x0017))) return;

        fprintf(stderr, "%s, Win version: %d, number: %u\n",
                get_session(flow, session, 1024),
                ntohs(get_u_int16_t(packet->payload, 1)),
                ntohl(get_u_int32_t(packet->payload, 7)));
        return;
    }
    // 观察来看   4字节长度头，5 字节固定值 0x00 00 00 0d 01 00  4字节序号 01
    // 开头/ 4字节 0/ 1字节QQ号版本 e 10位  d 9位
    uint32_t len = ntohl(get_u_int32_t(packet->payload, 0));
    if (len != packet->payload_packet_len) return;
    if (len < 18) return;
    // 安卓还是 mac
    // 4 字节 0x0000000d
    enum CLIENT_TYPE c = 0;
    if (ntohs(get_u_int16_t(packet->payload, 7)) == 0x0d01) {
        c = MAC;
    } else if (ntohs(get_u_int16_t(packet->payload, 7)) == 0x0a01) {
        c = ANDROID;
    }
    if (c == 0) return;
    // if (ntohl(get_u_int32_t(packet->payload, 4)) == 0x0000000d) return;
    // 2 字节 0x0100
    // if (ntohs(get_u_int16_t(packet->payload, 8)) != 0x0100) return;
    // 4 字节 seq
    uint32_t seq     = ntohl(get_u_int32_t(packet->payload, 10));
    uint32_t version = 0;
    if (seq == 0xe || seq == 0xd) {
        version = seq;
        seq     = 0;
    }
    int ql = 0;
    if (version == 0) { version = ntohl(get_u_int32_t(packet->payload, 14)); }
    ql         = version == 0xd ? 9 : 10;
    u_char *qq = malloc(ql + 1);
    memcpy(qq, (u_char *)&packet->payload[seq == 0 ? 14 : 18], ql);
    qq[ql] = '\0';
    fprintf(stderr, "%s, %s QQ: seq: %x, version: %x, qq: %s\n",
            get_session(flow, session, 1024), c == MAC ? "macOS" : "android",
            seq, version, qq);
    free(qq);

    // if ((packet->payload_packet_len == 72 &&
    //      ntohl(get_u_int32_t(packet->payload, 0)) == 0x02004800) ||
    //     (packet->payload_packet_len == 64 &&
    //      ntohl(get_u_int32_t(packet->payload, 0)) == 0x02004000) ||
    //     (packet->payload_packet_len == 60 &&
    //      ntohl(get_u_int32_t(packet->payload, 0)) == 0x02004200) ||
    //     (packet->payload_packet_len == 84 &&
    //      ntohl(get_u_int32_t(packet->payload, 0)) == 0x02005a00) ||
    //     (packet->payload_packet_len == 56 &&
    //      ntohl(get_u_int32_t(packet->payload, 0)) == 0x02003800) ||
    //     (packet->payload_packet_len >= 39 &&
    //      ntohl(get_u_int32_t(packet->payload, 0)) == 0x28000000)) {
    //     NDPI_LOG_INFO(ndpi_struct, "found QQ\n");
    //     ndpi_int_qq_add_connection(ndpi_struct, flow);
    // } else {
    //     if (flow->num_processed_pkts > 4) NDPI_EXCLUDE_PROTO(ndpi_struct,
    //     flow);
    // }
}

void init_qq_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                       u_int32_t                           *id,
                       NDPI_PROTOCOL_BITMASK               *detection_bitmask) {
    ndpi_set_bitmask_protocol_detection(
        "QQ", ndpi_struct, detection_bitmask, *id, NDPI_PROTOCOL_QQ,
        ndpi_search_qq,
        NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
        SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);

    *id += 1;
}
