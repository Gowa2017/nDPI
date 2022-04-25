#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_WECHAT

#include "ndpi_api.h"

static void
ndpi_int_wechat_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct             *flow /* , */
                               /* ndpi_protocol_type_t protocol_type */) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WECHAT,
                               NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

void prt_session(struct ndpi_flow_struct   *flow,
                 struct ndpi_packet_struct *packet) {
    struct in_addr addr;
    addr.s_addr = flow->saddr;
    if (ntohs(*((uint16_t *)&flow->saddr)) != 0xc0a8) { return; };
    char src_addr[16];
    char dst_addr[16];
    inet_ntop(AF_INET, (void *)&addr, src_addr, 16);
    addr.s_addr = flow->daddr;
    inet_ntop(AF_INET, (void *)&addr, dst_addr, 16);
    fprintf(stderr, "%s:%d -> %s:%d\t%x\n", src_addr, ntohs(flow->sport),
            dst_addr, ntohs(flow->dport),
            packet && packet->payload_packet_len > 4
                ? ntohl(get_u_int32_t(packet->payload, 0))
                : 0);
}

void ndpi_search_wechat(struct ndpi_detection_module_struct *ndpi_struct,
                        struct ndpi_flow_struct             *flow) {
    struct ndpi_packet_struct *packet = &ndpi_struct->packet;

    NDPI_LOG_DBG(ndpi_struct, "search wechat\n");
    if (packet->payload_packet_len > 4 &&
        (ntohl(get_u_int32_t(packet->payload, 0)) == 0x17f10401)) {
        NDPI_LOG_INFO(ndpi_struct, "found WECHAT\n");
        ndpi_int_wechat_add_connection(ndpi_struct, flow);
        fprintf(stderr, "wechat\n");
        prt_session(flow, packet);
    } else {
        if (flow->num_processed_pkts > 8) NDPI_EXCLUDE_PROTO(ndpi_struct,
        flow);
    }
}

void init_wechat_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                           u_int32_t                           *id,
                           NDPI_PROTOCOL_BITMASK *detection_bitmask) {
    ndpi_set_bitmask_protocol_detection(
        "wechat", ndpi_struct, detection_bitmask, *id, NDPI_PROTOCOL_WECHAT,
        ndpi_search_wechat,
        NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
        SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);

    *id += 1;
}
