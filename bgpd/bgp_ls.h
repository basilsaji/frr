/* MPLS-VPN
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 * This file is part of GxNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_LS_H
#define _QUAGGA_BGP_LS_H

#include "bgpd/bgp_route.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_zebra.h"

#define BGP_LS_NLRI_LENGTH_OFFSET 2
#define BGP_LS_NLRI_HEADER_LEN 4
#define BGP_LS_TLV_LENGTH_OFFSET 2
#define BGP_LS_TLV_HEADER_LEN 4

#define BGP_LS_NLRI_ID_OFFSET 1
#define BGP_LS_NLRI_DATA_MIN_BYTES 9

#define BGP_LS_ROUTER_ID_LEN 4
#define BGP_LS_AS_LEN 4

typedef enum {
	LINK_STATE_NODE_NLRI = 1,
	LINK_STATE_LINK_NLRI = 2,
	LINK_STATE_PREFIX4_NLRI = 3,
	LINK_STATE_PREFIX6_NLRI = 4
} bgp_ls_nlri_type;

typedef enum {
	LS_LOCAL_NODE_DESC = 256,
	LS_REMOTE_NODE_DESC = 257,
	LS_LINK_LOCAL_REMOTE_ID = 258,
	LS_LINK_LOCAL_IPV4 = 259,
	LS_LINK_REMOTE_IPV4 = 260,
	LS_LINK_LOCAL_IPV6 = 261,
	LS_LINK_REMOTE_IPV6 = 262,
	LS_PREFIX_IP_REACH = 265,
	LS_NODE_AS = 512,
	LS_NODE_BGP_LS_ID = 513,
	LS_NODE_IGP_ROUTER_ID = 515,
	LS_NODE_BGP_ROUTER_ID = 516,
} bgp_ls_desc_tlv_type;

typedef enum {
	LS_NODE_LOCAL_BGP_RID_BIT = 1,
	LS_NODE_LOCAL_AS_BIT = 2,
	LS_NODE_REMOTE_BGP_RID_BIT = 3,
	LS_NODE_REMOTE_AS_BIT = 4,
	LS_LINK_LOCAL_IPV4_BIT = 5,
	LS_LINK_REMOTE_IPV4_BIT = 6,
	LS_LINK_LOCAL_ID_BIT = 7,
	LS_LINK_REMOTE_ID_BIT = 8,
	LS_LINK_LOCAL_IPV6_BIT = 9,
	LS_LINK_REMOTE_IPV6_BIT = 10,
	LS_PREFIX_BIT = 11,
	LS_NODE_BGP_LS_ID_BIT = 12,
	LS_NODE_IGP_ROUTER_ID_BIT = 13,
} bgp_ls_nlri_data_bits;

typedef enum {
	LS_NODE_ATTR_SPF_CAP = 1,
	LS_NODE_ATTR_SPF_STATUS = 2,
	LS_LINK_ATTR_PREFIX_LEN = 3,
	LS_LINK_ATTR_SPF_STATUS = 4,
	LS_LINK_IGP_METRIC = 1095,
	LS_PREFIX_ATTR_METRIC = 1155,
	LS_PREFIX_ATTR_SPF_STATUS = 5,
	LS_PREFIX_ATTR_SEQ = 6,
} bgp_ls_attr_tlv_type;

typedef enum {
	LS_NODE_ATTR_SPF_CAP_PRESENT = 1,
	LS_NODE_ATTR_SPF_STATUS_PRESENT = 2,
	LS_LINK_ATTR_PREFIX_LEN_PRESENT = 3,
	LS_LINK_ATTR_SPF_STATUS_PRESENT = 4,
	LS_LINK_IGP_METRIC_PRESENT = 5,
	LS_PREFIX_ATTR_METRIC_PRESENT = 6,
	LS_PREFIX_ATTR_SPF_STATUS_PRESENT = 7,
	LS_PREFIX_ATTR_SEQ_PRESENT = 8,
} bgp_ls_attr_tlv_bit;

typedef enum {
	LS_ISIS_LEVEL1 = 1,
	LS_ISIS_LEVEL2 = 2,
	LS_OSPFV2 = 3,
	LS_DIRECT = 4,
	LS_STATIC = 5,
	LS_OSPFV3 = 6,
	LS_BGP = 7
} bgp_ls_protocol_id;

typedef struct {
	/* Length of the IGP Router ID
	 * 4 - OSPFv2/OSPFv3 non pseudo node
	 * 8 - OSPFv2/OSPFv3 pseudo node
	 * 6 - ISIS non pseudo node
	 * 7 - ISIS pseudo node
	 */
	uint8_t	len;

	uint8_t val[8];
} bgp_ls_igp_router_id;

typedef struct {
	/* BGP LS ATTR present bits */
	uint64_t flag;

	/* BGP LS SPF algorithm */
	uint8_t spf_algo;

	/* BGP LS SPF status */
	uint8_t node_spf_status;

	/* BGP LS IGP metric */
	uint32_t link_igp_metric;

	/* BGP LS Prefix Length */
	uint8_t link_prefix_len;

	/* bgp ls link spf status */
	uint8_t link_spf_status;

	/* BGP LS Prefix metric */
	uint32_t prefix_metric;

	/* bgp ls prefix spf status */
	uint8_t prefix_spf_status;

	/* BGP LS seq lower/higher */
	uint32_t prefix_seq_low;
	uint32_t prefix_seq_high;

} ls_attr_type;

typedef struct {
	/* BGP LS nlri type */
	uint16_t type;

	/* BGP LS nlri flags to set which values are set */
	uint64_t flag;

	/* BGP LS protocol id */
	uint16_t protocol_id;

	/* BGP LS identifier */
	uint16_t identifier;

	/* BGP LS local node desc bgp router id */
	uint32_t local_bgp_router_id;

	/* BGP LS local node desc as */
	uint32_t local_as;

	/* BGP LS remote node desc bgp router id */
	uint32_t remote_bgp_router_id;

	/* BGP LS local node desc as */
	uint32_t remote_as;

	/* BGP LS Local link IPv4 address */
	struct in_addr link_local_ipv4;

	/* BGP LS Remote link IPv4 address */
	struct in_addr link_remote_ipv4;

	/* BGP LS Local id */
	uint32_t link_localid;

	/* BGP LS Remote id */
	uint32_t link_remoteid;

	/* BGP LS Local link IPv6 address */
	struct in6_addr link_local_ipv6;

	/* BGP LS Remote link IPv6 address */
	struct in6_addr link_remote_ipv6;

	/* BGP LS IP Reach prefix */
	struct prefix p;

	/* BGP LS IGP Router ID */
	bgp_ls_igp_router_id igp_router_id;

	/* BGP LS Identifier */
	uint32_t ls_id;

} ls_nlri_type;

extern int bgp_nlri_parse_ls_node_local_desc(struct peer *peer, struct attr *attr,
	uint8_t *data, uint16_t length);
extern int bgp_nlri_parse_ls_node_remote_desc(struct peer *peer, struct attr *attr,
	uint8_t *data, uint16_t length);
extern int bgp_nlri_parse_ls_link_desc(struct peer *peer, struct attr *attr,
	uint8_t *data, uint16_t length);
extern int bgp_nlri_parse_ls_prefix_desc(struct peer *peer, struct attr *attr,
	uint8_t *data, uint16_t length, uint8_t afi);
extern int bgp_nlri_parse_ls_node(struct peer *peer, struct attr *attr,
	uint8_t *data, uint16_t length);
extern int bgp_nlri_parse_ls_link(struct peer *peer, struct attr *attr,
	uint8_t *data, uint16_t length);
extern int bgp_nlri_parse_ls_prefix(struct peer *peer, struct attr *attr,
	uint8_t *data, uint16_t length, uint8_t afi);
extern int bgp_nlri_parse_ls(struct peer *peer, struct attr *attr,
	struct bgp_nlri *packet, int mp_withdraw);


#endif
