/* MPLS-VPN
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 * This file is part of GNU Zebra.
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

#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"
#include "queue.h"
#include "filter.h"
#include "mpls.h"
#include "json.h"
#include "zclient.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_ls.h"

int bgp_nlri_parse_ls_node_local_desc(struct peer *peer, struct attr *attr,
			 uint8_t *data, uint16_t length)
{
	uint16_t type;
	uint16_t len;
	uint8_t *pnt;
	uint8_t *lim;
	uint16_t psize = 0;

	pnt = data;
	lim = data + length;

	for (;pnt < lim; pnt+=psize) {

		type = ntohs(*(uint16_t *)pnt);
		len = ntohs(*(uint16_t *)(pnt + BGP_LS_TLV_LENGTH_OFFSET));
		psize = BGP_LS_TLV_HEADER_LEN + len;

		if ( (pnt + psize) > lim ) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / LS LOCAL NODE DESC TLV (type %d tlv length %d exceeds packet size %u)",
				peer->host, type, len, (uint)(lim - pnt));
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}


		switch(type) {
			case LS_NODE_BGP_ROUTER_ID:
				attr->ls_nlri.local_bgp_router_id = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.flag |= ATTR_FLAG_BIT(LS_NODE_LOCAL_BGP_RID_BIT);
				zlog_debug("NODE LOCAL DESC: BGP ROUTER ID: %u",  attr->ls_nlri.local_bgp_router_id);
				break;
			case LS_NODE_BGP_LS_ID:
				attr->ls_nlri.ls_id = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.flag |= ATTR_FLAG_BIT(LS_NODE_BGP_LS_ID_BIT);
				zlog_debug("NODE LOCAL DESC: BGP LS ID: %u",  attr->ls_nlri.ls_id);
				break;
			case LS_NODE_IGP_ROUTER_ID:
				memcpy(&attr->ls_nlri.igp_router_id.val, pnt + BGP_LS_TLV_HEADER_LEN, len);
				attr->ls_nlri.igp_router_id.len = len;
				attr->ls_nlri.flag |= ATTR_FLAG_BIT(LS_NODE_IGP_ROUTER_ID_BIT);
				zlog_debug("NODE LOCAL DESC: IGP ROUTER ID");
				break;
			case LS_NODE_AS:
				attr->ls_nlri.local_as = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.flag |= ATTR_FLAG_BIT(LS_NODE_LOCAL_AS_BIT);
				zlog_debug("NODE LOCAL DESC: LOCAL AS: %u",  attr->ls_nlri.local_as);
				break;
			default:
				return BGP_NLRI_PARSE_ERROR;
		}
	}

	return 0;
}

int bgp_nlri_parse_ls_node_remote_desc(struct peer *peer, struct attr *attr,
			 uint8_t *data, uint16_t length)
{
	uint16_t type;
	uint16_t len;
	uint8_t *pnt;
	uint8_t *lim;
	uint16_t psize = 0;

	pnt = data;
	lim = data + length;

	for (;pnt < lim; pnt+=psize) {

		type = ntohs(*(uint16_t *)pnt);
		len = ntohs(*(uint16_t *)(pnt + BGP_LS_TLV_LENGTH_OFFSET));
		psize = BGP_LS_TLV_HEADER_LEN + len;

		if ( (pnt + psize) > lim ) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / LS LOCAL NODE DESC TLV (type %d tlv length %d exceeds packet size %u)",
				peer->host, type, len, (uint)(lim - pnt));
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		switch(type) {
			case LS_NODE_BGP_ROUTER_ID:
				attr->ls_nlri.remote_bgp_router_id = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.flag |= ATTR_FLAG_BIT(LS_NODE_REMOTE_BGP_RID_BIT);
				zlog_debug("NODE REMOTE DESC: BGP ROUTER ID: %u",  attr->ls_nlri.remote_bgp_router_id);
				break;
			case LS_NODE_AS:
				attr->ls_nlri.remote_as = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.flag |= ATTR_FLAG_BIT(LS_NODE_REMOTE_AS_BIT);
				zlog_debug("NODE REMOTE DESC: REMOTE AS: %u",  attr->ls_nlri.remote_as);
				break;
			default:
				return BGP_NLRI_PARSE_ERROR;
		}
	}
	return 0;
}

int bgp_nlri_parse_ls_link_desc(struct peer *peer, struct attr *attr,
			uint8_t *data, uint16_t length)
{
	uint16_t type;
	uint16_t len;
	uint8_t *pnt = data;
	uint8_t *lim;
	uint16_t psize = 0;

	lim = data + length;

	for (;pnt < lim; pnt+=psize) {

		type = ntohs(*(uint16_t *)pnt);
		len = ntohs(*(uint16_t *)(pnt + BGP_LS_TLV_LENGTH_OFFSET));
		psize = BGP_LS_TLV_HEADER_LEN + len;

		if ( (pnt + psize) > lim ) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / LS LOCAL NODE DESC TLV (type %d tlv length %d exceeds packet size %u)",
				peer->host, type, len, (uint)(lim - pnt));
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		switch(type) {
			case LS_LINK_LOCAL_IPV4:
				attr->ls_nlri.link_local_ipv4.s_addr = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.flag |= ATTR_FLAG_BIT(LS_LINK_LOCAL_IPV4_BIT);
				zlog_debug("LINK DESC: LOCAL IPv4: %s",  inet_ntoa(attr->ls_nlri.link_local_ipv4));
				break;
			case LS_LINK_REMOTE_IPV4:
				attr->ls_nlri.link_remote_ipv4.s_addr = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.flag |= ATTR_FLAG_BIT(LS_LINK_REMOTE_IPV4_BIT);
				zlog_debug("LINK DESC: REMOTE IPv4: %s",  inet_ntoa(attr->ls_nlri.link_remote_ipv4));
				break;
			case LS_LINK_LOCAL_REMOTE_ID:
				attr->ls_nlri.link_localid = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.flag |= ATTR_FLAG_BIT(LS_LINK_LOCAL_ID_BIT);
				attr->ls_nlri.link_remoteid = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN + 4));
				attr->ls_nlri.flag |= ATTR_FLAG_BIT(LS_LINK_REMOTE_ID_BIT);
				break;
			case LS_LINK_LOCAL_IPV6:
				memcpy(&attr->ls_nlri.link_local_ipv6, pnt + BGP_LS_TLV_HEADER_LEN, IPV6_MAX_BYTELEN);
				attr->ls_nlri.flag |= ATTR_FLAG_BIT(LS_LINK_LOCAL_IPV6_BIT);
				break;
			case LS_LINK_REMOTE_IPV6:
				memcpy(&attr->ls_nlri.link_remote_ipv6, pnt + BGP_LS_TLV_HEADER_LEN, IPV6_MAX_BYTELEN);
				attr->ls_nlri.flag |= ATTR_FLAG_BIT(LS_LINK_REMOTE_IPV6_BIT);
				break;
			default:
				return BGP_NLRI_PARSE_ERROR;
		}
	}
	return 0;
}

int bgp_nlri_parse_ls_prefix_desc(struct peer *peer, struct attr *attr,
			 uint8_t *data, uint16_t length, uint8_t afi)
{
	uint16_t type;
	uint16_t len;
	uint8_t *pnt;
	uint8_t *lim;
	uint16_t psize = 0;
	char buf[BUFSIZ];

	pnt = data;
	lim = data + length;

	for (;pnt < lim; pnt+=psize) {

		type = ntohs(*(uint16_t *)pnt);
		len = ntohs(*(uint16_t *)(pnt + BGP_LS_TLV_LENGTH_OFFSET));
		psize = BGP_LS_TLV_HEADER_LEN + len;

		if ( (pnt + psize) > lim ) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / LS PREFIX NLRI TLV (type %d tlv length %d exceeds packet size %u)",
				peer->host, type, len, (uint)(lim - pnt));
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		switch(type) {
			case LS_PREFIX_IP_REACH:
				attr->ls_nlri.p.prefixlen = *(pnt + BGP_LS_TLV_HEADER_LEN);
				if ( (afi == AFI_IP) && (attr->ls_nlri.p.prefixlen > 32) ) {
					flog_err(
						EC_BGP_UPDATE_RCV,
						"%s [Error] Update packet error / LS PREFIX4 NLRI TLV Prefix length more than 32",
						peer->host );
					return BGP_NLRI_PARSE_ERROR;
				}
				attr->ls_nlri.p.family = afi2family(afi);
				memcpy(attr->ls_nlri.p.u.val, pnt + BGP_LS_TLV_HEADER_LEN + 1, len - 1);
				attr->ls_nlri.flag |= ATTR_FLAG_BIT(LS_PREFIX_BIT);
				zlog_debug("PREFIX DESC: IPv4: %s", prefix2str(&(attr->ls_nlri.p), buf, PREFIX_STRLEN));
				break;
			default:
				return BGP_NLRI_PARSE_ERROR;
		}
	}
	return 0;
}

int bgp_nlri_parse_ls_node(struct peer *peer, struct attr *attr,
			 uint8_t *data, uint16_t length)
{
	uint8_t protocolid;
	uint64_t id;
	uint8_t *tlvdata;
	uint16_t tlvdatalen;
	uint16_t type;
	uint8_t *pnt;
	uint8_t *lim;

	protocolid = *(data);
	id = *((uint64_t *)(data + BGP_LS_NLRI_ID_OFFSET));
	attr->ls_nlri.protocol_id = protocolid;
	attr->ls_nlri.identifier = id;
	pnt = data + BGP_LS_NLRI_DATA_MIN_BYTES;
	lim = data + length;

	/* Parse local node descriptor TLV */
	type = ntohs(*(uint16_t *)pnt);
	tlvdatalen = ntohs(*(uint16_t *)(pnt + BGP_LS_TLV_LENGTH_OFFSET));
	tlvdata = pnt + BGP_LS_TLV_HEADER_LEN;

	if ( type != LS_LOCAL_NODE_DESC) {
		flog_err(
			EC_BGP_UPDATE_RCV,
			"%s [Error] Update packet error / LS NODE NLRI TLV expected local node descriptor TLV. Got type %d",
			peer->host, type);
		return BGP_NLRI_PARSE_ERROR;
	}

	if ( (tlvdata + tlvdatalen) > lim ) {
		flog_err(
			EC_BGP_UPDATE_RCV,
			"%s [Error] Update packet error / LS NODE NLRI TLV (type %d tlv length %d exceeds packet size %u)",
			peer->host, type, tlvdatalen, (uint)(lim - pnt));
		return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
	}

	return bgp_nlri_parse_ls_node_local_desc(peer, attr, tlvdata, tlvdatalen);
}

int bgp_nlri_parse_ls_link(struct peer *peer, struct attr *attr,
			 uint8_t *data, uint16_t length)
{
	uint8_t protocolid;
	uint64_t id;
	uint8_t *tlvdata;
	uint16_t tlvdatalen;
	uint8_t *pnt;
	uint8_t *lim;
	uint16_t psize;
	uint16_t type;
	uint16_t parsedlen = 0;
	int8_t error;

	protocolid = *data;
	id = *((uint64_t *)(data + BGP_LS_NLRI_ID_OFFSET));
	attr->ls_nlri.protocol_id = protocolid;
	attr->ls_nlri.identifier = id;
	pnt = data + BGP_LS_NLRI_DATA_MIN_BYTES;
	lim = data + length;
	parsedlen = BGP_LS_NLRI_DATA_MIN_BYTES;

	/* Parse local node descriptor TLV */
	type = ntohs(*(uint16_t *)pnt);
	tlvdatalen = ntohs(*(uint16_t *)(pnt + BGP_LS_TLV_LENGTH_OFFSET));
	psize = tlvdatalen +  BGP_LS_TLV_HEADER_LEN;
	tlvdata = pnt + BGP_LS_TLV_HEADER_LEN;

	if ( type != LS_LOCAL_NODE_DESC) {
		flog_err(
			EC_BGP_UPDATE_RCV,
			"%s [Error] Update packet error / LS LINK NLRI TLV expected local node descriptor TLV. Got type %d",
			peer->host, type);
		return BGP_NLRI_PARSE_ERROR;
	}

	if ( (tlvdata + tlvdatalen) > lim ) {
		flog_err(
			EC_BGP_UPDATE_RCV,
			"%s [Error] Update packet error / LS LINK NLRI TLV (type %d tlv length %d exceeds packet size %u)",
			peer->host, type, tlvdatalen, (uint)(lim - pnt));
		return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
	}

	error = bgp_nlri_parse_ls_node_local_desc(peer, attr, tlvdata, tlvdatalen);
	if ( error != BGP_NLRI_PARSE_ERROR ) {
		return error;
	}
	parsedlen += psize;
	pnt += psize;

	/* Parse remote node descriptor TLV */
	type = ntohs(*(uint16_t *)pnt);
	tlvdatalen = ntohs(*(uint16_t *)(pnt + BGP_LS_TLV_LENGTH_OFFSET));
	psize = tlvdatalen +  BGP_LS_TLV_HEADER_LEN;
	tlvdata = pnt + BGP_LS_TLV_HEADER_LEN;

	if ( type != LS_LOCAL_NODE_DESC) {
		flog_err(
			EC_BGP_UPDATE_RCV,
			"%s [Error] Update packet error / LS NODE NLRI TLV expected remote node descriptor TLV. Got type %d",
			peer->host, type);
		return BGP_NLRI_PARSE_ERROR;
	}

	if ( (tlvdata + tlvdatalen) > lim ) {
		flog_err(
			EC_BGP_UPDATE_RCV,
			"%s [Error] Update packet error / LS NODE NLRI TLV (type %d tlv length %d exceeds packet size %u)",
			peer->host, type, tlvdatalen, (uint)(lim - pnt));
		return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
	}

	error = bgp_nlri_parse_ls_node_remote_desc(peer, attr, tlvdata, tlvdatalen);
	if ( error != BGP_NLRI_PARSE_ERROR ) {
		return error;
	}
	parsedlen += psize;
	pnt += psize;

	return bgp_nlri_parse_ls_link_desc(peer, attr, pnt, length-parsedlen);
}

int bgp_nlri_parse_ls_prefix(struct peer *peer, struct attr *attr,
			 uint8_t *data, uint16_t length, uint8_t afi)
{
	uint8_t protocolid;
	uint64_t id;
	uint8_t *tlvdata;
	uint16_t tlvdatalen;
	uint8_t *pnt;
	uint8_t *lim;
	uint16_t psize = 0;
	uint16_t type;
	int8_t error;
	uint16_t desclen;

	protocolid = *data;
	id = *((uint64_t *)(data + BGP_LS_NLRI_ID_OFFSET));
	attr->ls_nlri.protocol_id = protocolid;
	attr->ls_nlri.identifier = id;
	pnt = data + BGP_LS_NLRI_DATA_MIN_BYTES;
	lim = data + length;

	/* Parse local node descriptor TLV */
	type = ntohs(*(uint16_t *)pnt);
	tlvdatalen = ntohs(*(uint16_t *)(pnt + BGP_LS_TLV_LENGTH_OFFSET));
	tlvdata = pnt + BGP_LS_TLV_HEADER_LEN;
	psize = tlvdatalen + BGP_LS_TLV_HEADER_LEN;

	if ( (tlvdata + tlvdatalen) > lim ) {
		flog_err(
			EC_BGP_UPDATE_RCV,
			"%s [Error] Update packet error / LS PREFIX4 NLRI TLV (type %d tlv length %d exceeds packet size %u)",
			peer->host, type, tlvdatalen, (uint)(lim - pnt));
		return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
	}

	if ( type != LS_LOCAL_NODE_DESC) {
		flog_err(
			EC_BGP_UPDATE_RCV,
			"%s [Error] Update packet error / LS PREFIX4 NLRI TLV expected local node descriptor TLV. Got type %d",
			peer->host, type);
		return BGP_NLRI_PARSE_ERROR;
	}

	error = bgp_nlri_parse_ls_node_local_desc(peer, attr, tlvdata, tlvdatalen);
	if ( error != BGP_NLRI_PARSE_ERROR ) {
		return error;
	}

	pnt += psize;
	desclen = length - BGP_LS_NLRI_DATA_MIN_BYTES - psize;
	return bgp_nlri_parse_ls_prefix_desc(peer, attr, pnt, desclen, afi);

}

int bgp_nlri_parse_ls(struct peer *peer, struct attr *attr,
			 struct bgp_nlri *packet, int mp_withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	uint16_t type;
	uint16_t length;
	uint8_t *nlridata;
	int psize = 0;

	pnt = packet->nlri;
	lim = pnt + packet->length;

	for (; pnt < lim; pnt += psize) {
		/* All BGP LS NLRI types start with type and length */
		if (pnt + 4 > lim )
			return BGP_NLRI_PARSE_ERROR_BGPLS_MISSING_TYPE;

		type = ntohs(*(uint16_t *)pnt);
		attr->ls_nlri.type = type;
		length = ntohs(*(uint16_t *)(pnt + BGP_LS_NLRI_LENGTH_OFFSET));
		psize = length;
		nlridata = pnt + BGP_LS_NLRI_HEADER_LEN;

		if ( (nlridata + length) > lim ) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / LS NLRI (nlri length %d exceeds packet size %u)",
				peer->host, length, (uint)(lim - pnt));
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		switch(type) {
			case LINK_STATE_NODE_NLRI:
			   	return bgp_nlri_parse_ls_node(peer, attr, nlridata, length);
			case LINK_STATE_LINK_NLRI:
			   	return bgp_nlri_parse_ls_link(peer, attr, nlridata, length);
			case LINK_STATE_PREFIX4_NLRI:
			   	return bgp_nlri_parse_ls_prefix(peer, attr, nlridata, length, AFI_IP);
			case LINK_STATE_PREFIX6_NLRI:
			   	return bgp_nlri_parse_ls_prefix(peer, attr, nlridata, length, AFI_IP6);
			default:
				return BGP_NLRI_PARSE_ERROR;
		}
	}

	return BGP_NLRI_PARSE_ERROR;

}

