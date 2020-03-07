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
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_ls.h"

int bgp_nlri_parse_ls_node_local_desc(struct peer *peer, struct ls_nlri *nlri,
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
				nlri->local.bgp_router_id = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				nlri->local.flag |= ATTR_FLAG_BIT(LS_NODE_BGP_RID_BIT);
				zlog_debug("NODE LOCAL DESC: BGP ROUTER ID: %u",  nlri->local.bgp_router_id);
				break;
			case LS_NODE_BGP_LS_ID:
				nlri->local.ls_id = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				nlri->local.flag |= ATTR_FLAG_BIT(LS_NODE_BGP_LS_ID_BIT);
				zlog_debug("NODE LOCAL DESC: BGP LS ID: %u",  nlri->local.ls_id);
				break;
			case LS_NODE_IGP_ROUTER_ID:
				memcpy(&nlri->local.igp_router_id.val, pnt + BGP_LS_TLV_HEADER_LEN, len);
				nlri->local.igp_router_id.len = len;
				nlri->local.flag |= ATTR_FLAG_BIT(LS_NODE_IGP_RID_BIT);
				zlog_debug("NODE LOCAL DESC: IGP ROUTER ID");
				break;
			case LS_NODE_AS:
				nlri->local.as = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				nlri->local.flag |= ATTR_FLAG_BIT(LS_NODE_AS_BIT);
				zlog_debug("NODE LOCAL DESC: LOCAL AS: %u",  nlri->local.as);
				break;
			default:
				return BGP_NLRI_PARSE_ERROR;
		}
	}

	return 0;
}

int bgp_nlri_parse_ls_node_remote_desc(struct peer *peer, struct ls_nlri *nlri,
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
				nlri->remote.bgp_router_id = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				nlri->remote.flag |= ATTR_FLAG_BIT(LS_NODE_BGP_RID_BIT);
				zlog_debug("NODE REMOTE DESC: BGP ROUTER ID: %u",  nlri->remote.bgp_router_id);
				break;
         case LS_NODE_BGP_LS_ID:
            nlri->remote.ls_id = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
            nlri->remote.flag |= ATTR_FLAG_BIT(LS_NODE_BGP_LS_ID_BIT);
            zlog_debug("NODE LOCAL DESC: BGP LS ID: %u",  nlri->remote.ls_id);
            break;
         case LS_NODE_IGP_ROUTER_ID:
            memcpy(&nlri->remote.igp_router_id.val, pnt + BGP_LS_TLV_HEADER_LEN, len);
            nlri->remote.igp_router_id.len = len;
            nlri->remote.flag |= ATTR_FLAG_BIT(LS_NODE_IGP_RID_BIT);
            zlog_debug("NODE LOCAL DESC: IGP ROUTER ID");
            break;
			case LS_NODE_AS:
				nlri->remote.as = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				nlri->remote.flag |= ATTR_FLAG_BIT(LS_NODE_AS_BIT);
				zlog_debug("NODE REMOTE DESC: REMOTE AS: %u",  nlri->remote.as);
				break;
			default:
				return BGP_NLRI_PARSE_ERROR;
		}
	}
	return 0;
}

int bgp_nlri_parse_ls_link_desc(struct peer *peer, struct ls_nlri *nlri,
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
				nlri->link.link_local_ipv4.s_addr = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				nlri->link.flag |= ATTR_FLAG_BIT(LS_LINK_LOCAL_IPV4_BIT);
				zlog_debug("LINK DESC: LOCAL IPv4: %s",  inet_ntoa(nlri->link.link_local_ipv4));
				break;
			case LS_LINK_REMOTE_IPV4:
				nlri->link.link_remote_ipv4.s_addr = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				nlri->link.flag |= ATTR_FLAG_BIT(LS_LINK_REMOTE_IPV4_BIT);
				zlog_debug("LINK DESC: REMOTE IPv4: %s",  inet_ntoa(nlri->link.link_remote_ipv4));
				break;
			case LS_LINK_LOCAL_REMOTE_ID:
				nlri->link.link_localid = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				nlri->link.flag |= ATTR_FLAG_BIT(LS_LINK_LOCAL_ID_BIT);
				nlri->link.link_remoteid = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN + 4));
				nlri->link.flag |= ATTR_FLAG_BIT(LS_LINK_REMOTE_ID_BIT);
				break;
			case LS_LINK_LOCAL_IPV6:
				memcpy(&nlri->link.link_local_ipv6, pnt + BGP_LS_TLV_HEADER_LEN, IPV6_MAX_BYTELEN);
				nlri->link.flag |= ATTR_FLAG_BIT(LS_LINK_LOCAL_IPV6_BIT);
				break;
			case LS_LINK_REMOTE_IPV6:
				memcpy(&nlri->link.link_remote_ipv6, pnt + BGP_LS_TLV_HEADER_LEN, IPV6_MAX_BYTELEN);
				nlri->link.flag |= ATTR_FLAG_BIT(LS_LINK_REMOTE_IPV6_BIT);
				break;
			default:
				return BGP_NLRI_PARSE_ERROR;
		}
	}
	return 0;
}

int bgp_nlri_parse_ls_prefix_desc(struct peer *peer, struct ls_nlri *nlri,
			 uint8_t *data, uint16_t length, afi_t afi)
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
				nlri->prefix.p.prefixlen = *(pnt + BGP_LS_TLV_HEADER_LEN);
				if ( (afi == AFI_IP) && (nlri->prefix.p.prefixlen > 32) ) {
					flog_err(
						EC_BGP_UPDATE_RCV,
						"%s [Error] Update packet error / LS PREFIX4 NLRI TLV Prefix length more than 32",
						peer->host );
					return BGP_NLRI_PARSE_ERROR;
				}
				nlri->prefix.p.family = afi2family(afi);
				memcpy(nlri->prefix.p.val, pnt + BGP_LS_TLV_HEADER_LEN + 1, len - 1);
				nlri->prefix.flag |= ATTR_FLAG_BIT(LS_PREFIX_BIT);
				break;
			default:
				return BGP_NLRI_PARSE_ERROR;
		}
	}
	return 0;
}

int bgp_nlri_parse_ls_node(struct peer *peer, struct ls_nlri *nlri,
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
	nlri->ls_hdr.protocol_id = protocolid;
	nlri->ls_hdr.identifier = id;
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

	return bgp_nlri_parse_ls_node_local_desc(peer, nlri, tlvdata, tlvdatalen);
}

int bgp_process_ls_node_nlri(struct peer *peer, afi_t afi, safi_t safi, struct attr *attr,
                             uint8_t *data, uint16_t length)
{
   int error;
   struct prefix_bgp_ls p;
   struct ls_nlri nlri;

   memset(&nlri, 0, sizeof(struct ls_nlri));
   error = bgp_nlri_parse_ls_node(peer, &nlri, data, length);
   if( error != BGP_NLRI_PARSE_OK ) {
      return error;
   }

   memset(&p, 0, sizeof(struct prefix_bgp_ls));
   p.family = AF_BGP_LS;
   p.prefix.ls_type = LINK_STATE_NODE_NLRI;
   p.prefix.ls_node.ls_hdr = nlri.ls_hdr;
   p.prefix.ls_node.local = nlri.local;

   if(attr)
      error = bgp_update(peer, (struct prefix *)&p, 0, attr, afi, safi, 
                       ZEBRA_ROUTE_BGP, BGP_ROUTE_LS, NULL, NULL, 0, 0, NULL);
   else
      error = bgp_withdraw(peer, (struct prefix *)&p, 0, attr, afi, safi,
                         ZEBRA_ROUTE_BGP, BGP_ROUTE_LS, NULL, NULL, 0, NULL);

   return error;
}

int bgp_nlri_parse_ls_link(struct peer *peer, struct ls_nlri *nlri,
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
	nlri->ls_hdr.protocol_id = protocolid;
	nlri->ls_hdr.identifier = id;
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

	error = bgp_nlri_parse_ls_node_local_desc(peer, nlri, tlvdata, tlvdatalen);
	if ( error != BGP_NLRI_PARSE_OK ) {
		return error;
	}
	parsedlen += psize;
	pnt += psize;

	/* Parse remote node descriptor TLV */
	type = ntohs(*(uint16_t *)pnt);
	tlvdatalen = ntohs(*(uint16_t *)(pnt + BGP_LS_TLV_LENGTH_OFFSET));
	psize = tlvdatalen +  BGP_LS_TLV_HEADER_LEN;
	tlvdata = pnt + BGP_LS_TLV_HEADER_LEN;

	if ( type != LS_REMOTE_NODE_DESC) {
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

	error = bgp_nlri_parse_ls_node_remote_desc(peer, nlri, tlvdata, tlvdatalen);
	if ( error != BGP_NLRI_PARSE_OK ) {
		return error;
	}
	parsedlen += psize;
	pnt += psize;

	return bgp_nlri_parse_ls_link_desc(peer, nlri, pnt, length-parsedlen);
}

int bgp_process_ls_link_nlri(struct peer *peer, afi_t afi, safi_t safi, struct attr *attr,
                             uint8_t *data, uint16_t length)
{
   int error;
   struct prefix_bgp_ls p;
   struct ls_nlri nlri;

   memset(&nlri, 0, sizeof(struct ls_nlri));
   error = bgp_nlri_parse_ls_link(peer, &nlri, data, length);
   if( error != BGP_NLRI_PARSE_OK ) {
      return error;
   }

   memset(&p, 0, sizeof(struct prefix_bgp_ls));
   p.family = AF_BGP_LS;
   p.prefixlen = sizeof(struct bgp_ls_addr);
   p.prefix.ls_type = LINK_STATE_LINK_NLRI;
   p.prefix.ls_link.ls_hdr = nlri.ls_hdr;
   p.prefix.ls_link.local = nlri.local;
   p.prefix.ls_link.remote = nlri.remote;
   p.prefix.ls_link.link = nlri.link;

   if(attr)
      error = bgp_update(peer, (struct prefix *)&p, 0, attr, afi, safi, 
                       ZEBRA_ROUTE_BGP, BGP_ROUTE_LS, NULL, NULL, 0, 0, NULL);
   else
      error = bgp_withdraw(peer, (struct prefix *)&p, 0, attr, afi, safi,
                         ZEBRA_ROUTE_BGP, BGP_ROUTE_LS, NULL, NULL, 0, NULL);

   return error;
}

int bgp_nlri_parse_ls_prefix(struct peer *peer, struct ls_nlri *nlri,
			 uint8_t *data, uint16_t length, afi_t afi)
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
	nlri->ls_hdr.protocol_id = protocolid;
	nlri->ls_hdr.identifier = id;
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

	error = bgp_nlri_parse_ls_node_local_desc(peer, nlri, tlvdata, tlvdatalen);
	if ( error != BGP_NLRI_PARSE_OK ) {
		return error;
	}

	pnt += psize;
	desclen = length - BGP_LS_NLRI_DATA_MIN_BYTES - psize;
	return bgp_nlri_parse_ls_prefix_desc(peer, nlri, pnt, desclen, afi);

}

int bgp_process_ls_prefix_nlri(struct peer *peer, afi_t afi, safi_t safi, struct attr *attr,
                             uint8_t *data, uint16_t length, afi_t pafi, uint8_t type)
{
   int error;
   struct prefix_bgp_ls p;
   struct ls_nlri nlri;

   memset(&nlri, 0, sizeof(struct ls_nlri));
   error = bgp_nlri_parse_ls_prefix(peer, &nlri, data, length, pafi);
   if( error != BGP_NLRI_PARSE_OK ) {
      return error;
   }

   memset(&p, 0, sizeof(struct prefix_bgp_ls));
   p.family = AF_BGP_LS;
   p.prefixlen = sizeof(struct bgp_ls_addr);
   p.prefix.ls_type = type;
   p.prefix.ls_pfx.ls_hdr = nlri.ls_hdr;
   p.prefix.ls_pfx.local = nlri.local;
   p.prefix.ls_pfx.prefix = nlri.prefix;

   if(attr)
      error = bgp_update(peer, (struct prefix *)&p, 0, attr, afi, safi, 
                       ZEBRA_ROUTE_BGP, BGP_ROUTE_LS, NULL, NULL, 0, 0, NULL);
   else
      error = bgp_withdraw(peer, (struct prefix *)&p, 0, attr, afi, safi,
                         ZEBRA_ROUTE_BGP, BGP_ROUTE_LS, NULL, NULL, 0, NULL);

   return error;
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
   int error;
   afi_t afi;
   safi_t safi;
   uint8_t nlriCount = 0;

	pnt = packet->nlri;
	lim = pnt + packet->length;
   afi = packet->afi;
   safi = packet->safi;

	for (; pnt < lim; pnt += psize) {
		/* All BGP LS NLRI types start with type and length */
		if (pnt + 4 > lim )
			return BGP_NLRI_PARSE_ERROR_BGPLS_MISSING_TYPE;

		type = ntohs(*(uint16_t *)pnt);
		length = ntohs(*(uint16_t *)(pnt + BGP_LS_NLRI_LENGTH_OFFSET));
      
      if( length == 0 )
         return BGP_NLRI_PARSE_ERROR_BGPLS_MISSING_TYPE;
         
      nlriCount++;
		psize = length + BGP_LS_NLRI_HEADER_LEN;
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
            error = bgp_process_ls_node_nlri(peer, afi, safi, mp_withdraw ? NULL : attr,
                                             nlridata, length);
            if (error != BGP_NLRI_PARSE_OK)
               return error;
            break;
			case LINK_STATE_LINK_NLRI:
            error = bgp_process_ls_link_nlri(peer, afi, safi, mp_withdraw ? NULL : attr,
                                             nlridata, length);
            if (error != BGP_NLRI_PARSE_OK)
               return error;
            break;
			case LINK_STATE_PREFIX4_NLRI:
            error = bgp_process_ls_prefix_nlri(peer, afi, safi, mp_withdraw ? NULL : attr,
                                             nlridata, length, AFI_IP, type);
            if (error != BGP_NLRI_PARSE_OK)
               return error;
            break;
			case LINK_STATE_PREFIX6_NLRI:
            error = bgp_process_ls_prefix_nlri(peer, afi, safi, mp_withdraw ? NULL : attr,
                                             nlridata, length, AFI_IP6, type);
            if (error != BGP_NLRI_PARSE_OK)
               return error;
            break;
			default:
				error = BGP_NLRI_PARSE_ERROR;
            break;
		}
	}

	return BGP_NLRI_PARSE_OK;

}

