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
				attr->ls_nlri.local.bgp_router_id = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.local.flag |= ATTR_FLAG_BIT(LS_NODE_BGP_RID_BIT);
				zlog_debug("NODE LOCAL DESC: BGP ROUTER ID: %u",  attr->ls_nlri.local.bgp_router_id);
				break;
			case LS_NODE_BGP_LS_ID:
				attr->ls_nlri.local.ls_id = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.local.flag |= ATTR_FLAG_BIT(LS_NODE_BGP_LS_ID_BIT);
				zlog_debug("NODE LOCAL DESC: BGP LS ID: %u",  attr->ls_nlri.local.ls_id);
				break;
			case LS_NODE_IGP_ROUTER_ID:
				memcpy(&attr->ls_nlri.local.igp_router_id.val, pnt + BGP_LS_TLV_HEADER_LEN, len);
				attr->ls_nlri.local.igp_router_id.len = len;
				attr->ls_nlri.local.flag |= ATTR_FLAG_BIT(LS_NODE_IGP_RID_BIT);
				zlog_debug("NODE LOCAL DESC: IGP ROUTER ID");
				break;
			case LS_NODE_AS:
				attr->ls_nlri.local.as = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.local.flag |= ATTR_FLAG_BIT(LS_NODE_AS_BIT);
				zlog_debug("NODE LOCAL DESC: LOCAL AS: %u",  attr->ls_nlri.local.as);
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
				attr->ls_nlri.remote.bgp_router_id = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.remote.flag |= ATTR_FLAG_BIT(LS_NODE_BGP_RID_BIT);
				zlog_debug("NODE REMOTE DESC: BGP ROUTER ID: %u",  attr->ls_nlri.remote.bgp_router_id);
				break;
         case LS_NODE_BGP_LS_ID:
            attr->ls_nlri.remote.ls_id = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
            attr->ls_nlri.remote.flag |= ATTR_FLAG_BIT(LS_NODE_BGP_LS_ID_BIT);
            zlog_debug("NODE LOCAL DESC: BGP LS ID: %u",  attr->ls_nlri.remote.ls_id);
            break;
         case LS_NODE_IGP_ROUTER_ID:
            memcpy(&attr->ls_nlri.remote.igp_router_id.val, pnt + BGP_LS_TLV_HEADER_LEN, len);
            attr->ls_nlri.remote.igp_router_id.len = len;
            attr->ls_nlri.remote.flag |= ATTR_FLAG_BIT(LS_NODE_IGP_RID_BIT);
            zlog_debug("NODE LOCAL DESC: IGP ROUTER ID");
            break;
			case LS_NODE_AS:
				attr->ls_nlri.remote.as = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.remote.flag |= ATTR_FLAG_BIT(LS_NODE_AS_BIT);
				zlog_debug("NODE REMOTE DESC: REMOTE AS: %u",  attr->ls_nlri.remote.as);
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
				attr->ls_nlri.link.link_local_ipv4.s_addr = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.link.flag |= ATTR_FLAG_BIT(LS_LINK_LOCAL_IPV4_BIT);
				zlog_debug("LINK DESC: LOCAL IPv4: %s",  inet_ntoa(attr->ls_nlri.link.link_local_ipv4));
				break;
			case LS_LINK_REMOTE_IPV4:
				attr->ls_nlri.link.link_remote_ipv4.s_addr = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.link.flag |= ATTR_FLAG_BIT(LS_LINK_REMOTE_IPV4_BIT);
				zlog_debug("LINK DESC: REMOTE IPv4: %s",  inet_ntoa(attr->ls_nlri.link.link_remote_ipv4));
				break;
			case LS_LINK_LOCAL_REMOTE_ID:
				attr->ls_nlri.link.link_localid = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN));
				attr->ls_nlri.link.flag |= ATTR_FLAG_BIT(LS_LINK_LOCAL_ID_BIT);
				attr->ls_nlri.link.link_remoteid = ntohl(*(uint32_t *)(pnt + BGP_LS_TLV_HEADER_LEN + 4));
				attr->ls_nlri.link.flag |= ATTR_FLAG_BIT(LS_LINK_REMOTE_ID_BIT);
				break;
			case LS_LINK_LOCAL_IPV6:
				memcpy(&attr->ls_nlri.link.link_local_ipv6, pnt + BGP_LS_TLV_HEADER_LEN, IPV6_MAX_BYTELEN);
				attr->ls_nlri.link.flag |= ATTR_FLAG_BIT(LS_LINK_LOCAL_IPV6_BIT);
				break;
			case LS_LINK_REMOTE_IPV6:
				memcpy(&attr->ls_nlri.link.link_remote_ipv6, pnt + BGP_LS_TLV_HEADER_LEN, IPV6_MAX_BYTELEN);
				attr->ls_nlri.link.flag |= ATTR_FLAG_BIT(LS_LINK_REMOTE_IPV6_BIT);
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
				attr->ls_nlri.prefix.p.prefixlen = *(pnt + BGP_LS_TLV_HEADER_LEN);
				if ( (afi == AFI_IP) && (attr->ls_nlri.prefix.p.prefixlen > 32) ) {
					flog_err(
						EC_BGP_UPDATE_RCV,
						"%s [Error] Update packet error / LS PREFIX4 NLRI TLV Prefix length more than 32",
						peer->host );
					return BGP_NLRI_PARSE_ERROR;
				}
				attr->ls_nlri.prefix.p.family = afi2family(afi);
				memcpy(attr->ls_nlri.prefix.p.u.val, pnt + BGP_LS_TLV_HEADER_LEN + 1, len - 1);
				attr->ls_nlri.prefix.flag |= ATTR_FLAG_BIT(LS_PREFIX_BIT);
				zlog_debug("PREFIX DESC: IPv4: %s", prefix2str(&(attr->ls_nlri.prefix.p), buf, PREFIX_STRLEN));
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
	attr->ls_nlri.ls_hdr.protocol_id = protocolid;
	attr->ls_nlri.ls_hdr.identifier = id;
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
	attr->ls_nlri.ls_hdr.protocol_id = protocolid;
	attr->ls_nlri.ls_hdr.identifier = id;
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

	error = bgp_nlri_parse_ls_node_remote_desc(peer, attr, tlvdata, tlvdatalen);
	if ( error != BGP_NLRI_PARSE_OK ) {
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
	attr->ls_nlri.ls_hdr.protocol_id = protocolid;
	attr->ls_nlri.ls_hdr.identifier = id;
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
	if ( error != BGP_NLRI_PARSE_OK ) {
		return error;
	}

	pnt += psize;
	desclen = length - BGP_LS_NLRI_DATA_MIN_BYTES - psize;
	return bgp_nlri_parse_ls_prefix_desc(peer, attr, pnt, desclen, afi);

}

static void *bgp_ls_attr_intern( void *arg)
{
   ls_attr_type *lsattr = XCALLOC(MTYPE_BGP_LS_ATTR, sizeof(ls_attr_type));
   memcpy(lsattr, arg, sizeof(ls_attr_type));
   return lsattr;
}

static void *bgp_ls_node_intern(void *arg)
{
   ls_nlriattr_type *nlri = arg;
   ls_nlri_node *node = XCALLOC(MTYPE_BGP_LS_NODE, sizeof(ls_nlri_node));
   node->ls_hdr = nlri->ls_hdr;
   node->local = nlri->local;
   return node;
}

static void *bgp_ls_alloc(void *arg)
{
   return arg;
}

static void *bgp_ls_link_intern(void *arg)
{
   ls_nlriattr_type *nlri = arg;
   ls_nlri_link *link = XCALLOC(MTYPE_BGP_LS_LINK, sizeof(ls_nlri_link));
   link->ls_hdr = nlri->ls_hdr;
   link->local = nlri->local;
   link->remote = nlri->remote;
   link->link = nlri->link;
   return link;
}

static void *bgp_ls_prefix_intern(void *arg)
{
   ls_nlriattr_type *nlri = arg;
   ls_nlri_prefix *pfx = XCALLOC(MTYPE_BGP_LS_PREFIX, sizeof(ls_nlri_prefix));
   pfx->ls_hdr = nlri->ls_hdr;
   pfx->local = nlri->local;
   pfx->prefix = nlri->prefix;
   return pfx;
}

static void bgp_ls_update_node(struct bgp *bgp, struct attr *attr)
{
   ls_nlri_node nodeToAdd;
   nodeToAdd.ls_hdr = attr->ls_nlri.ls_hdr;
   nodeToAdd.local = attr->ls_nlri.local;

   ls_attr_type *lsattr = hash_get(bgp->lsattrhash, &attr->ls_attr, bgp_ls_attr_intern);
   ls_nlri_node *node = hash_get(bgp->lsnodenlrihash, &nodeToAdd, bgp_ls_node_intern);
   node->ls_attr = lsattr;

   if (!lsattr->nodenlrihash)
      lsattr->nodenlrihash = hash_create(lsnodenlrihash_key_make, lsnodenlrihash_cmp, "BGP LS Node NLRI hash");
   hash_get(lsattr->nodenlrihash, node, bgp_ls_alloc);
}

static void bgp_ls_update_link(struct bgp *bgp, struct attr *attr)
{
   ls_nlri_link linkToAdd;
   linkToAdd.ls_hdr = attr->ls_nlri.ls_hdr;
   linkToAdd.local = attr->ls_nlri.local;
   linkToAdd.remote = attr->ls_nlri.remote;
   linkToAdd.link = attr->ls_nlri.link;

   ls_attr_type *lsattr = hash_get(bgp->lsattrhash, &attr->ls_attr, bgp_ls_attr_intern);
   ls_nlri_link *link = hash_get(bgp->lslinknlrihash, &linkToAdd, bgp_ls_link_intern);
   link->ls_attr = lsattr;

   if (!lsattr->linknlrihash)
      lsattr->linknlrihash = hash_create(lslinknlrihash_key_make, lslinknlrihash_cmp, "BGP LS Link NLRI hash");
   hash_get(lsattr->linknlrihash, link, bgp_ls_alloc);
}

static void bgp_ls_update_prefix4(struct bgp *bgp, struct attr *attr)
{
   ls_nlri_prefix prefixToAdd;
   prefixToAdd.ls_hdr = attr->ls_nlri.ls_hdr;
   prefixToAdd.local = attr->ls_nlri.local;
   prefixToAdd.prefix = attr->ls_nlri.prefix;

   ls_attr_type *lsattr = hash_get(bgp->lsattrhash, &attr->ls_attr, bgp_ls_attr_intern);
   ls_nlri_prefix *pfx = hash_get(bgp->lsprefix4nlrihash, &prefixToAdd, bgp_ls_prefix_intern);
   pfx->ls_attr = lsattr;

   if (!lsattr->prefix4nlrihash)
      lsattr->prefix4nlrihash = hash_create(lsprefixnlrihash_key_make, lsprefixnlrihash_cmp, "BGP LS Prefix4 NLRI hash");
   hash_get(lsattr->prefix4nlrihash, pfx, bgp_ls_alloc);
}

static void bgp_ls_update_prefix6(struct bgp *bgp, struct attr *attr)
{
   ls_nlri_prefix prefixToAdd;
   prefixToAdd.ls_hdr = attr->ls_nlri.ls_hdr;
   prefixToAdd.local = attr->ls_nlri.local;
   prefixToAdd.prefix = attr->ls_nlri.prefix;

   ls_attr_type *lsattr = hash_get(bgp->lsattrhash, &attr->ls_attr, bgp_ls_attr_intern);
   ls_nlri_prefix *pfx = hash_get(bgp->lsprefix6nlrihash, &prefixToAdd, bgp_ls_prefix_intern);
   pfx->ls_attr = lsattr;

   if (!lsattr->prefix6nlrihash)
      lsattr->prefix6nlrihash = hash_create(lsprefixnlrihash_key_make, lsprefixnlrihash_cmp, "BGP LS Prefix4 NLRI hash");
   hash_get(lsattr->prefix6nlrihash, pfx, bgp_ls_alloc);
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
			   error = bgp_nlri_parse_ls_node(peer, attr, nlridata, length);
            if (error != BGP_NLRI_PARSE_OK)
               return error;

            if (!mp_withdraw)
               bgp_ls_update_node(peer->bgp, attr);

            break;
			case LINK_STATE_LINK_NLRI:
			   error = bgp_nlri_parse_ls_link(peer, attr, nlridata, length);
            if (error != BGP_NLRI_PARSE_OK)
               return error;

            if (!mp_withdraw)
               bgp_ls_update_link(peer->bgp, attr);
            break;
			case LINK_STATE_PREFIX4_NLRI:
			   error = bgp_nlri_parse_ls_prefix(peer, attr, nlridata, length, AFI_IP);
            if (error != BGP_NLRI_PARSE_OK)
               return error;

            if (!mp_withdraw)
               bgp_ls_update_prefix4(peer->bgp, attr);
            break;
			case LINK_STATE_PREFIX6_NLRI:
            error = bgp_nlri_parse_ls_prefix(peer, attr, nlridata, length, AFI_IP6);
            if (error != BGP_NLRI_PARSE_OK)
               return error;

            if (!mp_withdraw)
               bgp_ls_update_prefix6(peer->bgp, attr);
            break;
			default:
				error = BGP_NLRI_PARSE_ERROR;
            break;
		}
	}

	return BGP_NLRI_PARSE_OK;

}

