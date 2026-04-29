/**
 * @file dns_parser.c
 * @brief DNS response parser for name attribution.
 * @details The parser walks DNS wire-format packets directly from sk_buffs,
 * validates each offset before reading, supports compressed and literal names,
 * and stores A records plus truncated AAAA records in the DNS map. Malformed
 * packets are ignored silently to keep packet hooks safe.
 * @author Kernel Traffic Analyzer Project
 * @license GPL-2.0
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include "../include/kta_api.h"

/**
 * dns_read_u8() - Read one byte from an skb.
 * @skb: Packet buffer.
 * @offset: Absolute packet offset.
 * @out: Destination byte.
 * @return: True on success, otherwise false.
 * @note: The helper never pulls or linearizes the skb.
 */
static bool dns_read_u8(const struct sk_buff *skb, unsigned int offset, u8 *out)
{
	return skb_copy_bits(skb, offset, out, sizeof(*out)) == 0;
}

/**
 * dns_read_u16() - Read a big-endian 16-bit value from an skb.
 * @skb: Packet buffer.
 * @offset: Absolute packet offset.
 * @out: Destination value in host byte order.
 * @return: True on success, otherwise false.
 * @note: DNS fields are network byte order on the wire.
 */
static bool dns_read_u16(const struct sk_buff *skb, unsigned int offset, u16 *out)
{
	__be16 tmp;

	if (skb_copy_bits(skb, offset, &tmp, sizeof(tmp)) != 0)
		return false;

	*out = ntohs(tmp);
	return true;
}

/**
 * dns_parse_name() - Decode a DNS name into a dotted string.
 * @skb: Packet buffer.
 * @base: DNS message start offset.
 * @offset: In/out absolute offset for the encoded name.
 * @out: Destination string.
 * @outlen: Destination string length.
 * @return: True when decoding succeeded.
 * @note: The input offset advances past the original encoded name only.
 */
static bool dns_parse_name(const struct sk_buff *skb, unsigned int base,
			   unsigned int *offset, char *out, size_t outlen)
{
	unsigned int pos = *offset;
	unsigned int end = *offset;
	unsigned int outpos = 0;
	unsigned int depth = 0;
	bool jumped = false;

	if (!out || !outlen)
		return false;
	out[0] = '\0';

	while (pos < skb->len) {
		u8 len;

		if (!dns_read_u8(skb, pos, &len))
			return false;
		if ((len & DNS_POINTER_MASK) == DNS_POINTER_VALUE) {
			u8 next;
			u16 ptr;

			if (!dns_read_u8(skb, pos + 1, &next))
				return false;
			ptr = (((u16)(len & ~DNS_POINTER_MASK)) << 8) | next;
			if (base + ptr >= skb->len || ++depth > DNS_MAX_POINTER_DEPTH)
				return false;
			if (!jumped)
				end = pos + DNS_COMPRESSED_NAME_LEN;
			pos = base + ptr;
			jumped = true;
			continue;
		}
		if (len == 0) {
			if (!jumped)
				end = pos + 1;
			break;
		}
		if ((len & DNS_POINTER_MASK) != 0 || len > DNS_LABEL_LEN_MASK)
			return false;
		pos++;
		if (pos + len > skb->len)
			return false;
		if (outpos && outpos + DNS_LABEL_DOT_LEN < outlen)
			out[outpos++] = '.';
		if (outpos + len >= outlen)
			len = outlen - outpos - 1;
		if (len && skb_copy_bits(skb, pos, out + outpos, len) != 0)
			return false;
		outpos += len;
		out[outpos] = '\0';
		pos += len;
	}

	*offset = end;
	return out[0] != '\0';
}

/**
 * dns_parse_response() - Parse a DNS response and update the DNS map.
 * @skb: Packet buffer containing a UDP DNS payload.
 * @data_offset: Absolute offset of the DNS message.
 * @return: None.
 * @note: A/AAAA answer names are preferred; the first question name is used as
 * a fallback when answers use compact owner names.
 */
void dns_parse_response(const struct sk_buff *skb, unsigned int data_offset)
{
	u16 flags;
	u16 qdcount;
	u16 ancount;
	unsigned int offset;
	unsigned int idx;
	char question[MAX_DOMAIN_LEN];

	if (!skb || data_offset + DNS_HEADER_LEN > skb->len)
		return;

	if (!dns_read_u16(skb, data_offset + 2, &flags) ||
	    !(flags & DNS_QR_RESPONSE))
		return;
	if (!dns_read_u16(skb, data_offset + 4, &qdcount) ||
	    !dns_read_u16(skb, data_offset + 6, &ancount) || !ancount)
		return;

	offset = data_offset + DNS_HEADER_LEN;
	question[0] = '\0';
	for (idx = 0; idx < qdcount; idx++) {
		char qname[MAX_DOMAIN_LEN];

		if (!dns_parse_name(skb, data_offset, &offset, qname,
				    sizeof(qname)))
			return;
		if (!question[0])
			strlcpy(question, qname, sizeof(question));
		if (offset + DNS_QFIXED_LEN > skb->len)
			return;
		offset += DNS_QFIXED_LEN;
	}

	for (idx = 0; idx < ancount; idx++) {
		char name[MAX_DOMAIN_LEN];
		char domain[MAX_DOMAIN_LEN];
		u16 type;
		u16 class;
		u16 rdlen;
		unsigned int rdata;

		if (!dns_parse_name(skb, data_offset, &offset, name,
				    sizeof(name)))
			return;
		if (offset + DNS_RR_FIXED_LEN > skb->len)
			return;
		if (!dns_read_u16(skb, offset, &type) ||
		    !dns_read_u16(skb, offset + 2, &class) ||
		    !dns_read_u16(skb, offset + 8, &rdlen))
			return;
		rdata = offset + DNS_RR_FIXED_LEN;
		if (rdata + rdlen > skb->len)
			return;

		if (name[0])
			strlcpy(domain, name, sizeof(domain));
		else
			strlcpy(domain, question, sizeof(domain));

		if (class == DNS_CLASS_IN && type == DNS_TYPE_A &&
		    rdlen == DNS_IPV4_RDATA_LEN) {
			__be32 ip;

			if (skb_copy_bits(skb, rdata, &ip, sizeof(ip)) == 0)
				dns_map_store(ip, domain);
		} else if (class == DNS_CLASS_IN && type == DNS_TYPE_AAAA &&
			   rdlen == DNS_IPV6_RDATA_LEN) {
			__be32 ip;

			if (skb_copy_bits(skb, rdata + DNS_IPV6_RDATA_LEN -
					  DNS_IPV4_RDATA_LEN, &ip,
					  sizeof(ip)) == 0) {
				pr_info("kta: dns_parser: truncated AAAA %s to %pI4\n",
					domain, &ip);
				dns_map_store(ip, domain);
			}
		}

		offset = rdata + rdlen;
	}
}
