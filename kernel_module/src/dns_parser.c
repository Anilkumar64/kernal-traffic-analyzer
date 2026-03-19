#include <linux/kernel.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/types.h>
#include "../include/dns_parser.h"
#include "../include/dns_map.h"

/* ================================================================
 * DNS WIRE FORMAT (RFC 1035)
 *
 * Header (12 bytes):
 *   ID      2 bytes
 *   Flags   2 bytes  — bit 15 = QR (0=query, 1=response)
 *                     bits 11-8 = opcode
 *                     bit 7 = AA, bit 6 = TC, bit 5 = RD
 *                     bit 4 = RA, bit 0-3 = rcode
 *   QDCOUNT 2 bytes  — number of questions
 *   ANCOUNT 2 bytes  — number of answer RRs
 *   NSCOUNT 2 bytes  — number of authority RRs
 *   ARCOUNT 2 bytes  — number of additional RRs
 *
 * Questions (QDCOUNT times):
 *   QNAME   variable — label sequence
 *   QTYPE   2 bytes
 *   QCLASS  2 bytes
 *
 * Answers (ANCOUNT times):
 *   NAME    variable — label or pointer
 *   TYPE    2 bytes  — 1 = A, 28 = AAAA, 5 = CNAME etc
 *   CLASS   2 bytes
 *   TTL     4 bytes
 *   RDLENGTH 2 bytes
 *   RDATA   RDLENGTH bytes
 * ================================================================ */

#define DNS_QR_MASK 0x8000    /* Response bit in flags */
#define DNS_RCODE_MASK 0x000F /* Response code         */
#define DNS_TYPE_A 1          /* IPv4 address record   */
#define DNS_TYPE_CNAME 5      /* Canonical name        */
#define DNS_TYPE_AAAA 28      /* IPv6 (we skip these)  */
#define DNS_CLASS_IN 1        /* Internet class        */
#define DNS_LABEL_PTR 0xC0    /* Pointer flag (top 2 bits) */
#define DNS_MAX_NAME 256
#define DNS_MAX_JUMPS 10 /* limit pointer hops to prevent loops */

/* ================================================================
 * LABEL DECODER
 *
 * Decodes a DNS name from the wire at position *pos within the
 * payload buffer [data, data+len).  Handles pointer compression.
 *
 * Writes the decoded name (dot-separated) into out[0..outsz-1].
 * Returns the new position after the name in the original stream
 * (NOT after the pointer target — the caller must advance past
 * the 2-byte pointer, not past what it points to).
 *
 * Returns -1 on malformed input.
 * ================================================================ */
static int dns_decode_name(const u8 *data, int len,
                           int pos, char *out, int outsz)
{
    int out_pos = 0;
    int jumped = 0;
    int jumps = 0;
    int ret_pos = -1; /* position to return (after original label) */

    if (!data || !out || outsz < 1)
        return -1;

    out[0] = '\0';

    while (pos < len)
    {
        u8 label_len = data[pos];

        if (label_len == 0)
        {
            /* End of name */
            if (!jumped)
                ret_pos = pos + 1;
            if (out_pos > 0 && out[out_pos - 1] == '.')
                out[out_pos - 1] = '\0'; /* strip trailing dot */
            return ret_pos;
        }

        if ((label_len & DNS_LABEL_PTR) == DNS_LABEL_PTR)
        {
            /* Pointer compression */
            if (pos + 1 >= len)
                return -1;

            if (!jumped)
                ret_pos = pos + 2; /* caller advances 2 bytes for the ptr */

            pos = ((label_len & ~DNS_LABEL_PTR) << 8) | data[pos + 1];
            jumped = 1;
            jumps++;

            if (jumps > DNS_MAX_JUMPS)
                return -1; /* loop guard */

            continue;
        }

        /* Regular label */
        pos++;

        if (pos + label_len > len)
            return -1;

        if (out_pos + label_len + 1 >= outsz)
            return -1; /* output buffer too small */

        memcpy(out + out_pos, data + pos, label_len);
        out_pos += label_len;
        out[out_pos++] = '.';

        pos += label_len;
    }

    return -1;
}

/* ================================================================
 * SKIP A NAME — advance past a name without decoding it
 * ================================================================ */
static int dns_skip_name(const u8 *data, int len, int pos)
{
    int jumps = 0;

    while (pos < len)
    {
        u8 b = data[pos];

        if (b == 0)
            return pos + 1;

        if ((b & DNS_LABEL_PTR) == DNS_LABEL_PTR)
        {
            if (pos + 1 >= len)
                return -1;
            return pos + 2; /* pointer is always 2 bytes */
        }

        pos += 1 + b;
        if (++jumps > DNS_MAX_JUMPS)
            return -1;
    }

    return -1;
}

/* ================================================================
 * MAIN ENTRY POINT
 *
 * Called from netfilter_hook.c for every UDP packet arriving FROM
 * port 53 (DNS response direction).
 *
 * Parses the DNS wire format and inserts every A record it finds
 * into dns_map.
 * ================================================================ */
bool parse_dns_response(struct sk_buff *skb, pid_t pid, const char *comm)
{
    struct iphdr *ip;
    struct udphdr *udp;
    const u8 *payload;
    int payload_len;
    int pos;

    /* DNS header fields */
    u16 flags, qdcount, ancount;
    int i;
    bool got_record = false;

    /* ---- Basic pointer validation ---- */
    if (!skb)
        return false;

    if (!pskb_may_pull(skb, sizeof(struct iphdr) + sizeof(struct udphdr)))
        return false;

    ip = ip_hdr(skb);
    udp = (struct udphdr *)((__u8 *)ip + ip_hdrlen(skb));

    /* DNS payload starts right after the UDP header */
    payload = (__u8 *)udp + sizeof(struct udphdr);
    payload_len = ntohs(udp->len) - sizeof(struct udphdr);

    if (payload_len < 12) /* minimum DNS header size */
        return false;

    /* Ensure the payload is actually in linear memory */
    if (!pskb_may_pull(skb, ip_hdrlen(skb) +
                                sizeof(struct udphdr) +
                                payload_len))
        return false;

    /* Re-read after potential pull */
    ip = ip_hdr(skb);
    udp = (struct udphdr *)((__u8 *)ip + ip_hdrlen(skb));
    payload = (__u8 *)udp + sizeof(struct udphdr);

    /* ---- Parse DNS header ---- */
    flags = (payload[2] << 8) | payload[3];
    qdcount = (payload[4] << 8) | payload[5];
    ancount = (payload[6] << 8) | payload[7];

    /* Must be a response (QR=1) with no error (RCODE=0) */
    if (!(flags & DNS_QR_MASK))
        return false;

    if ((flags & DNS_RCODE_MASK) != 0)
        return false;

    if (ancount == 0)
        return false;

    pos = 12; /* skip DNS header */

    /* ---- Skip question section ---- */
    for (i = 0; i < qdcount; i++)
    {
        pos = dns_skip_name(payload, payload_len, pos);
        if (pos < 0)
            return false;

        pos += 4; /* QTYPE + QCLASS */
        if (pos > payload_len)
            return false;
    }

    /* ---- Parse answer section ---- */
    for (i = 0; i < ancount && i < 64; i++)
    {
        char name[DNS_MAX_NAME];
        u16 rr_type, rr_class, rdlength;
        u32 ttl;
        int new_pos;

        /* Decode RR name */
        new_pos = dns_decode_name(payload, payload_len, pos,
                                  name, sizeof(name));
        if (new_pos < 0)
            break;
        pos = new_pos;

        /* Need at least 10 more bytes: TYPE(2)+CLASS(2)+TTL(4)+RDLEN(2) */
        if (pos + 10 > payload_len)
            break;

        rr_type = (payload[pos] << 8) | payload[pos + 1];
        rr_class = (payload[pos + 2] << 8) | payload[pos + 3];
        ttl = (payload[pos + 4] << 24) |
              (payload[pos + 5] << 16) |
              (payload[pos + 6] << 8) |
              payload[pos + 7];
        rdlength = (payload[pos + 8] << 8) | payload[pos + 9];
        pos += 10;

        if (pos + rdlength > payload_len)
            break;

        /* We only care about IN class A records (IPv4) */
        if (rr_type == DNS_TYPE_A &&
            rr_class == DNS_CLASS_IN &&
            rdlength == 4)
        {
            __be32 ip_addr;
            memcpy(&ip_addr, payload + pos, 4);

            /*
             * Insert into dns_map.  TTL capped at DNS_MAP_TTL
             * to prevent stale entries from living too long.
             */
            dns_map_insert(ip_addr, name,
                           ttl > 0 ? ttl : 60,
                           pid, comm);

            got_record = true;
        }

        pos += rdlength;
    }

    return got_record;
}