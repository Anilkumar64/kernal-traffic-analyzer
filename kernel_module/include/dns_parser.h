#ifndef _DNS_PARSER_H
#define _DNS_PARSER_H

#include <linux/types.h>
#include <linux/skbuff.h>

/*
 * parse_dns_response — called from netfilter hook on every UDP packet
 * destined from port 53 (DNS reply direction).
 *
 * Parses the DNS wire format, extracts every A record from the answer
 * section, and inserts each IP→domain mapping into dns_map.
 *
 * @skb:      the packet buffer (must be a UDP packet from port 53)
 * @pid:      PID of the process that sent the original query
 * @comm:     comm string of that process
 *
 * Returns true if at least one A record was extracted.
 */
bool parse_dns_response(struct sk_buff *skb, pid_t pid, const char *comm);

#endif /* _DNS_PARSER_H */