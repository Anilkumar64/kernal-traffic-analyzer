/**
 * @file kta_constants.h
 * @brief Shared numeric constants for the Kernel Traffic Analyzer module.
 * @details This header centralizes table sizes, TTLs, thresholds, protocol
 * parsing limits, cache policies, and /proc formatting limits so all source
 * files share a single set of tunables without embedding unexplained literals.
 * @author Kernel Traffic Analyzer Project
 * @license GPL-2.0
 */

#pragma once

/* Connection table */
#define MAX_TRAFFIC_ENTRIES 2048U /* Maximum tracked per-flow traffic entries. */
#define MAX_PROC_ENTRIES 512U /* Maximum aggregated per-process entries. */
#define MAX_DNS_ENTRIES 1024U /* Maximum DNS IP-to-domain cache entries. */
#define MAX_ROUTE_ENTRIES 256U /* Maximum completed traceroute hop entries. */
#define MAX_FLOW_CACHE_ENTRIES 4096U /* Maximum flow-to-PID cache entries. */
#define MAX_SOCK_CACHE_ENTRIES 2048U /* Maximum sock-pointer-to-PID cache entries. */
#define MAX_INODE_CACHE_ENTRIES 2048U /* Maximum socket-inode-to-PID cache entries. */
#define MAX_EXE_CACHE_ENTRIES 512U /* Maximum PID-to-executable-path cache entries. */

/* TTL per connection state (seconds) */
#define TTL_SYN_SENT 5U /* Lifetime for SYN_SENT flows without progress. */
#define TTL_SYN_RECEIVED 5U /* Lifetime for SYN_RECEIVED flows without progress. */
#define TTL_CLOSED 10U /* Lifetime for closed flows retained for display. */
#define TTL_FIN_WAIT 15U /* Lifetime for FIN_WAIT flows retained for display. */
#define TTL_UDP 30U /* Lifetime for UDP flows without additional packets. */
#define TTL_ESTABLISHED 120U /* Lifetime for established TCP flows without packets. */

/* Anomaly detection thresholds */
#define ANOMALY_CONN_BURST 20U /* New connections per second threshold. */
#define ANOMALY_PORT_SCAN 15U /* Unique destination port threshold. */
#define ANOMALY_HIGH_CONNS 200U /* Total connection count threshold. */
#define ANOMALY_SYN_FLOOD_PCT 80U /* Pending SYN percentage threshold. */
#define ANOMALY_HIGH_BW_BYTES 10485760ULL /* Ten megabytes per second threshold. */

/* Anomaly flag bitmask values */
#define ANOMALY_FLAG_CONN_BURST 0x01U /* Process opened too many new flows. */
#define ANOMALY_FLAG_PORT_SCAN 0x02U /* Process touched too many destination ports. */
#define ANOMALY_FLAG_HIGH_CONNS 0x04U /* Process owns too many active flows. */
#define ANOMALY_FLAG_SYN_FLOOD 0x08U /* Process has excessive pending SYNs. */
#define ANOMALY_FLAG_HIGH_BW 0x10U /* Process exceeds bandwidth threshold. */

/* Rate window */
#define RATE_WINDOW_SECS 1U /* Seconds per rate calculation window. */
#define CLEANUP_INTERVAL_SECS 1U /* Seconds between recurring cleanup timer runs. */

/* String limits */
#define MAX_PROC_NAME_LEN 64U /* Maximum process name stored in snapshots. */
#define MAX_DOMAIN_LEN 256U /* Maximum DNS domain name stored in snapshots. */
#define MAX_EXE_PATH_LEN 512U /* Maximum executable path stored in snapshots. */

/* Hash sizing */
#define DNS_HASH_BITS 10U /* Hash bits for the DNS cache table. */
#define SOCK_CACHE_HASH_BITS 11U /* Hash bits for the socket cache table. */
#define INODE_CACHE_HASH_BITS 11U /* Hash bits for the inode cache table. */
#define FLOW_CACHE_HASH_BITS 12U /* Hash bits for the flow cache table. */
#define EXE_CACHE_HASH_BITS 9U /* Hash bits for the executable cache table. */
#define KTA_JHASH_INITVAL 0U /* Seed value for stable flow-key hashing. */

/* Cache policy */
#define FLOW_RESCAN_INTERVAL_SECS 10U /* Seconds before a flow may be rescanned. */
#define EXE_CACHE_TTL_SECS 30U /* Seconds before executable cache entries expire. */
#define RESOLVER_MAX_INFLIGHT 8U /* Maximum queued resolver work items. */

/* DNS protocol constants */
#define DNS_PORT 53U /* UDP source port used by DNS responses. */
#define DNS_HEADER_LEN 12U /* DNS wire header length in bytes. */
#define DNS_QR_RESPONSE 0x8000U /* DNS flags bit indicating a response. */
#define DNS_POINTER_MASK 0xC0U /* DNS compressed-name pointer mask. */
#define DNS_POINTER_VALUE 0xC0U /* DNS compressed-name pointer marker. */
#define DNS_POINTER_OFFSET_MASK 0x3FFFU /* DNS compressed-name pointer offset mask. */
#define DNS_LABEL_LEN_MASK 0x3FU /* Maximum encoded DNS label length bits. */
#define DNS_TYPE_A 1U /* DNS RR type for IPv4 addresses. */
#define DNS_TYPE_AAAA 28U /* DNS RR type for IPv6 addresses. */
#define DNS_CLASS_IN 1U /* DNS Internet class value. */
#define DNS_QFIXED_LEN 4U /* QTYPE plus QCLASS length in bytes. */
#define DNS_RR_FIXED_LEN 10U /* TYPE, CLASS, TTL, and RDLENGTH length in bytes. */
#define DNS_IPV4_RDATA_LEN 4U /* IPv4 RDATA size in bytes. */
#define DNS_IPV6_RDATA_LEN 16U /* IPv6 RDATA size in bytes. */
#define DNS_COMPRESSED_NAME_LEN 2U /* Encoded compressed DNS name length in bytes. */
#define DNS_MAX_POINTER_DEPTH 8U /* Maximum DNS compression pointer recursion depth. */
#define DNS_LABEL_DOT_LEN 1U /* Bytes reserved for a dot between DNS labels. */

/* IPv6 parsing constants */
#define IPV6_ADDR_LAST_WORD 3U /* Index of last 32-bit word in an IPv6 address. */
#define IPV6_BASE_HDR_LEN 40U /* IPv6 fixed header length in bytes. */
#define IPV6_EXT_MIN_LEN 8U /* Minimum IPv6 extension header length in bytes. */
#define IPV6_AUTH_HDR_UNIT 4U /* Authentication header length unit in bytes. */
#define IPV6_AUTH_HDR_BIAS 2U /* Authentication header length bias in 32-bit words. */

/* Route/proc parsing constants */
#define ROUTE_RESULT_MAX_LEN 1024U /* Maximum accepted route result write length. */
#define ROUTE_RESULT_FIELDS 9U /* Pipe-delimited route result field count. */
#define ROUTE_COUNTRY_LEN 8U /* Country code field length. */
#define ROUTE_COORD_LEN 16U /* Latitude and longitude field length. */
#define ROUTE_ASN_LEN 32U /* Autonomous system field length. */
#define ROUTE_ORG_LEN 64U /* Organization field length. */
#define PROC_TIME_BUF_LEN 40U /* Timestamp buffer length for /proc output. */
#define PROC_FLAG_BUF_LEN 96U /* Anomaly flag-name buffer length for /proc output. */
#define PROC_SEVERITY_BUF_LEN 16U /* Anomaly severity string buffer length. */
#define PROC_PROTO_BUF_LEN 8U /* Protocol string buffer length. */
#define PROC_STATE_BUF_LEN 16U /* Connection state string buffer length. */

/* Resolver parsing constants */
#define RESOLVER_READ_CHUNK 4096U /* Bytes read per resolver file chunk. */
#define RESOLVER_MAX_FILE_BYTES 262144U /* Maximum bytes read from one /proc/net file. */
#define PROC_NET_TCP_FIELDS 12U /* Expected fields in /proc/net/tcp rows. */
#define PROC_NET_TCP6_HEX_LEN 32U /* Hex characters in a /proc/net/tcp6 IPv6 address. */

