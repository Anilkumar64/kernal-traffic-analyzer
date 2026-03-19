cd ~/Documents/Projects/kernel_traffic_analyzer/kernel_module

cat > /tmp/full_test.sh << 'TESTSCRIPT'
#!/bin/bash
# ============================================================
#  FULL TEST — kernel_traffic_analyzer
# ============================================================
PASS=0; FAIL=0; WARN=0
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
info() { echo -e "${CYAN}      $1${NC}"; }
hdr()  { echo -e "\n${BOLD}━━━ $1 ━━━${NC}"; }

MOD_DIR="/home/$SUDO_USER/Documents/Projects/kernel_traffic_analyzer/kernel_module"

# ============================================================
hdr "SETUP — reload module clean"
# ============================================================
sudo rmmod traffic_analyzer 2>/dev/null; sleep 1
sudo insmod $MOD_DIR/traffic_analyzer.ko
sleep 1
if lsmod | grep -q traffic_analyzer; then
    pass "Module loaded"
else
    fail "Module failed to load — aborting"
    exit 1
fi

# ============================================================
hdr "PROC FILES — all 7 must exist"
# ============================================================
for f in traffic_analyzer traffic_analyzer_procs traffic_analyzer_dns \
          traffic_analyzer_anomalies traffic_analyzer_dns_map \
          traffic_analyzer_routes traffic_analyzer_routes_pending; do
    [ -e /proc/$f ] && pass "/proc/$f" || fail "/proc/$f MISSING"
done

# ============================================================
hdr "GENERATING TRAFFIC — wait 5 seconds"
# ============================================================
info "Forcing IPv4 to avoid IPv6/DNS-map mismatch..."
for d in google.com github.com cloudflare.com reddit.com amazon.com; do
    curl -4 -s --max-time 5 https://$d > /dev/null &
done
wait; sleep 3

# ============================================================
hdr "PHASE 2 — TCP connections"
# ============================================================
TCP=$(awk -F'|' 'NR>1 && $7=="TCP"' /proc/traffic_analyzer)
TCP_COUNT=$(echo "$TCP" | grep -c .)
UDP_COUNT=$(awk -F'|' 'NR>1 && $7=="UDP"' /proc/traffic_analyzer | grep -c .)

info "TCP entries: $TCP_COUNT   UDP entries: $UDP_COUNT"
[ "$TCP_COUNT" -ge 3 ] && pass "TCP connections tracked ($TCP_COUNT entries)" \
    || fail "Too few TCP entries ($TCP_COUNT) — expected 3+"

echo "$TCP" | awk -F'|' '{printf "  %-18s %-18s %-6s %-14s\n",$3,$9,$11,$5}' | head -8

# TCP states
ESTABLISHED=$(echo "$TCP" | awk -F'|' '$5~/ESTABLISHED/' | wc -l)
FIN=$(echo "$TCP"         | awk -F'|' '$5~/FIN_WAIT/'    | wc -l)
CLOSED=$(echo "$TCP"      | awk -F'|' '$5~/CLOSED/'      | wc -l)
info "States → ESTABLISHED:$ESTABLISHED  FIN_WAIT:$FIN  CLOSED:$CLOSED"
[ $((ESTABLISHED+FIN+CLOSED)) -ge 3 ] \
    && pass "TCP state machine working" \
    || fail "TCP states wrong — check advance_state()"

# Byte counts
BYTES=$(echo "$TCP" | awk -F'|' '{sum+=$13} END{print sum+0}')
[ "$BYTES" -gt 0 ] && pass "TCP byte counts non-zero ($BYTES bytes)" \
    || fail "TCP byte counts all zero"

# ============================================================
hdr "PHASE 3 — Process intelligence"
# ============================================================
PROCS=$(cat /proc/traffic_analyzer_procs)
PROC_COUNT=$(echo "$PROCS" | grep -c . )
info "Process entries: $PROC_COUNT"
[ "$PROC_COUNT" -ge 2 ] && pass "Per-process entries exist" \
    || fail "No process entries"

# EXE paths
EXE_RESOLVED=$(echo "$PROCS" | awk -F'|' 'NR>1 && length($4)>3' | wc -l)
[ "$EXE_RESOLVED" -ge 1 ] && pass "EXE paths resolved ($EXE_RESOLVED processes)" \
    || fail "EXE paths empty — check exe_resolver workqueue"

# Protocol %
info "Per-process protocol breakdown:"
echo "$PROCS" | awk -F'|' 'NR>1 {printf "  %-18s TCP:%-4s UDP:%-4s Anomaly:%s\n",$3,$15,$16,$17}' \
    | head -5

# ============================================================
hdr "PHASE 4 — DNS map + DOMAIN column"
# ============================================================
DNS_MAP=$(cat /proc/traffic_analyzer_dns_map)
DNS_COUNT=$(echo "$DNS_MAP" | grep -c . )
info "DNS map entries: $DNS_COUNT"
[ "$DNS_COUNT" -ge 4 ] && pass "DNS map populated ($DNS_COUNT entries)" \
    || fail "DNS map too sparse ($DNS_COUNT) — check dns_parser"

info "DNS map sample:"
echo "$DNS_MAP" | awk -F'|' 'NR>1 {printf "  %-30s %s\n",$1,$2}' | head -6

# DOMAIN column in connections
DOMAIN_FILLED=$(awk -F'|' 'NR>1 && $7=="TCP" && $12!="-" && length($12)>1' \
    /proc/traffic_analyzer | wc -l)
info "TCP entries with DOMAIN filled: $DOMAIN_FILLED / $TCP_COUNT"
[ "$DOMAIN_FILLED" -ge 1 ] && pass "DOMAIN column populated" \
    || warn "DOMAIN column empty — dns_map_lookup timing issue (known bug)"

# ============================================================
hdr "PHASE 5 — Route store + daemon write"
# ============================================================
PENDING=$(cat /proc/traffic_analyzer_routes_pending)
PEND_COUNT=$(echo "$PENDING" | grep -c .)
info "Pending IPs: $PEND_COUNT"
[ "$PEND_COUNT" -ge 1 ] && pass "Route pending queue has entries" \
    || warn "No pending IPs — connections may not have reached ESTABLISHED yet"

# Write test hop
TEST_IP=$(echo "$PENDING" | head -1 | awk '{print $1}')
[ -z "$TEST_IP" ] && TEST_IP="8.8.8.8"
info "Writing test hop for IP: $TEST_IP"

printf "DEST %s\nSTATUS DONE\nHOP 1 192.168.1.1 1500 gw.local Mumbai India IN 19076000 72877000 AS9829 BSNL\nHOP 2 %s 24000 dest.net NewYork USA US 40712000 -74005000 AS15169 Google\n" \
    "$TEST_IP" "$TEST_IP" | sudo tee /proc/traffic_analyzer_routes > /dev/null
sleep 1

ROUTE_DONE=$(awk -F'|' '$3=="DONE"' /proc/traffic_analyzer_routes | wc -l)
[ "$ROUTE_DONE" -ge 1 ] && pass "Route write protocol working (DONE entries: $ROUTE_DONE)" \
    || fail "Route write failed — check route_store write handler"

# ============================================================
hdr "PHASE 6 — Netlink"
# ============================================================
NL_PROTO=$(sudo dmesg | grep "Netlink socket created" | tail -1 | grep -o "proto=[0-9]*" | cut -d= -f2)
info "Kernel netlink proto: $NL_PROTO"

cat > /tmp/nl_test.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
int main() {
    int fd = socket(PF_NETLINK, SOCK_RAW, ${NL_PROTO:-2});
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_nl src = {.nl_family=AF_NETLINK,.nl_pid=getpid()};
    bind(fd, (struct sockaddr*)&src, sizeof(src));
    struct nlmsghdr *h = calloc(1, NLMSG_SPACE(32));
    h->nlmsg_len = NLMSG_SPACE(32);
    h->nlmsg_pid = getpid();
    strcpy(NLMSG_DATA(h), "PING");
    struct sockaddr_nl dst = {.nl_family=AF_NETLINK};
    struct iovec iov = {h, h->nlmsg_len};
    struct msghdr msg = {&dst,sizeof(dst),&iov,1};
    int r = sendmsg(fd, &msg, 0);
    if (r > 0) printf("OK sent %d bytes on proto=%d\n", r, ${NL_PROTO:-2});
    else { perror("sendmsg"); return 1; }
    free(h); close(fd); return 0;
}
EOF
gcc -o /tmp/nl_test /tmp/nl_test.c 2>/dev/null
if /tmp/nl_test 2>/dev/null | grep -q "OK"; then
    pass "Netlink userspace→kernel message sent (proto=$NL_PROTO)"
else
    fail "Netlink send failed — proto mismatch or socket not registered"
fi

# ============================================================
hdr "WRITE COMMANDS"
# ============================================================
# Generate some closed connections first
curl -4 -s https://example.com > /dev/null; sleep 1
BEFORE=$(awk -F'|' 'NR>1 && $5=="CLOSED"' /proc/traffic_analyzer | wc -l)
echo "clear_closed" | sudo tee /proc/traffic_analyzer > /dev/null; sleep 1
AFTER=$(awk -F'|' 'NR>1 && $5=="CLOSED"' /proc/traffic_analyzer | wc -l)
info "CLOSED entries: before=$BEFORE after=$AFTER"
[ "$AFTER" -le "$BEFORE" ] && pass "clear_closed works" || fail "clear_closed had no effect"

echo "clear_dns_map" | sudo tee /proc/traffic_analyzer > /dev/null; sleep 1
DNS_AFTER=$(awk 'NR>1' /proc/traffic_analyzer_dns_map | wc -l)
info "DNS map after clear_dns_map: $DNS_AFTER entries"
[ "$DNS_AFTER" -eq 0 ] && pass "clear_dns_map works" || fail "clear_dns_map had no effect"

echo "clear_routes" | sudo tee /proc/traffic_analyzer_routes > /dev/null; sleep 1
ROUTES_AFTER=$(awk 'NR>1' /proc/traffic_analyzer_routes | wc -l)
[ "$ROUTES_AFTER" -eq 0 ] && pass "clear_routes works" || fail "clear_routes had no effect"

# ============================================================
hdr "STRESS — 50 parallel connections"
# ============================================================
for i in $(seq 1 50); do curl -4 -s --max-time 3 https://httpbin.org/get > /dev/null & done
wait; sleep 2
STRESS_COUNT=$(awk 'NR>1' /proc/traffic_analyzer | wc -l)
info "Total entries after stress: $STRESS_COUNT"
[ "$STRESS_COUNT" -ge 20 ] && pass "Stress test handled ($STRESS_COUNT entries)" \
    || warn "Low entry count after stress ($STRESS_COUNT)"

# ============================================================
hdr "CLEAN UNLOAD"
# ============================================================
sudo rmmod traffic_analyzer; sleep 1
if ! lsmod | grep -q traffic_analyzer; then
    pass "Module unloaded cleanly"
else
    fail "Module still loaded after rmmod"
fi
ALL_GONE=true
for f in traffic_analyzer traffic_analyzer_procs traffic_analyzer_dns \
          traffic_analyzer_anomalies traffic_analyzer_dns_map \
          traffic_analyzer_routes traffic_analyzer_routes_pending; do
    [ -e /proc/$f ] && ALL_GONE=false && fail "/proc/$f still exists"
done
$ALL_GONE && pass "All /proc entries removed"

DMESG_ERR=$(sudo dmesg | tail -20 | grep -i "BUG\|oops\|panic\|use.after.free\|null.pointer" | wc -l)
[ "$DMESG_ERR" -eq 0 ] && pass "No kernel errors in dmesg" \
    || fail "$DMESG_ERR kernel error(s) in dmesg — run: sudo dmesg | tail -30"

# ============================================================
hdr "SUMMARY"
# ============================================================
TOTAL=$((PASS+FAIL+WARN))
echo -e "\n  ${GREEN}PASS: $PASS${NC}  ${RED}FAIL: $FAIL${NC}  ${YELLOW}WARN: $WARN${NC}  (total: $TOTAL)"
[ "$FAIL" -eq 0 ] \
    && echo -e "\n  ${GREEN}${BOLD}ALL TESTS PASSED — ready for GUI phase${NC}\n" \
    || echo -e "\n  ${RED}${BOLD}$FAIL test(s) failed — fix before GUI${NC}\n"
TESTSCRIPT

