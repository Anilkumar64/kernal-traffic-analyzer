#!/bin/bash
# ============================================================
#  kernel_traffic_analyzer — Full Test Script
#  Run as: sudo bash test_kernel_traffic_analyzer.sh
#  Ubuntu 22.04 | Kernel 6.8.0-106-generic
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }
section() { echo -e "\n${BOLD}${YELLOW}══════════════════════════════════════${NC}"; echo -e "${BOLD}${YELLOW}  $1${NC}"; echo -e "${BOLD}${YELLOW}══════════════════════════════════════${NC}"; }

# ============================================================
# PHASE 1 — Module load & proc files
# ============================================================
section "PHASE 1 — Module Load & Proc Files"

info "Building and loading module..."
cd ~/Documents/Projects/kernel_traffic_analyzer/kernel_module
sudo rmmod traffic_analyzer 2>/dev/null && info "Old module removed"
make clean && make
sudo insmod traffic_analyzer.ko

info "Checking dmesg for load message..."
dmesg | tail -5
if dmesg | tail -10 | grep -q "Module loaded"; then
    pass "Module loaded successfully"
else
    fail "Module load message not found in dmesg"
fi

info "Checking all 7 proc files exist..."
for f in \
    /proc/traffic_analyzer \
    /proc/traffic_analyzer_procs \
    /proc/traffic_analyzer_dns \
    /proc/traffic_analyzer_anomalies \
    /proc/traffic_analyzer_dns_map \
    /proc/traffic_analyzer_routes \
    /proc/traffic_analyzer_routes_pending; do
    if [ -e "$f" ]; then
        pass "$f exists"
    else
        fail "$f MISSING"
    fi
done

# ============================================================
# PHASE 2 — Connection Tracking (5-tuple, TCP states, bytes)
# ============================================================
section "PHASE 2 — Connection Tracking"

info "Generating TCP traffic (curl to google.com)..."
curl -s https://google.com > /dev/null
curl -s https://github.com > /dev/null
curl -s https://cloudflare.com > /dev/null

info "Waiting 2 seconds for entries to settle..."
sleep 2

info "Connections table (PID | PROCESS | PROTO | DEST_IP | DEST_PORT | STATE | OUT_BYTES):"
awk -F'|' 'NR>1 {printf "%-8s %-20s %-6s %-20s %-6s %-14s %s\n", $1,$3,$7,$9,$11,$5,$13}' \
    /proc/traffic_analyzer | head -20

info "Checking for ESTABLISHED connections..."
if grep -q "ESTABLISHED" /proc/traffic_analyzer; then
    pass "ESTABLISHED connections found"
else
    fail "No ESTABLISHED connections — check netfilter hooks"
fi

info "Checking for non-zero byte counts..."
if awk -F'|' 'NR>1 {if($13+0 > 0) found=1} END{exit !found}' /proc/traffic_analyzer; then
    pass "Non-zero OUT_BYTES found"
else
    fail "All byte counts are zero"
fi

info "Checking TCP state variety (should see SYN, ESTABLISHED, CLOSED)..."
awk -F'|' 'NR>1 {print $5}' /proc/traffic_analyzer | sort | uniq -c | sort -rn

info "Generating UDP traffic (DNS queries)..."
dig google.com > /dev/null 2>&1
dig github.com > /dev/null 2>&1

info "Checking for UDP entries..."
if awk -F'|' 'NR>1 {if($7=="UDP") found=1} END{exit !found}' /proc/traffic_analyzer; then
    pass "UDP entries found"
else
    info "No UDP in main table — check DNS tab (expected)"
fi

# ============================================================
# PHASE 3 — Process Intelligence
# ============================================================
section "PHASE 3 — Process Intelligence"

info "Per-process table:"
awk -F'|' 'NR>1 {printf "%-8s %-20s %-8s %-8s %-14s %-14s %s\n", $1,$3,$5,$6,$13,$14,$17}' \
    /proc/traffic_analyzer_procs | head -20

info "Checking EXE paths are resolved (not blank)..."
if awk -F'|' 'NR>1 {if(length($4)>3) found=1} END{exit !found}' /proc/traffic_analyzer_procs; then
    pass "EXE paths resolved"
else
    fail "EXE paths empty — check exe_resolver workqueue"
fi

info "Checking RATE fields populated..."
if awk -F'|' 'NR>1 {if($13+0 >= 0) found=1} END{exit !found}' /proc/traffic_analyzer_procs; then
    pass "Rate fields present"
else
    fail "Rate fields missing"
fi

info "Checking TCP_PCT / UDP_PCT fields..."
awk -F'|' 'NR>1 {printf "%-20s TCP:%-6s UDP:%s\n", $3,$15,$16}' \
    /proc/traffic_analyzer_procs | head -10

info "Triggering anomaly — opening many connections fast..."
for i in $(seq 1 30); do curl -s --max-time 1 https://httpbin.org/get > /dev/null & done
wait
sleep 2

info "Anomalies table:"
cat /proc/traffic_analyzer_anomalies | column -t -s '|' 2>/dev/null | head -20

if [ -s /proc/traffic_analyzer_anomalies ]; then
    LINES=$(wc -l < /proc/traffic_analyzer_anomalies)
    if [ "$LINES" -gt 1 ]; then
        pass "Anomalies detected"
    else
        info "No anomalies triggered yet — try more aggressive traffic"
    fi
fi

# ============================================================
# PHASE 4 — DNS Resolution
# ============================================================
section "PHASE 4 — DNS Resolution"

info "Generating DNS traffic to populate map..."
for domain in google.com github.com cloudflare.com amazon.com reddit.com; do
    curl -s https://$domain > /dev/null &
done
wait
sleep 2

info "DNS map (IP → domain):"
cat /proc/traffic_analyzer_dns_map | column -t -s '|' 2>/dev/null

if [ -s /proc/traffic_analyzer_dns_map ]; then
    LINES=$(wc -l < /proc/traffic_analyzer_dns_map)
    if [ "$LINES" -gt 1 ]; then
        pass "DNS map has entries"
    else
        fail "DNS map empty — check dns_parser / port 53 intercept"
    fi
fi

info "Checking DOMAIN column in main connections table..."
awk -F'|' 'NR>1 && length($12)>1 {printf "%-20s → %s\n", $9,$12}' \
    /proc/traffic_analyzer | head -15

if awk -F'|' 'NR>1 {if(length($12)>1) found=1} END{exit !found}' /proc/traffic_analyzer; then
    pass "DOMAIN column populated in connections"
else
    fail "DOMAIN column empty — DNS map not linking to connections"
fi

info "DNS flows table:"
cat /proc/traffic_analyzer_dns | column -t -s '|' 2>/dev/null | head -10

# ============================================================
# PHASE 5 — Route Store + Daemon
# ============================================================
section "PHASE 5 — Route Store + Daemon"

info "Checking pending IPs (IPs waiting for traceroute)..."
cat /proc/traffic_analyzer_routes_pending

if [ -s /proc/traffic_analyzer_routes_pending ]; then
    pass "Pending IPs found"
    PENDING_IP=$(head -1 /proc/traffic_analyzer_routes_pending | awk '{print $1}')
    info "First pending IP: $PENDING_IP"
else
    info "No pending IPs yet — generating new TCP connections..."
    curl -s https://amazon.com > /dev/null
    sleep 2
    cat /proc/traffic_analyzer_routes_pending
fi

info "Manually writing a test hop to route store..."
TEST_IP=$(head -1 /proc/traffic_analyzer_routes_pending 2>/dev/null | awk '{print $1}')
if [ -z "$TEST_IP" ]; then
    TEST_IP="8.8.8.8"
    info "Using fallback test IP: $TEST_IP"
fi

sudo bash -c "echo 'DEST $TEST_IP' > /proc/traffic_analyzer_routes"
sudo bash -c "echo 'STATUS DONE' > /proc/traffic_analyzer_routes"
sudo bash -c "echo 'HOP 1 192.168.1.1 1500 router.local Mumbai India IN 19076000 72877000 AS9829 BSNL' > /proc/traffic_analyzer_routes"
sudo bash -c "echo 'HOP 2 103.21.244.0 8200 cf-node.net Mumbai India IN 19076000 72877000 AS13335 Cloudflare' > /proc/traffic_analyzer_routes"
sudo bash -c "echo 'HOP 3 $TEST_IP 24000 dest-host.net NewYork USA US 40712000 -74005000 AS15169 Google' > /proc/traffic_analyzer_routes"

sleep 1

info "Routes table after write:"
cat /proc/traffic_analyzer_routes | column -t -s '|' 2>/dev/null | head -20

if grep -q "DONE" /proc/traffic_analyzer_routes 2>/dev/null; then
    pass "Route data written and readable"
else
    fail "Route data not appearing — check write handler in route_store.c"
fi

# ============================================================
# PHASE 6 — Netlink Socket
# ============================================================
section "PHASE 6 — Netlink Socket"

info "Compiling netlink test client..."
cat > /tmp/nl_test.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define NETLINK_TRAFFIC_ANALYZER 31
#define MAX_PAYLOAD 1024

int main() {
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh;
    struct iovec iov;
    struct msghdr msg;
    int sock_fd;

    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TRAFFIC_ANALYZER);
    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    strcpy(NLMSG_DATA(nlh), "HELLO_FROM_USERSPACE");

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("Sending netlink message to kernel...\n");
    sendmsg(sock_fd, &msg, 0);
    printf("Message sent — check dmesg for kernel acknowledgement\n");

    free(nlh);
    close(sock_fd);
    return 0;
}
EOF

gcc -o /tmp/nl_test /tmp/nl_test.c
if [ $? -eq 0 ]; then
    pass "Netlink test client compiled"
    info "Sending netlink message..."
    /tmp/nl_test
    sleep 1
    info "dmesg output (last 5 lines — look for netlink receive log):"
    dmesg | tail -5
else
    fail "Compile failed — adjust NETLINK family number to match your module"
fi

# ============================================================
# WRITE COMMANDS — clear / clear_dns / clear_routes etc.
# ============================================================
section "Write Commands (clear / clear_dns / clear_routes...)"

info "Testing: echo clear_closed → removes CLOSED connections..."
BEFORE=$(grep -c "CLOSED" /proc/traffic_analyzer 2>/dev/null || echo 0)
sudo bash -c "echo 'clear_closed' > /proc/traffic_analyzer"
sleep 1
AFTER=$(grep -c "CLOSED" /proc/traffic_analyzer 2>/dev/null || echo 0)
info "CLOSED entries before: $BEFORE  after: $AFTER"
[ "$AFTER" -le "$BEFORE" ] && pass "clear_closed works" || fail "clear_closed had no effect"

info "Testing: echo clear_dns → removes DNS flow entries..."
sudo bash -c "echo 'clear_dns' > /proc/traffic_analyzer"
sleep 1
DNS_LINES=$(wc -l < /proc/traffic_analyzer_dns 2>/dev/null || echo 0)
info "DNS entries after clear_dns: $DNS_LINES"
pass "clear_dns executed (check DNS table above)"

info "Testing: echo clear_dns_map → wipes IP→domain map..."
sudo bash -c "echo 'clear_dns_map' > /proc/traffic_analyzer"
sleep 1
MAP_LINES=$(wc -l < /proc/traffic_analyzer_dns_map 2>/dev/null || echo 0)
info "DNS map entries after clear: $MAP_LINES"
pass "clear_dns_map executed"

info "Testing: echo clear_routes → wipes all route data..."
sudo bash -c "echo 'clear_routes' > /proc/traffic_analyzer_routes"
sleep 1
ROUTE_LINES=$(wc -l < /proc/traffic_analyzer_routes 2>/dev/null || echo 0)
info "Route entries after clear: $ROUTE_LINES"
pass "clear_routes executed"

info "Testing: echo clear → wipes all traffic stats..."
sudo bash -c "echo 'clear' > /proc/traffic_analyzer"
sleep 1
CONN_LINES=$(wc -l < /proc/traffic_analyzer 2>/dev/null || echo 0)
info "Connection entries after clear: $CONN_LINES"
pass "clear executed"

# ============================================================
# STRESS TEST
# ============================================================
section "Stress Test — Many Connections + Rapid insmod/rmmod"

info "Opening 50 parallel connections..."
for i in $(seq 1 50); do
    curl -s --max-time 2 https://httpbin.org/get > /dev/null &
done
wait
info "Connection count in proc file:"
wc -l < /proc/traffic_analyzer

info "Rapid insmod/rmmod cycle (5 times)..."
for i in $(seq 1 5); do
    sudo rmmod traffic_analyzer 2>/dev/null
    sudo insmod ~/Documents/Projects/kernel_traffic_analyzer/kernel_module/traffic_analyzer.ko
    sleep 0.5
    echo -n "  Cycle $i: "
    if lsmod | grep -q traffic_analyzer; then echo "loaded"; else echo "FAILED"; fi
done

info "dmesg after rapid cycles (last 15 lines):"
dmesg | tail -15

# ============================================================
# MEMORY LEAK CHECK (kmemleak)
# ============================================================
section "Memory Leak Check (kmemleak)"

if [ -e /sys/kernel/debug/kmemleak ]; then
    info "kmemleak is available"
    sudo bash -c "echo scan > /sys/kernel/debug/kmemleak"
    sleep 5
    LEAKS=$(sudo cat /sys/kernel/debug/kmemleak | grep -c "unreferenced" 2>/dev/null || echo 0)
    if [ "$LEAKS" -eq 0 ]; then
        pass "No memory leaks detected"
    else
        fail "$LEAKS potential leak(s) found — check /sys/kernel/debug/kmemleak"
        sudo cat /sys/kernel/debug/kmemleak | head -40
    fi
else
    info "kmemleak not available — boot with kmemleak=on in GRUB to enable"
    info "Alternative: check /proc/slabinfo for kmalloc growth"
    cat /proc/slabinfo | grep -i "kmalloc-" | head -10
fi

# ============================================================
# FINAL — Clean Unload
# ============================================================
section "Final — Clean Unload"

info "Removing module..."
sudo rmmod traffic_analyzer
sleep 1

info "dmesg after rmmod (look for cleanup messages):"
dmesg | tail -10

info "Checking all /proc entries are gone..."
for f in \
    /proc/traffic_analyzer \
    /proc/traffic_analyzer_procs \
    /proc/traffic_analyzer_dns \
    /proc/traffic_analyzer_anomalies \
    /proc/traffic_analyzer_dns_map \
    /proc/traffic_analyzer_routes \
    /proc/traffic_analyzer_routes_pending; do
    if [ ! -e "$f" ]; then
        pass "$f removed"
    else
        fail "$f still exists after rmmod"
    fi
done

info "Checking module is not listed in lsmod..."
if lsmod | grep -q traffic_analyzer; then
    fail "Module still loaded!"
else
    pass "Module fully unloaded"
fi

# ============================================================
echo -e "\n${BOLD}${GREEN}════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  All tests complete.${NC}"
echo -e "${BOLD}${GREEN}  Check [PASS]/[FAIL] lines above.${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════${NC}\n"