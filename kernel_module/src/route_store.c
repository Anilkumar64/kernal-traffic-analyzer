#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/inet.h>
#include "../include/route_store.h"
#include "../include/netlink_comm.h"

static DEFINE_HASHTABLE(route_table, ROUTE_STORE_BITS);
static DEFINE_SPINLOCK(route_lock);

/*
 * pending_write_ip — persists the current DEST IP across write() syscalls.
 *
 * The daemon writes DEST/STATUS/HOP as separate lines which the kernel
 * receives as separate write() calls.  Without this static, the local
 * `cur` pointer in route_store_write() is reset to NULL on every call,
 * so STATUS and HOP lines after the first write() are silently ignored.
 *
 * We store the IP (not a pointer) to avoid any use-after-free risk if
 * the entry is evicted between calls.  Each STATUS/HOP write resolves
 * the entry freshly from the hash table using this IP.
 */
static __be32 pending_write_ip = 0;

void route_store_init(void)
{
    hash_init(route_table);
    pending_write_ip = 0;
}

static struct route_entry *__find_entry(__be32 ip)
{
    struct route_entry *e;
    u32 h = jhash(&ip, sizeof(ip), 0);

    hash_for_each_possible(route_table, e, node, h)
    {
        if (e->dest_ip == ip)
            return e;
    }
    return NULL;
}

static inline bool is_routable(__be32 ip)
{
    u32 h = ntohl(ip);
    if ((h >> 24) == 127)
        return false; /* loopback   */
    if ((h >> 24) == 10)
        return false; /* 10/8       */
    if ((h >> 20) == (172 << 4 | 1))
        return false; /* 172.16/12 */
    if ((h >> 16) == (192 << 8 | 168))
        return false; /* 192.168/16 */
    if ((h >> 16) == (169 << 8 | 254))
        return false; /* link-local */
    if ((h >> 28) == 14)
        return false; /* multicast  */
    if (h == 0)
        return false; /* 0.0.0.0    */
    return true;
}

void route_store_request(__be32 ip, const char *domain)
{
    struct route_entry *e;
    u64 now = ktime_get_real_seconds();
    u32 h = jhash(&ip, sizeof(ip), 0);

    if (!is_routable(ip))
        return;

    spin_lock(&route_lock);
    e = __find_entry(ip);
    if (e)
    {
        if (e->status == ROUTE_STATUS_DONE &&
            now - e->last_updated < ROUTE_TTL)
        {
            spin_unlock(&route_lock);
            return;
        }
        if (e->status == ROUTE_STATUS_PENDING ||
            e->status == ROUTE_STATUS_RUNNING)
        {
            spin_unlock(&route_lock);
            return;
        }
        e->hop_count = 0;
        e->status = ROUTE_STATUS_PENDING;
        e->requested_at = now;
        if (domain && domain[0] && !e->domain[0])
            strscpy(e->domain, domain, sizeof(e->domain));
        spin_unlock(&route_lock);
        return;
    }
    spin_unlock(&route_lock);

    e = kmalloc(sizeof(*e), GFP_ATOMIC);
    if (!e)
        return;

    memset(e, 0, sizeof(*e));
    e->dest_ip = ip;
    e->status = ROUTE_STATUS_PENDING;
    e->requested_at = now;
    if (domain && domain[0])
        strscpy(e->domain, domain, sizeof(e->domain));

    spin_lock(&route_lock);
    hash_add(route_table, &e->node, h);
    spin_unlock(&route_lock);
}

bool route_store_lookup(__be32 ip, struct route_entry *out)
{
    struct route_entry *e;
    bool found = false;

    spin_lock(&route_lock);
    e = __find_entry(ip);
    if (e)
    {
        *out = *e;
        found = true;
    }
    spin_unlock(&route_lock);
    return found;
}

static const char *next_field(const char *p, char *out, size_t outsz)
{
    size_t i = 0;

    while (*p == ' ' || *p == '\t')
        p++;
    if (!*p || *p == '\n')
        return NULL;

    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && i < outsz - 1)
        out[i++] = *p++;

    out[i] = '\0';
    return p;
}

/*
 * route_store_write — parse DEST / STATUS / HOP lines from the daemon.
 *
 * The daemon (ta_route_daemon.py) writes results line by line.  Each
 * line arrives as a separate write() syscall so we cannot use a local
 * `cur` pointer — it would be NULL on every call except the one that
 * contains "DEST".  Instead we persist the current IP in the module-
 * level `pending_write_ip` variable and look up the entry fresh on
 * every STATUS/HOP call.
 *
 * Protocol:
 *   DEST <ip>
 *   STATUS DONE|FAILED|RUNNING
 *   HOP <n> <ip> <rtt_us> <host> <city> <country> <cc> \
 *       <lat_e6> <lon_e6> <asn> <org>
 */
int route_store_write(const char *buf, size_t len)
{
    const char *p = buf;
    const char *end = buf + len;
    u64 now = ktime_get_real_seconds();

    while (p < end)
    {
        /* Slice one line */
        const char *eol = p;
        while (eol < end && *eol != '\n')
            eol++;

        size_t llen = eol - p;
        if (llen == 0)
        {
            p = eol + 1;
            continue;
        }
        if (llen > 512)
            llen = 512;

        char line[513];
        memcpy(line, p, llen);
        line[llen] = '\0';
        p = eol + 1;

        /* Strip trailing whitespace / CR */
        while (llen > 0 &&
               (line[llen - 1] == ' ' || line[llen - 1] == '\t' ||
                line[llen - 1] == '\r'))
            line[--llen] = '\0';

        if (llen == 0)
            continue;

        /* ---- DEST <ip> ---- */
        if (strncmp(line, "DEST ", 5) == 0)
        {
            __be32 ip;
            const char *ep;

            if (in4_pton(line + 5, -1, (u8 *)&ip, -1, &ep) != 1)
                continue;

            /* Ensure entry exists */
            spin_lock(&route_lock);
            if (!__find_entry(ip))
            {
                spin_unlock(&route_lock);
                route_store_request(ip, "");
                spin_lock(&route_lock);
            }
            {
                struct route_entry *e = __find_entry(ip);
                if (e)
                    e->hop_count = 0;
            }
            spin_unlock(&route_lock);

            /* Persist across subsequent write() calls */
            pending_write_ip = ip;
            continue;
        }

        /* ---- STATUS DONE|FAILED|RUNNING ---- */
        if (strncmp(line, "STATUS ", 7) == 0 && pending_write_ip)
        {
            const char *sv = line + 7;
            u8 status;

            if (strncmp(sv, "DONE", 4) == 0)
                status = ROUTE_STATUS_DONE;
            else if (strncmp(sv, "FAILED", 6) == 0)
                status = ROUTE_STATUS_FAILED;
            else if (strncmp(sv, "RUNNING", 7) == 0)
                status = ROUTE_STATUS_RUNNING;
            else
                continue;

            spin_lock(&route_lock);
            {
                struct route_entry *e = __find_entry(pending_write_ip);
                if (e)
                {
                    e->status = status;
                    e->last_updated = now;

                    /* Phase 6: emit netlink when route is complete */
                    if (status == ROUTE_STATUS_DONE)
                    {
                        spin_unlock(&route_lock);
                        spin_lock(&route_lock);
                        e = __find_entry(pending_write_ip);
                        if (e)
                            ta_nl_send_route(e);
                    }
                }
            }
            spin_unlock(&route_lock);
            continue;
        }

        /* ---- HOP <n> <ip> <rtt_us> <host> <city> <country> <cc>
                    <lat_e6> <lon_e6> <asn> <org> ---- */
        if (strncmp(line, "HOP ", 4) == 0 && pending_write_ip)
        {
            char fld[128];
            const char *fp = line + 4;
            struct route_hop hop;
            memset(&hop, 0, sizeof(hop));

            /* hop number */
            fp = next_field(fp, fld, sizeof(fld));
            if (!fp)
                continue;
            if (kstrtou8(fld, 10, &hop.hop_num) != 0)
                continue;

            /* hop IP */
            fp = next_field(fp, fld, sizeof(fld));
            if (!fp)
                continue;
            if (strcmp(fld, "*") != 0)
            {
                const char *ep;
                in4_pton(fld, -1, (u8 *)&hop.ip, -1, &ep);
            }

            /* rtt_us */
            fp = next_field(fp, fld, sizeof(fld));
            if (!fp)
                continue;
            {
                u32 rtt;
                if (kstrtou32(fld, 10, &rtt) == 0)
                    hop.rtt_us = rtt;
            }

            /* host */
            fp = next_field(fp, fld, sizeof(fld));
            if (fp)
                strscpy(hop.host, fld, HOP_HOST_MAX);

            /* city */
            fp = next_field(fp, fld, sizeof(fld));
            if (fp)
                strscpy(hop.city, fld, sizeof(hop.city));

            /* country */
            fp = next_field(fp, fld, sizeof(fld));
            if (fp)
                strscpy(hop.country, fld, sizeof(hop.country));

            /* country_code */
            fp = next_field(fp, fld, sizeof(fld));
            if (fp)
                strscpy(hop.country_code, fld, sizeof(hop.country_code));

            /* lat_e6 */
            fp = next_field(fp, fld, sizeof(fld));
            if (fp)
            {
                s32 v;
                if (kstrtos32(fld, 10, &v) == 0)
                    hop.lat_e6 = v;
            }

            /* lon_e6 */
            fp = next_field(fp, fld, sizeof(fld));
            if (fp)
            {
                s32 v;
                if (kstrtos32(fld, 10, &v) == 0)
                    hop.lon_e6 = v;
            }

            /* asn */
            fp = next_field(fp, fld, sizeof(fld));
            if (fp)
                strscpy(hop.asn, fld, sizeof(hop.asn));

            /* org */
            fp = next_field(fp, fld, sizeof(fld));
            if (fp)
                strscpy(hop.org, fld, sizeof(hop.org));

            spin_lock(&route_lock);
            {
                struct route_entry *e = __find_entry(pending_write_ip);
                if (e && e->hop_count < MAX_HOPS)
                {
                    e->hops[e->hop_count++] = hop;
                    e->last_updated = now;
                }
            }
            spin_unlock(&route_lock);
            continue;
        }
    }

    return 0;
}

void route_store_seq_show(struct seq_file *m)
{
    struct route_entry *e;
    int bkt, i;
    u64 now = ktime_get_real_seconds();

    spin_lock(&route_lock);

    hash_for_each(route_table, bkt, e, node)
    {
        bool stale = (e->status == ROUTE_STATUS_DONE &&
                      now - e->last_updated > ROUTE_TTL);

        if (e->hop_count == 0)
        {
            seq_printf(m,
                       "%pI4|%s|%s|0|-|-|-|-|-|-|-|-|-|-\n",
                       &e->dest_ip,
                       e->domain[0] ? e->domain : "-",
                       stale ? "STALE" : route_status_str(e->status));
            continue;
        }

        for (i = 0; i < e->hop_count; i++)
        {
            struct route_hop *h = &e->hops[i];
            seq_printf(m,
                       "%pI4|%s|%s|%u|%u|%pI4|%s|%u|%s|%s|%s|%d|%d|%s|%s\n",
                       &e->dest_ip,
                       e->domain[0] ? e->domain : "-",
                       stale ? "STALE" : route_status_str(e->status),
                       (unsigned)e->hop_count,
                       (unsigned)h->hop_num,
                       &h->ip,
                       h->host[0] ? h->host : "-",
                       h->rtt_us / 1000,
                       h->city[0] ? h->city : "-",
                       h->country[0] ? h->country : "-",
                       h->country_code[0] ? h->country_code : "-",
                       h->lat_e6, h->lon_e6,
                       h->asn[0] ? h->asn : "-",
                       h->org[0] ? h->org : "-");
        }
    }

    spin_unlock(&route_lock);
}

void route_store_pending_seq_show(struct seq_file *m)
{
    struct route_entry *e;
    int bkt;

    spin_lock(&route_lock);

    hash_for_each(route_table, bkt, e, node)
    {
        if (e->status != ROUTE_STATUS_PENDING)
            continue;
        e->status = ROUTE_STATUS_RUNNING;
        seq_printf(m, "%pI4 %s\n",
                   &e->dest_ip,
                   e->domain[0] ? e->domain : "-");
    }

    spin_unlock(&route_lock);
}

void route_store_cleanup(void)
{
    struct route_entry *e;
    struct hlist_node *tmp;
    int bkt;

    spin_lock(&route_lock);
    hash_for_each_safe(route_table, bkt, tmp, e, node)
    {
        hash_del(&e->node);
        kfree(e);
    }
    spin_unlock(&route_lock);

    pending_write_ip = 0;
}