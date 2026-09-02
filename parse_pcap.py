"""Minimal pcapng parser to summarize multicast test traffic."""
import struct, sys, collections
from datetime import datetime, timedelta

path = sys.argv[1] if len(sys.argv) > 1 else "pcap.pcapng"
data = open(path, "rb").read()

pos = 0
endian = "<"
ifaces = []
packets = []  # (ts, raw)

while pos < len(data) - 12:
    block_type, block_len = struct.unpack_from(endian + "II", data, pos)
    if block_type == 0x0A0D0D0A:  # SHB
        bom = struct.unpack_from("I", data, pos + 8)[0]
        endian = "<" if bom == 0x1A2B3C4D else ">"
        block_type, block_len = struct.unpack_from(endian + "II", data, pos)
    body = data[pos + 8 : pos + block_len - 4]
    if block_type == 0x00000001:  # IDB
        lt = struct.unpack_from(endian + "H", body)[0]
        tsresol = 6
        opt = 8  # after LinkType(2) + Reserved(2) + SnapLen(4)
        while opt + 2 < len(body):
            ocode, olen = struct.unpack_from(endian + "HH", body, opt)
            if ocode == 0:
                break
            if ocode == 9 and olen >= 1:  # if_tsresol
                r = body[opt + 4]
                tsresol = 10 ** (r & 0x7F) if r & 0x80 else 10 ** r
            opt += 2 + olen + ((4 - (2 + olen) % 4) % 4)
        ifaces.append({"lt": lt, "tsresol": tsresol})
    elif block_type == 0x00000006 and ifaces:  # EPB
        iid, hi, lo, caplen, origlen = struct.unpack_from(endian + "IIIII", body)
        pkt = body[20 : 20 + caplen]
        packets.append((hi * 2**32 + lo, pkt))
    pos += block_len

if not packets:
    print("no packets parsed"); sys.exit(1)

tsresol = ifaces[0]["tsresol"] if ifaces else 6
def ts_secs(raw):
    return raw / tsresol

def mac(b):
    return ":".join(f"{x:02x}" for x in b)

def parse_pkt(pkt):
    out = {}
    if len(pkt) < 14:
        return None
    ethertype = struct.unpack_from("!H", pkt, 12)[0]
    off = 14
    out["dst_mac"] = mac(pkt[0:6]); out["src_mac"] = mac(pkt[6:12])
    while ethertype in (0x8100, 0x88A8) and len(pkt) >= off + 4:
        ethertype = struct.unpack_from("!H", pkt, off + 2)[0]
        out["vlan"] = struct.unpack_from("!H", pkt, off)[0] & 0xFFF
        off += 4
    out["ethertype"] = ethertype
    if ethertype != 0x0800 or len(pkt) < off + 20:
        return out
    ip = pkt[off:]
    ihl = (ip[0] & 0xF) * 4
    proto = ip[9]
    src = ".".join(map(str, ip[12:16])); dst = ".".join(map(str, ip[16:20]))
    out.update(proto=proto, src=src, dst=dst, ttl=ip[8], total_len=struct.unpack_from("!H", ip, 2)[0], df=bool(struct.unpack_from("!H", ip, 6)[0] & 0x4000))
    l4 = ip[ihl:]
    if proto == 17 and len(l4) >= 8:
        out["sport"], out["dport"] = struct.unpack_from("!HH", l4)
        out["payload"] = l4[8:]
    elif proto == 2 and len(l4) >= 8:
        out["igmp_type"] = l4[0]
        out["igmp_group"] = ".".join(map(str, l4[4:8]))
    return out

# --- summaries ---
flows = collections.Counter()
igmp = collections.Counter()
pkts_by_flow = collections.defaultdict(list)
seqs = collections.Counter()
payload_lens = collections.Counter()
ttls = collections.Counter()
srcs = collections.Counter()

for raw, pkt in packets:
    p = parse_pkt(pkt)
    if not p:
        continue
    if p.get("proto") == 17:
        key = (p["src"], p["dst"], p["sport"], p["dport"])
        flows[key] += 1
        pl = p.get("payload", b"")
        payload_lens[len(pl)] += 1
        ttls[p["ttl"]] += 1
        srcs[p["src"]] += 1
        pkts_by_flow[key].append((raw, p))
    elif p.get("proto") == 2:
        igmp[(p["igmp_type"], p["igmp_group"], p["src"])] += 1

first, last = ts_secs(packets[0][0]), ts_secs(packets[-1][0])
dur = last - first
print(f"packets: {len(packets)}  ifaces: {ifaces}  duration: {dur:.2f}s")
if packets:
    t = datetime(1970,1,1) + timedelta(seconds=first)
    print(f"first packet time: {t} (local: {t.astimezone()})")
print("\nUDP flows (src -> dst, sport->dport): count")
for k, c in flows.most_common(20):
    print(f"  {k[0]}:{k[2]} -> {k[1]}:{k[3]}  {c}")
print("\nIP srcs:", dict(srcs))
print("IP TTLs:", dict(ttls))
print("UDP payload lengths:", dict(sorted(payload_lens.items())))
print("\nIGMP (type, group, src): count")
names = {0x11: "v2-report", 0x12: "v1-report", 0x16: "v3-report", 0x22: "v3-report", 0x17: "leave"}
for k, c in sorted(igmp.items()):
    print(f"  {names.get(k[0], hex(k[0]))} group={k[1]} src={k[2]}  {c}")

# inter-packet timing for the main flow
main = flows.most_common(1)
if main:
    key = main[0][0]
    ps = pkts_by_flow[key]
    gaps = [ts_secs(ps[i+1][0]) - ts_secs(ps[i][0]) for i in range(len(ps) - 1)]
    if gaps:
        gaps_sorted = sorted(gaps)
        print(f"\nmain flow {key}: {len(ps)} pkts in {dur:.2f}s ({len(ps)/dur:.0f} pps)")
        print(f"  gap min/median/p95/max = {gaps_sorted[0]*1000:.2f} / {gaps_sorted[len(gaps_sorted)//2]*1000:.2f} / {gaps_sorted[int(len(gaps_sorted)*0.95)]*1000:.2f} / {gaps_sorted[-1]*1000:.2f} ms")
    # peek first payloads
    for raw, p in ps[:3]:
        pl = p.get("payload", b"")
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in pl[:80])
        print(f"  payload[{len(pl)}]: {pl[:24].hex()}  |{printable}|")