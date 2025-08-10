from scapy.all import rdpcap, TCP, IP
from collections import defaultdict

pcap_file = "1.pcap"  # change to your file path
packets = rdpcap(pcap_file)

send_times = defaultdict(dict)         # For RTT: flow -> {seq_start: send_time}
seen_sequences = defaultdict(set)      # For retrans detection
last_arrival = {}                       # For jitter
flow_rtts = defaultdict(list)
flow_retrans_count = defaultdict(int)
flow_jitter = defaultdict(list)

def flow_id(pkt):
    ip = pkt[IP]
    tcp = pkt[TCP]
    return (ip.src, tcp.sport, ip.dst, tcp.dport)

for pkt in packets:
    if not (IP in pkt and TCP in pkt):
        continue

    fwd = flow_id(pkt)
    ts = pkt.time
    tcp = pkt[TCP]

    # --- RTT calculation (improved) ---
    if tcp.flags & 0x10:  # ACK
        rev_flow = (fwd[2], fwd[3], fwd[0], fwd[1])
        for seq_start, sent_time in list(send_times[rev_flow].items()):
            if tcp.ack > seq_start:
                rtt = ts - sent_time
                if rtt > 0:
                    flow_rtts[fwd].append(rtt)
                del send_times[rev_flow][seq_start]  # remove matched seq

    if len(tcp.payload) > 0:
        send_times[fwd][tcp.seq] = ts

    # --- Retransmission detection ---
    seq_key = (tcp.seq, len(tcp.payload))
    if seq_key in seen_sequences[fwd]:
        flow_retrans_count[fwd] += 1
    else:
        seen_sequences[fwd].add(seq_key)

    # --- Jitter calculation ---
    if fwd in last_arrival:
        delta = ts - last_arrival[fwd]
        if len(flow_jitter[fwd]) == 0:
            flow_jitter[fwd].append(delta)
        else:
            prev_j = flow_jitter[fwd][-1]
            jitter = prev_j + (abs(delta - prev_j) - prev_j) / 16
            flow_jitter[fwd].append(jitter)
    last_arrival[fwd] = ts

# --- Combine all flows into one set ---
all_flows = set(flow_rtts.keys()) | set(flow_retrans_count.keys()) | set(flow_jitter.keys())

# --- Print results ---
for flow in all_flows:
    avg_rtt = (sum(flow_rtts[flow]) / len(flow_rtts[flow])
               if flow_rtts[flow] else 0)
    avg_jitter = flow_jitter[flow][-1] if flow_jitter[flow] else 0
    retrans = flow_retrans_count[flow]

    print(f"Flow {flow[0]}:{flow[1]} -> {flow[2]}:{flow[3]}")
    print(f"  Avg RTT: {avg_rtt*1000:.2f} ms")
    print(f"  Retransmissions: {retrans}")
    print(f"  Jitter: {avg_jitter*1000:.2f} ms\n")
