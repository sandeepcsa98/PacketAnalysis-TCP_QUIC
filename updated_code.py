from scapy.all import rdpcap, TCP, IP
from collections import defaultdict

PCAP_FILE = "1.pcap"

packets = rdpcap(PCAP_FILE)

flow_rtts = defaultdict(list)
flow_jitters = defaultdict(list)
flow_retrans = defaultdict(int)
flow_bytes = defaultdict(int)
flow_first_ts = {}
flow_last_ts = {}

last_arrival = {}
sent_times = {}
ack_times = {}

# Store RTT for each flow
flow_est_rtt = defaultdict(lambda: 0.1)  # default RTT guess: 100ms

for pkt in packets:
    if IP in pkt and TCP in pkt:
        ts = float(pkt.time)
        src, dst = pkt[IP].src, pkt[IP].dst
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        seq, ack = pkt[TCP].seq, pkt[TCP].ack
        payload_len = len(pkt[TCP].payload)
        flags = pkt[TCP].flags

        flow_key = f"{src}:{sport} -> {dst}:{dport}"

        # Flow byte counters
        flow_bytes[flow_key] += payload_len
        if flow_key not in flow_first_ts:
            flow_first_ts[flow_key] = ts
        flow_last_ts[flow_key] = ts

        # --- RTT measurement ---
        if payload_len > 0:
            sent_times[(src, sport, dst, dport, seq + payload_len)] = ts
        if flags & 0x10:  # ACK
            key = (dst, dport, src, sport, ack)
            if key in sent_times:
                rtt = ts - sent_times[key]
                if rtt >= 0:
                    flow_rtts[flow_key].append(rtt)
                    flow_est_rtt[flow_key] = (flow_est_rtt[flow_key] * 0.875) + (rtt * 0.125)
                del sent_times[key]

        # --- Jitter measurement ---
        if flow_key in last_arrival:
            interarrival = ts - last_arrival[flow_key]
            flow_jitters[flow_key].append(interarrival)
        last_arrival[flow_key] = ts

        # --- Retransmission detection ---
        if payload_len > 0:
            seq_key = (src, sport, dst, dport, seq, payload_len)

            # Ignore keep-alives (1-byte repeats)
            if payload_len == 1 :
                continue
            
            if seq_key in sent_times:
                    flow_retrans[flow_key] += 1
            else:
                sent_times[seq_key] = ts

# ==== Output ====
for flow in set(flow_bytes.keys()) | set(flow_rtts.keys()) | set(flow_jitters.keys()):
    rtts = flow_rtts.get(flow, [])
    avg_rtt_ms = (sum(rtts) / len(rtts) * 1000) if rtts else 0.0

    jitters = flow_jitters.get(flow, [])
    avg_jitter_ms = (sum(abs(j2 - j1) for j1, j2 in zip(jitters[:-1], jitters[1:])) /
                     len(jitters) * 1000) if len(jitters) > 1 else 0.0

    retrans = flow_retrans.get(flow, 0)

    duration = float(flow_last_ts[flow] - flow_first_ts[flow]) if flow_first_ts.get(flow) and flow_last_ts.get(flow) else 0.0
    throughput_bps = (float(flow_bytes[flow]) / duration) if duration > 0 else 0.0
    throughput_mbps = (throughput_bps * 8.0) / 1_000_000.0

    print(f"\nFlow {flow}")
    print(f"  Avg RTT: {avg_rtt_ms:.2f} ms")
    print(f"  Avg Jitter: {avg_jitter_ms:.2f} ms")
    print(f"  Retransmissions: {retrans}")
    print(f"  Throughput: {throughput_mbps:.2f} Mbps")

