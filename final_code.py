import sys
from scapy.all import *
from collections import defaultdict

def calculate_tcp_rtt_jitter(pcap_file):
    """
    Calculate average RTT and RFC3550 jitter for TCP packets in a pcap file.
    Returns (avg_rtt_seconds, jitter_seconds)
    """
    # Stores unacked packets: flow_id -> list[(seq_no, length, send_time)]
    unacked_packets = defaultdict(list)

    # RTT stats
    rtt_sum = 0.0
    rtt_count = 0

    # RFC3550 jitter
    prev_rtt = None
    jitter = 0.0

    packets = rdpcap(pcap_file)

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        tcp = pkt[TCP]

        fwd_flow = (ip.src, tcp.sport, ip.dst, tcp.dport)
        rev_flow = (ip.dst, tcp.dport, ip.src, tcp.sport)

        # Skip SYN packets
        if tcp.flags & 0x02:  # SYN
            continue

        payload_len = len(tcp.payload)

        # Data packet
        if payload_len > 0:
            seq_no = tcp.seq
            unacked_packets[fwd_flow].append((seq_no, payload_len, float(pkt.time)))

        # ACK packet
        if tcp.flags & 0x10:  # ACK
            ack_no = tcp.ack
            if rev_flow in unacked_packets and unacked_packets[rev_flow]:
                # Find packets fully acknowledged by this ACK
                newly_acked = [
                    (seq, length, sent_time)
                    for (seq, length, sent_time) in unacked_packets[rev_flow]
                    if seq + length <= ack_no
                ]
                if newly_acked:
                    # Use the packet with the largest seq (most recent sent)
                    latest_packet = max(newly_acked, key=lambda x: x[0])
                    seq, length, sent_time = latest_packet
                    rtt = float(pkt.time) - float(sent_time)
                    rtt_sum += rtt
                    rtt_count += 1

                    # RFC 3550 jitter calculation
                    if prev_rtt is not None:
                        D = abs(rtt - prev_rtt)
                        jitter += (D - jitter) / 16.0
                    prev_rtt = rtt

                    # Remove all newly acked packets
                    unacked_packets[rev_flow] = [
                        (seq, length, sent_time)
                        for (seq, length, sent_time) in unacked_packets[rev_flow]
                        if seq + length > ack_no
                    ]

    avg_rtt = (rtt_sum / rtt_count) if rtt_count > 0 else None
    return avg_rtt, jitter

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    avg_rtt, jitter = calculate_tcp_rtt_jitter(pcap_file)

    if avg_rtt is not None:
        print(f"Average RTT: {avg_rtt * 1000:.3f} ms")
        print(f"Average Jitter (RFC3550): {jitter * 1000:.3f} ms")
    else:
        print("No valid RTT samples found.")

