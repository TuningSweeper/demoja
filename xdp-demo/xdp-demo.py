#!/usr/bin/env python3

# apt-get install python3-bpfcc bpfcc-tools
# or so

from bcc import BPF
import os
import time
import struct
import socket
import argparse


def dropAll(device):
    bpfcode = """
    #include <uapi/linux/bpf.h>

    int dropall(struct xdp_md *ctx) {
        return XDP_DROP;
    }
    """

    b = BPF(text=bpfcode)
    fn = b.load_func("dropall", BPF.XDP)
    b.attach_xdp(device, fn, 0)



def drop10(device):
    bpfcode = """
    #include <uapi/linux/bpf.h>
    #include <linux/if_ether.h>
    #include <linux/ip.h>

    BPF_HASH(packet_count, u32, u32);

    int drop10(struct xdp_md *ctx) {
        u32 key = 0;
        u32 *count = packet_count.lookup(&key);

        if (count) {
            (*count)++;
            if (*count == 10) {
                *count = 0;
                return XDP_DROP;
            }
        } else {
            u32 initial_count = 1;
            packet_count.update(&key, &initial_count);
        }

        return XDP_PASS;
    }
    """

    b = BPF(text=bpfcode)
    fn = b.load_func("drop10", BPF.XDP)
    b.attach_xdp(device, fn, 0)



def firewall(device, ip):

    bpfcode = """
    #include <uapi/linux/bpf.h>
    #include <linux/if_ether.h>
    #include <linux/ip.h>

    int firewall(struct xdp_md *ctx) {
        void *data_end = (void *)(long)ctx->data_end;
        void *data     = (void *)(long)ctx->data;

        // Parse Ethernet header
        struct ethhdr *eth = data;
        if ((void*)(eth + 1) > data_end) return XDP_PASS;

        // Only handle IPv4
        if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

        // Parse IP header
        struct iphdr *ip = (void *)(eth + 1);
        if ((void*)(ip + 1) > data_end) return XDP_PASS;

        // Hardcoded source IP to drop
        __u32 blocked_ip = __constant_htonl(--ip--);

        if (ip->saddr == blocked_ip) {
            // Drop the packet
            bpf_trace_printk("Dropped packet from --ip_readable--\\n");
            return XDP_DROP;
        }

        // Allow all other packets
        return XDP_PASS;
    }
    """
    ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
    ip_hex = f"0x{ip_int:08x}"  # hex string, e.g., '0xc0a80101'
    bpfcode = bpfcode.replace("--ip--", ip_hex)
    bpfcode = bpfcode.replace("--ip_readable--", ip)

    b = BPF(text=bpfcode)
    fn = b.load_func("firewall", BPF.XDP)
    b.attach_xdp(device, fn, 0)



def counter(device):
    bpfcode = """
    #include <uapi/linux/bpf.h>

    BPF_HISTOGRAM(counter, u64);

    int pktcounter(struct xdp_md *ctx) {
        counter.increment(1);
        return XDP_PASS;
    }
    """

    b = BPF(text=bpfcode)
    fn = b.load_func("pktcounter", BPF.XDP)
    b.attach_xdp(device, fn, 0)

    try:
        while True:
            dist = b.get_table("counter")
            total = 0
            for key, leaf in dist.items():
                if isinstance(leaf.value, list):
                    total += sum(leaf.value)
                else:
                    total += leaf.value
            print(f"total rx count: {total}")
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        print("Removing XDP program")
        b.remove_xdp(device, 0)


if os.geteuid() != 0:
    print("Run as root.")
    exit(1)

parser = argparse.ArgumentParser(description="XDP Loader")

# Required interface with short -i
parser.add_argument('-i', '--interface', required=True, help='Network interface')

# Mutually exclusive group for mode
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--dropall', action='store_true', help='Install XDP program to drop all packets')
group.add_argument('--drop10', action='store_true', help='Install XDP program to drop every 10th packet')
group.add_argument('--firewall', action='store_true', help='Install XDP program to firewall based on source IP')
group.add_argument('--counter', action='store_true', help='Install XDP program to count packets')
group.add_argument('--remove', action='store_true', help='Remove any XDP program from interface')

# Optional positional IP (we'll check when needed)
parser.add_argument('ip', nargs='?', help='IP address (only required with --firewall)')

args = parser.parse_args()

if args.firewall and not args.ip:
    parser.error("IP address is required when using --firewall")
elif not args.firewall and args.ip:
    parser.error("IP address is only allowed with --firewall")

print(f"Interface: {args.interface}")
if args.dropall:
    print("Mode: dropall")
    dropAll(args.interface)
elif args.drop10:
    print("Mode: drop 10 %")
    drop10(args.interface)
elif args.counter:
    print("Mode: counter mode")
    counter(args.interface)
elif args.firewall:
    print("Mode: firewall mode")
    firewall(args.interface, args.ip)
    print("To see dropped packets: sudo cat /sys/kernel/debug/tracing/trace_pipe")
elif args.remove:
    print("Removing XDP program")
    BPF.remove_xdp(args.interface, 0)

