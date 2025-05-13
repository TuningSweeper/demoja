# XDP and BPF Demo

This script demonstrates basic XDP (eXpress Data Path) and BPF (Berkeley Packet Filter) usage in Python. It allows you to apply different XDP programs on a network interface.

## Available Modes

 * Drop All Packets (--dropall): Drops all packets on the interface.
 * Drop Every 10th Packet (--drop10): Drops every 10th packet.
 * Firewall Mode (--firewall): Drops packets from a specified source IP.
 * Packet Counter (--counter): Counts packets on the interface.
 * Remove XDP Program (--remove): Removes the XDP program.

## Example usage

Drop all packets:
```
sudo python3 xdp_demo.py -i eth0 --dropall
```

Drop every 10th packet:
```
sudo python3 xdp_demo.py -i eth0 --drop10
```

Firewall mode to block a source IP:
```
sudo python3 xdp_demo.py -i eth0 --firewall 192.168.1.1
```

Count packets:
```
sudo python3 xdp_demo.py -i eth0 --counter
```

Remove any XDP program:
```
sudo python3 xdp_demo.py -i eth0 --remove
```

