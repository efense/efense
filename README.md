# Efense -- Linux Security Monitor and Protection Tool

*Working in progress, no use at all*

Efense is a Linux tool for security monitor and protection.

## Features
 * eBPF based high performance, low overhead monitoring and protection
 * No daemon, no leftover thread

## Usage

```
# Query loaded rules
cargo run -- show

# Monitor security events in real time
cargo run -- monitor

# Apply config
cargo run -- apply <config_file>

# Purge all config
cargo run -- purge
```

## Example

### Only allow UDP DNS server from 192.168.122.0/24 via enp2s0

```bash
echo '---
interfaces:
  - name: enp2s0
    udp:
      allow_list:
      - name: allow_dns_query
        src_ip_ranges:
        - 192.168.122.0/24
        src_port: 53' | cargo run -- apply -
```

### Only allow ingress SSH from 192.168.122.0/24

```bash
echo '---
interfaces:
  - name: enp2s0
    tcp:
      # allow TCP connection initialized by current host
      allow_outgoing: true
      protections:
        # Drop illegal TCP ACK before send to kernel process.
        # default is false
        tcp_ack_flood: true
      allow_list:
      - name: allow_ssh
        src_ip_ranges:
        - 192.168.122.0/24
        port: 22' | cargo run -- apply -
```

### Enable TCP ACK flood protection for port 22 and 443

```bash
echo '---
interfaces:
  - name: enp2s0
    tcp:
      # allow TCP connection initialized by current host
      allow_outgoing: true
      protections:
        # Drop illegal TCP ACK before send to kernel process.
        tcp_ack_flood: true
      allow_list:
      - name: allow_ssh
        port: 22
      - name: httpd
        port 443' | cargo run -- apply -
```

## License

The code in `src/ebpf` folder are GPL-2.0 only license. Others are Apache 2.0
license.
