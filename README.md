# Efense -- Linux Sensitive Monitor and Protection Tool

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
    udp_ingress:
      default_action: drop
      allow_list:
      - name: allow_dns_query
        src_ip: 192.168.122.0/24
        src_port: 53' | cargo run -- apply -
```

### Only allow ingress SSH from 192.168.122.0/24

```bash
echo '---
interfaces:
  - name: enp2s0
    tcp_ingress:
      default_action: drop
      allow_list:
      - name: allow_dns_query
        src_ip: 192.168.122.0/24
        dst_port: 22' | cargo run -- apply -
```

## License

The code in `src/ebpf` folder are GPL-2.0 only license. Others are Apache 2.0
license.
