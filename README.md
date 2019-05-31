# ICMPcat

A *netcat* inspired utility for bidirectional communication over ICMP (ping) traffic.

## Usage

### Server

``bash
sudo sysctl net.ipv4.icmp_echo_ignore_all=1
sudo python icmpcat_server.py
```

### Client

```bash
sudo python icmpcat_client.py <IP ADDRESS OF ICMPCAT SERVER> <TIME INTERVAL BETWEEN PINGS (SECONDS)>
```

Any lines typed into the *client* console will appear on the *server*
console. Any lines typed into the *server* console will appear on
the *client* console.

