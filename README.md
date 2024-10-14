# Ghostwire
An (experimental) stateful XDP firewall for Linux.

We built this to use it internally at [Packetware](https://packetware.net), a global content delivery network, to protect our infrastructure.
We found performance with IPtables is a joke for systems where performance is must, and unintuitive to manage persistence for.

For stateless "stupid" filtering, Ghostwire is approximately 5.5x more capable (in handled packets per second) than IPtables's fastest PREROUTING table.
For stateful filtering, Ghostwire destroys IPtables' conntrack (our initial benchmarks show at least 9.5x more packets per second).
It's controlled through simple YAML configuration files, no BS.

Some features are:
- Stateful holepunch-based filtering
- Rate limiting
- Simple YAML syntax
- UNIX socket API
- Exports Prometheus metrics

We'd like to add:
- Block IP UNIX socket endpoint (much more performant ipset)
- More complex rate limiting
- Installation support for more systems

This is currently in Alpha state, I wouldn't recommend using it in production just yet.

## Getting Started

### Configuration
Ghostwire is configured through YAML files. Here's an example configuration file:

```yaml
# The interface to run the XDP on. We'll try to load with offloading first, then without in SKB mode.
interface: "eth0"

# Default behavior is drop-all, firewall rules explicitly allow traffic
rules:
  # Every component of this rule must match for the rule to apply.
  - rule:
    # The source IP range this rule will apply to. For example, 23.133.104.69/32, or 10.0.0.0/8.
    # To allow traffic from any IP, use 0.0.0.0/0.
    source_ip_range: 0.0.0.0/0
    # The destination IP range this rule will apply to.
    # To allow traffic to go to any IP, use 0.0.0.0/0.
    destination_ip_range: 0.0.0.0/0
    # The IP protocol to allow.
    # Current allowed values are: TCP, UDP, ICMP, ALL.
    # Leave empty to allow all protocols.
    protocol: "TCP"
    # The port to allow the traffic to. Only applicable to TCP and UDP.
    # Leavy empty to allow any port.
    port: 22
    # Limit the amount of packets sent to this service per source IP. Runs over 1 minute.
    # Omit to disable rate limiting.
    ratelimit: 1000
```

### Installation
Ghostwire is tested on Ubuntu 24.04 LTS internally, but this installation script should work on any systemd-based system.

```bash
curl -s https://raw.githubusercontent.com/packetware/ghostwire/main/scripts/install.sh | sudo bash
```

Then, add the rules you'd like in a YAML file and start the firewall

Start the firewall:
```bash
gw load config.yml
```

See the status:
```bash
gw status
```

Stop the firewall:
```bash
gw disable
```
