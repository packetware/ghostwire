# Ghostwire
An (experimental) stateful XDP firewall for Linux.

We built this and use it internally at [Packetware](https://packetware.net), a global content delivery network, to protect our infrastructure.
We found performance with IPtables is abysmal for systems where performance is must, and somewhat uninitive to manage persistence for.

For stateless "stupid" filtering, Ghostwire is approximately 5.5x more capable than IPtables's fastest PREROUTING table.
It's controlled through simple YAML configuration files.

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

## Installation
Ghostwire is used extensively on Ubuntu 24.04 LTS internally, but this installation script should work on any systemd-based system.

```bash
curl -s https://raw.githubusercontent.com/packetware/ghostwire/main/scripts/install.sh | sudo bash
```

Then, add the rules you'd like.

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

## Configuration
Ghostwire is configured through YAML files. Here's an example configuration file:

```yaml
# The firewall rules you'd like to define.
# The firewall drops traffic like TCP and UDP by default, rules whitelist traffic
rules:
  # Define each rule individually
  - rule:
    # The source IP range this rule will apply to. For example, 23.133.104.69/32, or 23.133.104.0/24.
    # To allow traffic from any IP, use 0.0.0.0/0
    source_ip_range: 0.0.0.0/0
    # The destination IP range this rule will apply to.
    # To allow traffic to go to any IP assigned with this server, use 0.0.0.0/0.
    destination_ip_range: 0.0.0.0/0
    # The IP protocol to allow.
    # Current allowed values are: TCP, UDP, ICMP, ALL.
    protocol: "TCP"
    # The port to allow the traffic to. Only applicable to TCP and UDP.
    # Omit or enter 0 to allow any port.
    port: 22
    # Limit the amount of packets sent to this service per source IP. Runs over 1 minute.
    # Enter to zero to disable ratelimiting.
    ratelimit: 100
```
