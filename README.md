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
- Exports IPFIX to Clickhouse

We'd like to add:
- Block IP UNIX socket endpoint (much more performant ipset)
- More complex rate limiting
- Installation support for more systems

This is currently in Alpha state, I wouldn't recommend using it in production just yet.

## Installation
Ghostwire is tested on Ubuntu 24.04 LTS internally, but this installation script should work on any systemd-based system.

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
interface: "enp0s8"
source: 
  type: local # Can be "local" for using this YAML or "database" to fetch rules from a DB
  database: # Only required if `type` is "database"
    host: "db.example.com"
    port: 5432
    username: "firewall_user"
    password: "securepassword"
    database_name: "firewall_rules"
default: block # Optional, sets the default action for unmatched rules
rules:
  - action: allow # Optional, defaults to the `default_action`
    sources: 
      - 192.168.56.0/24 # Optional, defaults to 0.0.0.0/0
    destinations: 
      - 192.168.56.101/32 # Required
    protocols:
      - tcp
      - udp # List of protocols
    port_range: # Optional range, ports cant be specified if port_range is specified
      start: 23
      end: 40
  - action: allow
    destinations: 
      - 192.168.56.101/32
    protocols:
      - tcp
    ports:
      - 2022
  - action: allow
    destinations: 
      - 10.0.0.1/32
    protocols:
      - icmp # if the protocol is ICMP the ports should be just [0]
```
