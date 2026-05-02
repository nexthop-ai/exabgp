# ExaBGP SR-Policy Configuration Guide

This directory contains example configurations for announcing SR-Policy routes using ExaBGP.

## Files

- **conf-sr-policy-simple.conf** - Minimal working example (start here!)
- **conf-sr-policy.conf** - Comprehensive examples covering all features

## Quick Start

### 1. Simple MPLS SR-Policy

```
sr-policy distinguisher 0 color 100 endpoint 10.1.1.1 \
    next-hop 192.0.2.1 \
    preference 100 \
    binding-sid mpls 24000 \
    segment-list weight 1 \
        segment type-a mpls 16001 \
        segment type-a mpls 16002;
```

This announces an SR-Policy that:
- Identifies traffic by color 100 destined to 10.1.1.1
- Uses MPLS binding SID 24000
- Routes traffic through labels 16001 → 16002

### 2. Simple SRv6 SR-Policy

```
sr-policy distinguisher 0 color 100 endpoint 2001:db8::1 \
    next-hop 2001:db8:ffff::1 \
    preference 100 \
    srv6-binding-sid fc00:0:100::1 \
    segment-list weight 1 \
        segment type-b srv6 fc00:0:1::1;
```

This announces an SRv6 SR-Policy that:
- Identifies traffic by color 100 destined to 2001:db8::1
- Uses SRv6 binding SID fc00:0:100::1
- Routes traffic through SRv6 SID fc00:0:1::1

## Configuration Syntax

### Full Syntax

```
sr-policy distinguisher <0-4294967295> color <0-4294967295> endpoint <ip-address> \
    next-hop <ip-address> \
    preference <0-4294967295> \
    [priority <0-255>] \
    [binding-sid mpls <20-1048575>] \
    [srv6-binding-sid <ipv6-address>] \
    [policy-name "<string>"] \
    [candidate-path-name "<string>"] \
    segment-list weight <1-4294967295> \
        segment type-a mpls <label> [segment type-a mpls <label> ...] \
    [segment-list weight <1-4294967295> ...]
```

**Important:** Use backslash (`\`) at the end of each line for continuation.

### Parameters

**SR-Policy NLRI (required):**
- `distinguisher` - Unique identifier (typically 0, increment for multiple candidate paths)
- `color` - Policy selector matched against traffic (32-bit value)
- `endpoint` - Destination IPv4 or IPv6 address
- `next-hop` - BGP next-hop (must be reachable by peer)

**Tunnel Encapsulation (required):**
- `preference` - Policy preference (higher value = higher preference)

**Tunnel Encapsulation (optional):**
- `priority` - Path priority (lower value = higher priority, 0-255)
- `binding-sid mpls` - MPLS label representing the entire SR-Policy (20-1048575)
- `srv6-binding-sid` - IPv6 address representing the entire SR-Policy
- `policy-name` - Human-readable policy name (quoted string)
- `candidate-path-name` - Human-readable candidate path name (quoted string)

**Segment Lists:**

For MPLS (Type A):
```
segment-list weight <N> \
    segment type-a mpls <label> \
    [segment type-a mpls <label> ...]
```

For SRv6 (Type B):
```
segment-list weight <N> \
    segment type-b srv6 <ipv6-sid> [endpoint-behavior <behavior> <lb> <ln> <fun> <arg>] \
    [segment type-b srv6 <ipv6-sid> ...]
```

**Notes:**
- Each segment must be declared separately with the `segment` keyword
- Multiple segment lists provide ECMP/load balancing
- Weight determines traffic distribution (proportional to weight value)
- Endpoint behavior is optional for SRv6 segments (5 integer parameters)

## Common Use Cases

### Load Balancing (ECMP)

Use multiple segment lists with different weights:

```
sr-policy distinguisher 0 color 100 endpoint 10.1.1.1 \
    next-hop 192.0.2.1 \
    preference 100 \
    binding-sid mpls 24000 \
    segment-list weight 10 \
        segment type-a mpls 16001 \
        segment type-a mpls 16002 \
    segment-list weight 5 \
        segment type-a mpls 17001 \
        segment type-a mpls 17002;
```
Traffic splits: ~66% via first path, ~33% via second path.

### Traffic Engineering

Force traffic through specific nodes:

```
sr-policy distinguisher 0 color 200 endpoint 10.2.2.2 \
    next-hop 192.0.2.1 \
    preference 100 \
    binding-sid mpls 24001 \
    segment-list weight 1 \
        segment type-a mpls 16001 \
        segment type-a mpls 16002 \
        segment type-a mpls 16003 \
        segment type-a mpls 16004;
```

### Service Chaining

Steer traffic through service functions (e.g., Firewall):

```
sr-policy distinguisher 0 color 300 endpoint 10.3.3.3 \
    next-hop 192.0.2.1 \
    preference 100 \
    binding-sid mpls 24002 \
    segment-list weight 1 \
        segment type-a mpls 16001 \
        segment type-a mpls 16002 \
        segment type-a mpls 16003;
```

### Multi-Path with Different Preferences

Primary and backup paths (use different distinguisher values):

```
# High preference primary path
sr-policy distinguisher 0 color 100 endpoint 10.1.1.1 \
    next-hop 192.0.2.1 \
    preference 200 \
    binding-sid mpls 24000 \
    segment-list weight 1 segment type-a mpls 16001;

# Lower preference backup path
sr-policy distinguisher 1 color 100 endpoint 10.1.1.1 \
    next-hop 192.0.2.1 \
    preference 100 \
    binding-sid mpls 24001 \
    segment-list weight 1 segment type-a mpls 17001;
```

## Running ExaBGP

### Basic

```bash
exabgp conf-sr-policy-simple.conf
```

### With Logging

```bash
env exabgp_daemon_daemonize=false \
    exabgp_log_enable=true \
    exabgp_log_level=INFO \
    exabgp conf-sr-policy.conf
```

### Testing Configuration

Validate syntax without running:

```bash
exabgp validate conf-sr-policy.conf
```

## Verification

### Using ExaBGP API

If you have the API enabled, you can query announced routes:

```bash
# Show all announced routes
echo "show adj-rib out" | socat - /run/exabgp/exabgp.in

# JSON format
echo "show adj-rib out json" | socat - /run/exabgp/exabgp.in
```

### On the Receiving Router

For Cisco IOS-XR:
```
show bgp ipv4 sr-policy summary
show bgp ipv4 sr-policy
show bgp ipv6 sr-policy
```

For Juniper:
```
show bgp summary family inet-srpolicy
show route table inet-srpolicy.0
```

For GoBGP:
```
gobgp global rib -a ipv4-srpolicy
gobgp global rib -a ipv6-srpolicy
```

## Troubleshooting

### SR-Policy routes not appearing

1. **Check family configuration:**
   ```
   family {
       ipv4 sr-policy;
       ipv6 sr-policy;
   }
   ```

2. **Verify BGP session is established:**
   ```
   # Look for "neighbor X.X.X.X up" in logs
   ```

3. **Check capability negotiation:**
   ```
   # Both sides must support SR-Policy SAFI (73)
   ```

### Invalid configuration errors

- Ensure `binding-sid mpls` label is in valid range (20-1048575)
- Check `srv6-binding-sid` is a valid IPv6 address
- Verify `segment type-a` uses `mpls` keyword (not `label`)
- Verify `segment type-b` uses `srv6` keyword
- Each segment must be declared separately with `segment` keyword
- Use backslash `\` for line continuation

## References

- **RFC 9256** - Segment Routing Policy Architecture
- **RFC 9012** - The BGP Tunnel Encapsulation Attribute
- **RFC 8669** - Segment Routing Prefix SID extensions for BGP
- **RFC 8986** - Segment Routing over IPv6 (SRv6) Network Programming

## Additional Examples

See `conf-sr-policy.conf` for comprehensive examples including:
- Multiple segment lists (ECMP)
- SRv6 with endpoint behavior
- Named policies
- Mixed MPLS and SRv6 configurations
