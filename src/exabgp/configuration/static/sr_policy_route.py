"""static/sr_policy_route.py

Parser for hierarchical SR Policy configuration in static section.

Syntax:
    static {
        sr-policy distinguisher <N> color <N> endpoint <IP> {
            next-hop <IP>;
            preference <N>;
            priority <N>;
            binding-sid mpls <label>;
            srv6-binding-sid <ipv6>;
            policy-name "<string>";
            candidate-path-name "<string>";
            segment-list weight <N> segment type-a mpls <label> ...;
            # Standard BGP attributes
            community [ <value> ... ];
            extended-community [ <value> ... ];
            large-community [ <value> ... ];
            origin IGP|EGP|INCOMPLETE;
            med <N>;
            local-preference <N>;
            as-path [ <asn> ... ];
        }
    }

Note: This follows the same inline pattern for segment-list as the announce section,
      but uses the hierarchical braced format for the route itself.

Created by Manoharan Sundaramoorthy 2026-05-06.
"""

from __future__ import annotations

from exabgp.configuration.core import Section
from exabgp.bgp.message.update.attribute import Attributes
from exabgp.bgp.message.update.attribute.tunnel_encap import TunnelEncap
from exabgp.rib.change import Change
from exabgp.protocol.family import AFI
from exabgp.protocol.ip import IP

# Import SR-Policy TLV parsers
from exabgp.bgp.message.update.nlri.sr_policy import SRPolicyNLRI
from exabgp.bgp.message.update.attribute.tunnel_encap.sr_policy import (
    SRPolicyTunnel,
    PreferenceSubTLV,
    PrioritySubTLV,
    BindingSIDSubTLV,
    SRv6BindingSIDSubTLV,
    PolicyNameSubTLV,
    CandidatePathNameSubTLV,
    SegmentListSubTLV,
)
from exabgp.bgp.message.update.attribute.tunnel_encap.sr_policy.segment_list import (
    SegmentTypeA,
    SegmentTypeB,
    SegmentTypeC,
    SegmentTypeD,
    SegmentTypeE,
    SegmentTypeF,
    SegmentTypeG,
    SegmentTypeH,
    SegmentTypeI,
    SegmentTypeJ,
    SegmentTypeK,
    SRv6EndpointBehavior,
    WeightSubSubTLV,
)
from exabgp.configuration.static.sr_policy import _parse_segment_list
from exabgp.configuration.static.parser import (
    community,
    large_community,
    extended_community,
    origin,
    med,
    local_preference,
    as_path,
    atomic_aggregate,
    aggregator,
    originator_id,
    cluster_list,
    aigp,
)

_MPLS_LABEL_MAX = 1048575  # 2^20 - 1


# SR-Policy specific parsers
def sr_policy_next_hop(tokeniser):
    """Parse next-hop <IP>"""
    return IP.create(tokeniser())


def sr_policy_preference(tokeniser):
    """Parse preference <N>"""
    return PreferenceSubTLV(preference=int(tokeniser()))


def sr_policy_priority(tokeniser):
    """Parse priority <N>"""
    return PrioritySubTLV(priority=int(tokeniser()))


def sr_policy_binding_sid(tokeniser):
    """Parse binding-sid mpls <label> | binding-sid null"""
    bsid_type = tokeniser()
    if bsid_type == 'mpls':
        label = int(tokeniser())
        if label < 0 or label > 1048575:  # 2^20 - 1
            raise ValueError(f'MPLS label {label} out of range (0-1048575)')
        return BindingSIDSubTLV(label=label)
    elif bsid_type == 'null':
        return BindingSIDSubTLV(label=None)
    else:
        raise ValueError(f"Unknown binding-sid type '{bsid_type}'. Expected: mpls, null")


def sr_policy_srv6_binding_sid(tokeniser):
    """Parse srv6-binding-sid <IPv6>"""
    return SRv6BindingSIDSubTLV(sid=tokeniser())


def sr_policy_policy_name(tokeniser):
    """Parse policy-name "<string>" """
    name = tokeniser()
    return PolicyNameSubTLV(name=name.strip('"').strip("'"))


def sr_policy_candidate_path_name(tokeniser):
    """Parse candidate-path-name "<string>" """
    name = tokeniser()
    return CandidatePathNameSubTLV(name=name.strip('"').strip("'"))


def sr_policy_segment_list(tokeniser):
    """Parse segment-list weight <N> segment type-a mpls <label> ...

    This is for the inline style (used by sr_policy() function).
    """
    return _parse_segment_list(tokeniser)


# The actual function that will be registered with ParseStatic
def sr_policy(tokeniser):
    """Parse SR-Policy route from static section.

    Format: sr-policy distinguisher <N> color <N> endpoint <IP> { ... }

    Returns list of Change objects.
    """
    # Parse the SR-Policy NLRI header
    tokeniser.consume('distinguisher')
    distinguisher = int(tokeniser())
    tokeniser.consume('color')
    color = int(tokeniser())
    tokeniser.consume('endpoint')
    endpoint_str = tokeniser()

    # Determine AFI from endpoint IP
    endpoint_ip = IP.create(endpoint_str)
    afi = AFI.ipv4 if endpoint_ip.ipv4() else AFI.ipv6

    # Create SR-Policy NLRI
    nlri = SRPolicyNLRI.create(afi=afi, distinguisher=distinguisher, color=color, endpoint=endpoint_str)

    # Build attributes
    attributes = Attributes()

    # Lists to collect SR-Policy sub-TLVs
    subtlvs = []
    nexthop = None

    # Known commands map to parsers
    sr_policy_commands = {
        'next-hop': sr_policy_next_hop,
        'preference': sr_policy_preference,
        'priority': sr_policy_priority,
        'binding-sid': sr_policy_binding_sid,
        'srv6-binding-sid': sr_policy_srv6_binding_sid,
        'policy-name': sr_policy_policy_name,
        'candidate-path-name': sr_policy_candidate_path_name,
        'segment-list': sr_policy_segment_list,
        # Standard BGP attributes
        'community': community,
        'large-community': large_community,
        'extended-community': extended_community,
        'origin': origin,
        'med': med,
        'local-preference': local_preference,
        'as-path': as_path,
        'atomic-aggregate': atomic_aggregate,
        'aggregator': aggregator,
        'originator-id': originator_id,
        'cluster-list': cluster_list,
        'aigp': aigp,
    }

    # Parse the block content
    while True:
        command = tokeniser()

        if not command:
            break

        if command not in sr_policy_commands:
            raise ValueError(f'unknown SR-Policy command "{command}"')

        result = sr_policy_commands[command](tokeniser)

        # Handle different command types
        if command == 'next-hop':
            nexthop = result
        elif command in (
            'preference',
            'priority',
            'binding-sid',
            'srv6-binding-sid',
            'policy-name',
            'candidate-path-name',
            'segment-list',
        ):
            # SR-Policy sub-TLVs
            if isinstance(result, list):
                subtlvs.extend(result)
            else:
                subtlvs.append(result)
        else:
            # Standard BGP attributes
            attributes.add(result)

    # Validate required fields
    if nexthop is None:
        raise ValueError('SR-Policy route requires next-hop')

    nlri.nexthop = nexthop

    # Add tunnel encapsulation attribute if we have sub-TLVs
    if subtlvs:
        tunnel_encap = TunnelEncap(tunnel_tlvs=[SRPolicyTunnel(subtlvs=subtlvs)])
        attributes.add(tunnel_encap)

    # Create and return the change
    return [Change(nlri, attributes)]


# Parsers for segment-list { } subsection
def segment_weight(tokeniser):
    """Parse weight <N>"""
    return int(tokeniser())


def segment_type_a(tokeniser):
    """Parse segment type-a mpls <label>"""
    tokeniser()  # consume 'mpls'
    label = int(tokeniser())
    if label < 0 or label > _MPLS_LABEL_MAX:
        raise ValueError(f'MPLS label {label} out of range (0-{_MPLS_LABEL_MAX})')
    return SegmentTypeA(label=label)


def segment_type_b(tokeniser):
    """Parse segment type-b srv6 <SID> [endpoint-behavior <args>]"""
    tokeniser()  # consume 'srv6'
    sid = tokeniser()

    # Check for optional endpoint-behavior
    if tokeniser.peek() == 'endpoint-behavior':
        tokeniser()  # consume 'endpoint-behavior'
        behavior = int(tokeniser(), 0)  # allow 0x prefix
        lb = int(tokeniser())
        ln = int(tokeniser())
        fun = int(tokeniser())
        arg = int(tokeniser())
        eb = SRv6EndpointBehavior(
            endpoint_behavior=behavior,
            lb_length=lb,
            ln_length=ln,
            fun_length=fun,
            arg_length=arg,
        )
        return SegmentTypeB(sid=sid, endpoint_behavior=eb)

    return SegmentTypeB(sid=sid, endpoint_behavior=None)


def segment_type_c(tokeniser):
    """Parse segment type-c ipv4 <IPv4> algorithm <N> [sid <label>]"""
    tokeniser()  # consume 'ipv4'
    ipv4_node = tokeniser()
    tokeniser()  # consume 'algorithm'
    algorithm = int(tokeniser())

    # Check for optional sid
    sid = None
    if tokeniser.peek() == 'sid':
        tokeniser()  # consume 'sid'
        sid = int(tokeniser())
        if sid < 0 or sid > _MPLS_LABEL_MAX:
            raise ValueError(f'MPLS SID {sid} out of range (0-{_MPLS_LABEL_MAX})')

    # Set A-Flag if algorithm is provided (RFC 9831 Section 2.1)
    flags = 0x40 if algorithm != 0 else 0
    return SegmentTypeC(ipv4_node=ipv4_node, algorithm=algorithm, flags=flags, sid=sid)


def segment_type_d(tokeniser):
    """Parse segment type-d ipv6 <IPv6> algorithm <N> [sid <label>]"""
    tokeniser()  # consume 'ipv6'
    ipv6_node = tokeniser()
    tokeniser()  # consume 'algorithm'
    algorithm = int(tokeniser())

    # Check for optional sid
    sid = None
    if tokeniser.peek() == 'sid':
        tokeniser()  # consume 'sid'
        sid = int(tokeniser())

    # Set A-Flag if algorithm is provided (RFC 9831 Section 2.1)
    flags = 0x40 if algorithm != 0 else 0
    return SegmentTypeD(ipv6_node=ipv6_node, algorithm=algorithm, flags=flags, sid=sid)


def segment_type_e(tokeniser):
    """Parse segment type-e local-if-id <N> ipv4 <IPv4> [sid <label>]"""
    tokeniser()  # consume 'local-if-id'
    local_if_id = int(tokeniser())
    tokeniser()  # consume 'ipv4'
    ipv4_node = tokeniser()

    # Check for optional sid
    sid = None
    if tokeniser.peek() == 'sid':
        tokeniser()  # consume 'sid'
        sid = int(tokeniser())

    return SegmentTypeE(local_if_id=local_if_id, ipv4_node=ipv4_node, sid=sid)


def segment_type_f(tokeniser):
    """Parse segment type-f local <IPv4> remote <IPv4> [sid <label>]"""
    tokeniser()  # consume 'local'
    local_ipv4 = tokeniser()
    tokeniser()  # consume 'remote'
    remote_ipv4 = tokeniser()

    # Check for optional sid
    sid = None
    if tokeniser.peek() == 'sid':
        tokeniser()  # consume 'sid'
        sid = int(tokeniser())

    return SegmentTypeF(local_ipv4=local_ipv4, remote_ipv4=remote_ipv4, sid=sid)


def segment_type_g(tokeniser):
    """Parse segment type-g local-if-id <N> local-ipv6 <IPv6> remote-if-id <N> remote-ipv6 <IPv6> [sid <label>]"""
    tokeniser()  # consume 'local-if-id'
    local_if_id = int(tokeniser())
    tokeniser()  # consume 'local-ipv6'
    local_ipv6 = tokeniser()
    tokeniser()  # consume 'remote-if-id'
    remote_if_id = int(tokeniser())
    tokeniser()  # consume 'remote-ipv6'
    remote_ipv6 = tokeniser()

    # Check for optional sid
    sid = None
    if tokeniser.peek() == 'sid':
        tokeniser()  # consume 'sid'
        sid = int(tokeniser())

    return SegmentTypeG(
        local_if_id=local_if_id, local_ipv6=local_ipv6, remote_if_id=remote_if_id, remote_ipv6=remote_ipv6, sid=sid
    )


def segment_type_h(tokeniser):
    """Parse segment type-h local <IPv6> remote <IPv6> [sid <label>]"""
    tokeniser()  # consume 'local'
    local_ipv6 = tokeniser()
    tokeniser()  # consume 'remote'
    remote_ipv6 = tokeniser()

    # Check for optional sid
    sid = None
    if tokeniser.peek() == 'sid':
        tokeniser()  # consume 'sid'
        sid = int(tokeniser())

    return SegmentTypeH(local_ipv6=local_ipv6, remote_ipv6=remote_ipv6, sid=sid)


def segment_type_i(tokeniser):
    """Parse segment type-i ipv6 <IPv6> algorithm <N> [sid <IPv6>] [endpoint-behavior <args>]"""
    tokeniser()  # consume 'ipv6'
    ipv6_node = tokeniser()
    tokeniser()  # consume 'algorithm'
    algorithm = int(tokeniser())

    # Check for optional sid
    sid = None
    if tokeniser.peek() == 'sid':
        tokeniser()  # consume 'sid'
        sid = tokeniser()

    # Check for optional endpoint-behavior
    eb: SRv6EndpointBehavior | None = None
    if tokeniser.peek() == 'endpoint-behavior':
        tokeniser()  # consume 'endpoint-behavior'
        behavior = int(tokeniser(), 0)  # allow 0x prefix
        lb = int(tokeniser())
        ln = int(tokeniser())
        fun = int(tokeniser())
        arg = int(tokeniser())
        eb = SRv6EndpointBehavior(
            endpoint_behavior=behavior,
            lb_length=lb,
            ln_length=ln,
            fun_length=fun,
            arg_length=arg,
        )

    # Set A-Flag if algorithm is provided, B-Flag if endpoint behavior is provided
    flags = 0
    if algorithm != 0:
        flags |= 0x40  # A-Flag
    if eb is not None:
        flags |= 0x10  # B-Flag

    return SegmentTypeI(ipv6_node=ipv6_node, algorithm=algorithm, flags=flags, sid=sid, endpoint_behavior=eb)


def segment_type_j(tokeniser):
    """Parse segment type-j local-if-id <N> local-ipv6 <IPv6> remote-if-id <N> remote-ipv6 <IPv6> algorithm <N> [sid <IPv6>] [endpoint-behavior <args>]"""
    tokeniser()  # consume 'local-if-id'
    local_if_id = int(tokeniser())
    tokeniser()  # consume 'local-ipv6'
    local_ipv6 = tokeniser()
    tokeniser()  # consume 'remote-if-id'
    remote_if_id = int(tokeniser())
    tokeniser()  # consume 'remote-ipv6'
    remote_ipv6 = tokeniser()
    tokeniser()  # consume 'algorithm'
    algorithm = int(tokeniser())

    # Check for optional sid
    sid = None
    if tokeniser.peek() == 'sid':
        tokeniser()  # consume 'sid'
        sid = tokeniser()

    # Check for optional endpoint-behavior
    eb: SRv6EndpointBehavior | None = None
    if tokeniser.peek() == 'endpoint-behavior':
        tokeniser()  # consume 'endpoint-behavior'
        behavior = int(tokeniser(), 0)  # allow 0x prefix
        lb = int(tokeniser())
        ln = int(tokeniser())
        fun = int(tokeniser())
        arg = int(tokeniser())
        eb = SRv6EndpointBehavior(
            endpoint_behavior=behavior,
            lb_length=lb,
            ln_length=ln,
            fun_length=fun,
            arg_length=arg,
        )

    # Set A-Flag if algorithm is provided, B-Flag if endpoint behavior is provided
    flags = 0
    if algorithm != 0:
        flags |= 0x40  # A-Flag
    if eb is not None:
        flags |= 0x10  # B-Flag

    return SegmentTypeJ(
        local_if_id=local_if_id,
        local_ipv6=local_ipv6,
        remote_if_id=remote_if_id,
        remote_ipv6=remote_ipv6,
        algorithm=algorithm,
        flags=flags,
        sid=sid,
        endpoint_behavior=eb,
    )


def segment_type_k(tokeniser):
    """Parse segment type-k local <IPv6> remote <IPv6> algorithm <N> [sid <IPv6>] [endpoint-behavior <args>]"""
    tokeniser()  # consume 'local'
    local_ipv6 = tokeniser()
    tokeniser()  # consume 'remote'
    remote_ipv6 = tokeniser()
    tokeniser()  # consume 'algorithm'
    algorithm = int(tokeniser())

    # Check for optional sid
    sid = None
    if tokeniser.peek() == 'sid':
        tokeniser()  # consume 'sid'
        sid = tokeniser()

    # Check for optional endpoint-behavior
    eb: SRv6EndpointBehavior | None = None
    if tokeniser.peek() == 'endpoint-behavior':
        tokeniser()  # consume 'endpoint-behavior'
        behavior = int(tokeniser(), 0)  # allow 0x prefix
        lb = int(tokeniser())
        ln = int(tokeniser())
        fun = int(tokeniser())
        arg = int(tokeniser())
        eb = SRv6EndpointBehavior(
            endpoint_behavior=behavior,
            lb_length=lb,
            ln_length=ln,
            fun_length=fun,
            arg_length=arg,
        )

    # Set A-Flag if algorithm is provided, B-Flag if endpoint behavior is provided
    flags = 0
    if algorithm != 0:
        flags |= 0x40  # A-Flag
    if eb is not None:
        flags |= 0x10  # B-Flag

    return SegmentTypeK(
        local_ipv6=local_ipv6, remote_ipv6=remote_ipv6, algorithm=algorithm, flags=flags, sid=sid, endpoint_behavior=eb
    )


# Section class for segment-list { } subsection
class ParseSegmentList(Section):
    """Section parser for segment-list with hierarchical syntax.

    Handles: segment-list weight <N> { segment type-a mpls <label>; ... }
    """

    definition = [
        'weight <N>',
        'segment type-a mpls <label>',
        'segment type-b srv6 <SID> [endpoint-behavior <behavior> <lb> <ln> <fun> <arg>]',
        'segment type-c ipv4 <IPv4> algorithm <N> [sid <label>]',
        'segment type-d ipv6 <IPv6> algorithm <N> [sid <label>]',
        'segment type-e local-if-id <N> ipv4 <IPv4> [sid <label>]',
        'segment type-f local <IPv4> remote <IPv4> [sid <label>]',
        'segment type-g local-if-id <N> local-ipv6 <IPv6> remote-if-id <N> remote-ipv6 <IPv6> [sid <label>]',
        'segment type-h local <IPv6> remote <IPv6> [sid <label>]',
        'segment type-i ipv6 <IPv6> algorithm <N> [sid <IPv6>] [endpoint-behavior <behavior> <lb> <ln> <fun> <arg>]',
        'segment type-j local-if-id <N> local-ipv6 <IPv6> remote-if-id <N> remote-ipv6 <IPv6> algorithm <N> [sid <IPv6>] [endpoint-behavior <behavior> <lb> <ln> <fun> <arg>]',
        'segment type-k local <IPv6> remote <IPv6> algorithm <N> [sid <IPv6>] [endpoint-behavior <behavior> <lb> <ln> <fun> <arg>]',
    ]

    syntax = 'segment-list weight <N> {{\n  {}\n}}'.format(' ;\n  '.join(definition))

    known = {
        'weight': segment_weight,
        'segment': None,  # Will be handled specially in parse()
    }

    action = {
        'weight': 'set-weight',
        'segment': 'add-segment',
    }

    name = 'static/sr-policy/route/segment-list'

    def __init__(self, tokeniser, scope, error):
        Section.__init__(self, tokeniser, scope, error)
        self._weight = None
        self._segments = []

    def clear(self):
        self._weight = None
        self._segments = []

    def pre(self):
        # Parse weight <N>
        token = self.tokeniser.iterate()
        if token != 'weight':
            return self.error.set(f"Expected 'weight', got '{token}'")
        self._weight = int(self.tokeniser.iterate())
        return True

    def parse(self, name, command):
        """Override parse to handle segment type-a/type-b/type-c/type-d/type-e/type-f/type-g/type-h/type-i/type-j/type-k."""
        if command == 'segment':
            # Parse: segment type-a/type-b/type-c/type-d/type-e/type-f/type-g/type-h/type-i/type-j/type-k ...
            seg_type = self.tokeniser.iterate()
            if seg_type == 'type-a':
                segment = segment_type_a(self.tokeniser.iterate)
                self._segments.append(segment)
            elif seg_type == 'type-b':
                segment = segment_type_b(self.tokeniser.iterate)
                self._segments.append(segment)
            elif seg_type == 'type-c':
                segment = segment_type_c(self.tokeniser.iterate)
                self._segments.append(segment)
            elif seg_type == 'type-d':
                segment = segment_type_d(self.tokeniser.iterate)
                self._segments.append(segment)
            elif seg_type == 'type-e':
                segment = segment_type_e(self.tokeniser.iterate)
                self._segments.append(segment)
            elif seg_type == 'type-f':
                segment = segment_type_f(self.tokeniser.iterate)
                self._segments.append(segment)
            elif seg_type == 'type-g':
                segment = segment_type_g(self.tokeniser.iterate)
                self._segments.append(segment)
            elif seg_type == 'type-h':
                segment = segment_type_h(self.tokeniser.iterate)
                self._segments.append(segment)
            elif seg_type == 'type-i':
                segment = segment_type_i(self.tokeniser.iterate)
                self._segments.append(segment)
            elif seg_type == 'type-j':
                segment = segment_type_j(self.tokeniser.iterate)
                self._segments.append(segment)
            elif seg_type == 'type-k':
                segment = segment_type_k(self.tokeniser.iterate)
                self._segments.append(segment)
            else:
                return self.error.set(
                    f"Unknown segment type '{seg_type}'. Expected: type-a, type-b, type-c, type-f, type-g, type-h, type-i, type-j, type-k"
                )
            return True
        else:
            return self.error.set(f'unknown command "{command}" in segment-list')

    def post(self):
        # Create SegmentListSubTLV and store in parent scope
        weight_subtlv = WeightSubSubTLV(weight=self._weight)
        segment_list = SegmentListSubTLV(weight=weight_subtlv, segments=self._segments)

        # Add to parent's segment lists
        self.scope.extend('segment-lists', [segment_list])

        return True


# Section class for hierarchical sr-policy configuration
class ParseStaticSRPolicyRoute(Section):
    """Section parser for SR-Policy routes with brace syntax.

    Handles: sr-policy distinguisher <N> color <N> endpoint <IP> { ... }
    """

    definition = [
        'next-hop <ip>',
        'preference <N>',
        'priority <N>',
        'binding-sid mpls <label> | binding-sid null',
        'srv6-binding-sid <ipv6>',
        'policy-name "<string>"',
        'candidate-path-name "<string>"',
        'segment-list weight <N> { segment type-a mpls <label>; ... }',
        'community [ <value> ... ]',
        'large-community [ <value> ... ]',
        'extended-community [ <value> ... ]',
        'origin IGP|EGP|INCOMPLETE',
        'med <N>',
        'local-preference <N>',
        'as-path [ <asn> ... ]',
        'atomic-aggregate',
        'aggregator <asn>:<ip>',
        'originator-id <ipv4>',
        'cluster-list <ipv4>',
        'aigp <N>',
    ]

    syntax = 'sr-policy distinguisher <N> color <N> endpoint <IP> {{\n  {}\n}}'.format(' ;\n  '.join(definition))

    # Known parsers for SR-Policy specific and BGP attributes
    known = {
        'next-hop': sr_policy_next_hop,
        'preference': sr_policy_preference,
        'priority': sr_policy_priority,
        'binding-sid': sr_policy_binding_sid,
        'srv6-binding-sid': sr_policy_srv6_binding_sid,
        'policy-name': sr_policy_policy_name,
        'candidate-path-name': sr_policy_candidate_path_name,
        # Standard BGP attributes
        'community': community,
        'large-community': large_community,
        'extended-community': extended_community,
        'origin': origin,
        'med': med,
        'local-preference': local_preference,
        'as-path': as_path,
        'atomic-aggregate': atomic_aggregate,
        'aggregator': aggregator,
        'originator-id': originator_id,
        'cluster-list': cluster_list,
        'aigp': aigp,
    }

    action = {
        'next-hop': 'sr-policy-nexthop',
        'preference': 'sr-policy-subtlv',
        'priority': 'sr-policy-subtlv',
        'binding-sid': 'sr-policy-subtlv',
        'srv6-binding-sid': 'sr-policy-subtlv',
        'policy-name': 'sr-policy-subtlv',
        'candidate-path-name': 'sr-policy-subtlv',
        # Standard BGP attributes
        'community': 'attribute-add',
        'large-community': 'attribute-add',
        'extended-community': 'attribute-add',
        'origin': 'attribute-add',
        'med': 'attribute-add',
        'local-preference': 'attribute-add',
        'as-path': 'attribute-add',
        'atomic-aggregate': 'attribute-add',
        'aggregator': 'attribute-add',
        'originator-id': 'attribute-add',
        'cluster-list': 'attribute-add',
        'aigp': 'attribute-add',
    }

    name = 'static/sr-policy/route'

    def __init__(self, tokeniser, scope, error):
        Section.__init__(self, tokeniser, scope, error)
        self._nlri = None
        self._nexthop = None
        self._subtlvs = []
        self._attributes = []

    def clear(self):
        self._nlri = None
        self._nexthop = None
        self._subtlvs = []
        self._attributes = []

    def pre(self):
        # Parse the SR-Policy NLRI header: distinguisher <N> color <N> endpoint <IP>
        # The tokeniser has already consumed 'sr-policy', so we start with 'distinguisher'
        token = self.tokeniser.iterate()
        if token != 'distinguisher':
            return self.error.set(f"Expected 'distinguisher', got '{token}'")
        distinguisher = int(self.tokeniser.iterate())

        token = self.tokeniser.iterate()
        if token != 'color':
            return self.error.set(f"Expected 'color', got '{token}'")
        color = int(self.tokeniser.iterate())

        token = self.tokeniser.iterate()
        if token != 'endpoint':
            return self.error.set(f"Expected 'endpoint', got '{token}'")
        endpoint_str = self.tokeniser.iterate()

        # Determine AFI from endpoint IP
        endpoint_ip = IP.create(endpoint_str)
        afi = AFI.ipv4 if endpoint_ip.ipv4() else AFI.ipv6

        # Create SR-Policy NLRI
        self._nlri = SRPolicyNLRI.create(afi=afi, distinguisher=distinguisher, color=color, endpoint=endpoint_str)

        return True

    def parse(self, name, command):
        """Override parse to handle SR-Policy specific actions."""
        identifier = command if command in self.known else (self.name, command)
        if identifier not in self.known:
            options = ', '.join([str(_) for _ in self.known])
            return self.error.set(f'unknown command {command} options are {options}')

        try:
            # Call the parser function
            result = self.known[identifier](self.tokeniser.iterate)

            # Handle the result based on action type
            action = self.action.get(identifier, '')

            if action == 'sr-policy-nexthop':
                self._nexthop = result
            elif action == 'sr-policy-subtlv':
                self._subtlvs.append(result)
            elif action == 'attribute-add':
                self._attributes.append(result)
            else:
                return self.error.set(f'unknown action {action} for command {command}')

            return True
        except (ValueError, IndexError) as exc:
            if self.error.debug:
                raise
            return self.error.set(str(exc))
        except Exception:
            return self.error.set(f'could not parse command {command}')

    def post(self):
        # Validate required fields
        if self._nexthop is None:
            return self.error.set('SR-Policy route requires next-hop')

        self._nlri.nexthop = self._nexthop

        # Collect segment-lists from subsections (added by ParseSegmentList.post())
        segment_lists = self.scope.pop('segment-lists', [])

        # Combine all sub-TLVs
        all_subtlvs = self._subtlvs + segment_lists

        # Build attributes
        attributes = Attributes()

        # Add tunnel encapsulation attribute if we have sub-TLVs
        if all_subtlvs:
            tunnel_encap = TunnelEncap(tunnel_tlvs=[SRPolicyTunnel(subtlvs=all_subtlvs)])
            attributes.add(tunnel_encap)

        # Add standard BGP attributes
        for attr in self._attributes:
            attributes.add(attr)

        # Create the change and add to routes
        change = Change(self._nlri, attributes)
        self.scope.append_route(change)

        return True
