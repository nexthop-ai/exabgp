"""announce/sr_policy.py

SR Policy route announcement handler (RFC 9830).

Registers handlers for:
  ipv4 sr-policy
  ipv6 sr-policy

Supports standard BGP path attributes:
  - community
  - large-community
  - extended-community
  - origin
  - med
  - local-preference
  - as-path
  - etc.

Created by Manoharan Sundaramoorthy 2026-05-01.
"""

from __future__ import annotations

from exabgp.bgp.message.update.attribute import Attributes
from exabgp.protocol.family import AFI
from exabgp.rib.change import Change

from exabgp.configuration.announce import ParseAnnounce
from exabgp.configuration.static.sr_policy import sr_policy_route

# Import attribute parsers from static.parser
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


# Known attribute parsers for SR-Policy
_SR_POLICY_ATTRIBUTES = {
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


def _build_sr_policy_route(tokeniser, afi: AFI) -> list[Change]:
    """Build SR-Policy route with attributes.

    Parses SR-Policy specific configuration (distinguisher, color, endpoint, etc.)
    and then parses any additional BGP path attributes (community, origin, etc.).
    """
    nlri, nexthop, tunnel_encap = sr_policy_route(tokeniser, afi)
    nlri.nexthop = nexthop
    attributes = Attributes()

    # Add tunnel encapsulation attribute (contains SR-Policy details)
    if tunnel_encap is not None:
        attributes.add(tunnel_encap)

    # Parse additional BGP path attributes
    while True:
        command = tokeniser()

        if not command:
            break

        # Check if this is a known attribute
        if command in _SR_POLICY_ATTRIBUTES:
            attribute = _SR_POLICY_ATTRIBUTES[command](tokeniser)
            attributes.add(attribute)
        else:
            raise ValueError(f'unknown SR-Policy attribute "{command}"')

    return [Change(nlri, attributes)]


@ParseAnnounce.register('sr-policy', 'extend-name', 'ipv4')
def sr_policy_ipv4(tokeniser):
    return _build_sr_policy_route(tokeniser, AFI.ipv4)


@ParseAnnounce.register('sr-policy', 'extend-name', 'ipv6')
def sr_policy_ipv6(tokeniser):
    return _build_sr_policy_route(tokeniser, AFI.ipv6)
