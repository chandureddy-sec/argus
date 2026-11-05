"""AED (Argus Endpoint Detection) — separate experimental lab track.

Isolated from the product: nothing here is imported by ``threatlens.api.app``
and the gateway runs as its own ASGI app/process (default :8443), disabled
until explicitly enabled. Lab use only; see
``.gstack/projects/chandureddy-sec-argus/aed/phase-1-design.md``.
"""
