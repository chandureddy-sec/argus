"""Knowledge base (Phase 2): ATT&CK, vulnerability intelligence and the
relationship graph. Importing this package registers its sources."""

from threatlens.kb import attack as attack
from threatlens.kb import epss as epss
from threatlens.kb import nvd as nvd
from threatlens.kb import osv as osv
from threatlens.kb.base import KB_REGISTRY as KB_REGISTRY
