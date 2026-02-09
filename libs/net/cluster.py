import ipaddress
import logging
from functools import cache

from ocp_resources.network_config_openshift_io import Network
from ocp_resources.resource import get_client

from utilities.constants import CLUSTER

LOGGER = logging.getLogger(__name__)


@cache
def is_ipv6_single_stack_cluster() -> bool:
    """
    Detect if the cluster is IPv6 single-stack.

    Returns:
        bool: True if cluster is IPv6 single-stack, False otherwise
    """
    service_network = Network(client=get_client(), name=CLUSTER).instance.status.serviceNetwork
    if not service_network:
        return False

    ipv4_supported = any(ipaddress.ip_network(ip).version == 4 for ip in service_network)
    ipv6_supported = any(ipaddress.ip_network(ip).version == 6 for ip in service_network)

    is_ipv6_only = ipv6_supported and not ipv4_supported
    LOGGER.info(f"Cluster network detection: IPv4={ipv4_supported}, IPv6={ipv6_supported}, IPv6-only={is_ipv6_only}")
    return is_ipv6_only
