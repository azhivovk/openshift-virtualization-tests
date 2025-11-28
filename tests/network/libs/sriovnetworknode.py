import logging

from kubernetes.dynamic import DynamicClient
from ocp_resources.node import Node
from ocp_resources.sriov_network_node_policy import SriovNetworkNodePolicy
from ocp_resources.sriov_network_node_state import SriovNetworkNodeState
from timeout_sampler import TimeoutExpiredError, retry

from utilities.exceptions import ResourceMismatch

LOGGER = logging.getLogger(__name__)


def wait_for_ready_sriov_nodes(
    snns_list: list[SriovNetworkNodeState],
    client: DynamicClient,
    policy: SriovNetworkNodePolicy | None = None,
    nic_selector: dict[str, list[str]] | None = None,
) -> None:
    """
    Wait for SR-IOV nodes to be ready and verify interface configuration.

    Usage:
    1. Policy creation: Waits for SUCCEEDED status and verifies config matches policy.
    2. Policy teardown: Verifies VFs are removed from specified interfaces.

    Args:
        snns_list: List of SriovNetworkNodeState objects.
        client: client for Node access.
        policy: SriovNetworkNodePolicy for verification. None during teardown.
        nic_selector: NIC selector dict with pfNames/rootDevices for teardown verification.

    Raises:
        TimeoutExpiredError: If sync status doesn't reach SUCCEEDED or verification times out.
    """
    for sriov_node_network_state in snns_list:
        try:
            _check_sriov_node_ready_and_configured(
                sriov_node_network_state=sriov_node_network_state,
                policy=policy,
                client=client,
                nic_selector=nic_selector,
            )
        except TimeoutExpiredError:
            current_status = sriov_node_network_state.instance.status.syncStatus
            if current_status == SriovNetworkNodePolicy.Status.SUCCEEDED:
                LOGGER.error(
                    f"Timeout waiting for SR-IOV configuration to match policy on node {sriov_node_network_state.name}"
                )
            else:
                LOGGER.error(
                    f"Timeout waiting for node {sriov_node_network_state.name} "
                    f"SriovNetworkNodeState to reach SUCCEEDED status. "
                    f"Current status: {current_status}"
                )
            raise


@retry(wait_timeout=1000, sleep=5, exceptions_dict={ResourceMismatch: []})
def _check_sriov_node_ready_and_configured(
    sriov_node_network_state: SriovNetworkNodeState,
    client: DynamicClient,
    nic_selector: dict[str, list[str]],
    policy: SriovNetworkNodePolicy | None = None,
) -> bool:
    if sriov_node_network_state.instance.status.syncStatus != SriovNetworkNodePolicy.Status.SUCCEEDED:
        return False

    if policy:
        _verify_sriov_setup_config(
            sriov_node_network_state=sriov_node_network_state,
            client=client,
            policy=policy,
        )
    else:
        _verify_sriov_teardown_config(
            sriov_node_network_state=sriov_node_network_state,
            nic_selector=nic_selector,
        )

    return True


def _verify_sriov_setup_config(
    sriov_node_network_state: SriovNetworkNodeState,
    client: DynamicClient,
    policy: SriovNetworkNodePolicy,
) -> None:
    node = Node(client=client, name=sriov_node_network_state.name)

    if not _node_matches_policy_selector(node=node, policy=policy):
        LOGGER.info(f"Skipping verification for node {node.name} - does not match policy {policy.name} nodeSelector")
        return

    policy_spec = policy.instance.spec
    pf_names = policy_spec.nicSelector.get("pfNames", [])
    root_devices = policy_spec.nicSelector.get("rootDevices", [])
    expected_num_vfs = policy_spec.numVfs
    expected_mtu = policy_spec.get("mtu")

    matching_interfaces = []
    for iface in sriov_node_network_state.instance.status.interfaces:
        if iface.name in pf_names or iface.pciAddress in root_devices:
            matching_interfaces.append(iface)

    if not matching_interfaces:
        raise ResourceMismatch(
            f"Node {sriov_node_network_state.name} matches policy {policy.name} nodeSelector "
            f"but has no interfaces matching pfNames={pf_names}, rootDevices={root_devices})."
        )

    for iface in matching_interfaces:
        if iface.numVfs != expected_num_vfs:
            raise ResourceMismatch(
                f"SR-IOV interface {iface.name} on node {sriov_node_network_state.name}: "
                f"numVfs mismatch - got {iface.numVfs}, expected {expected_num_vfs}"
            )

        if expected_mtu:
            iface_mtu = getattr(iface, "mtu", None)
            if iface_mtu and iface_mtu != expected_mtu:
                raise ResourceMismatch(
                    f"SR-IOV interface {iface.name} on node {sriov_node_network_state.name}: "
                    f"MTU mismatch - got {iface_mtu}, expected {expected_mtu}"
                )

        LOGGER.info(f"Interface {iface.name} configuration verified successfully")


def _verify_sriov_teardown_config(
    sriov_node_network_state: SriovNetworkNodeState,
    nic_selector: dict[str, list[str]],
) -> None:
    pf_names = nic_selector.get("pfNames", [])
    root_devices = nic_selector.get("rootDevices", [])

    for iface in sriov_node_network_state.instance.status.interfaces:
        if iface.name in pf_names or iface.pciAddress in root_devices:
            if iface.numVfs:
                raise ResourceMismatch(
                    f"SR-IOV interface {iface.name} on node {sriov_node_network_state.name} still has "
                    f"numVfs={iface.numVfs} after policy deletion. Expected numVfs=0 or None"
                )
            LOGGER.info(f"Interface {iface.name} teardown verified successfully")


def _node_matches_policy_selector(node: Node, policy: SriovNetworkNodePolicy) -> bool:
    node_labels = node.instance.metadata.labels
    for key, value in policy.instance.spec.nodeSelector.items():
        if (node_value := node_labels.get(key)) != value:
            LOGGER.info(f"Node {node.name} does not match nodeSelector: {key}={value} (node has {key}={node_value})")
            return False

    return True
