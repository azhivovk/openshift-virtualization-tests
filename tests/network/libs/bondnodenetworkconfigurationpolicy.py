from dataclasses import dataclass
from typing import Any

from kubernetes.dynamic import DynamicClient
from timeout_sampler import retry

from tests.network.libs.nodenetworkconfigurationpolicy import (
    DesiredState,
    Interface,
    IPv4,
    IPv6,
    NodeNetworkConfigurationPolicy,
)
from utilities.constants import ACTIVE_BACKUP
from utilities.network import BOND

LINK_AGGREGATION_ATTR = "link_aggregation"


@dataclass
class LinkAggregationOptions:
    miimon: str
    primary: str | None = None


@dataclass
class LinkAggregation:
    mode: str
    port: list[str]
    options: LinkAggregationOptions


@dataclass
class BondInterface:
    name: str
    type: str
    state: str
    link_aggregation: LinkAggregation
    mtu: int | None = None
    ipv4: IPv4 | None = None
    ipv6: IPv6 | None = None


def create_bond_desired_state(
    bond_name: str,
    bond_ports: list[str],
    mode: str = ACTIVE_BACKUP,
    mtu: int | None = None,
    primary_bond_port: str | None = None,
    ipv4_enable: bool = False,
    ipv4_dhcp: bool = False,
    ipv6_enable: bool = False,
    bond_options: dict | None = None,
) -> DesiredState:
    """Creates a DesiredState for bond interface configuration.

    Args:
        bond_name: Name of the bond interface.
        bond_ports: List of port names to aggregate.
        mode: Bond mode. Defaults to ACTIVE_BACKUP.
        mtu: MTU for the bond and port interfaces.
        primary_bond_port: Primary port for active-backup mode.
        ipv4_enable: Enable IPv4 on the bond.
        ipv4_dhcp: Enable IPv4 DHCP on the bond.
        ipv6_enable: Enable IPv6 on the bond.
        bond_options: Additional bond options.

    Returns:
        DesiredState: The desired state configuration for the bond.
    """
    options_dict = {"miimon": "120"}
    if bond_options:
        options_dict.update(bond_options)
    if mode == ACTIVE_BACKUP and primary_bond_port is not None:
        options_dict["primary"] = primary_bond_port

    link_aggregation = LinkAggregation(
        mode=mode,
        port=bond_ports,
        options=LinkAggregationOptions(
            miimon=options_dict["miimon"],
            primary=options_dict.get("primary"),
        ),
    )

    bond_interface = BondInterface(
        name=bond_name,
        type=BOND,
        state=NodeNetworkConfigurationPolicy.Interface.State.UP,
        link_aggregation=link_aggregation,
        mtu=mtu,
        ipv4=IPv4(enabled=ipv4_enable, dhcp=ipv4_dhcp) if ipv4_enable or ipv4_dhcp else None,
        ipv6=IPv6(enabled=ipv6_enable) if ipv6_enable else None,
    )

    port_interfaces = [
        Interface(
            name=port,
            type="ethernet",
            state=NodeNetworkConfigurationPolicy.Interface.State.UP,
            mtu=mtu,
        )
        for port in bond_ports
    ]

    return DesiredState(interfaces=[bond_interface] + port_interfaces)  # type: ignore[arg-type]


class BondNodeNetworkConfigurationPolicy(NodeNetworkConfigurationPolicy):
    """
    NodeNetworkConfigurationPolicy for bond interface configuration.
    """

    def __init__(
        self,
        client: DynamicClient,
        name: str,
        bond_name: str,
        desired_state: DesiredState,
        node_selector: dict[str, str] | None = None,
        bond_ports: list[str] | None = None,
        mode: str | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Create and manage Bond NodeNetworkConfigurationPolicy

        Args:
            client: Dynamic client used to interact with the cluster.
            name: Name of the NodeNetworkConfigurationPolicy object.
            bond_name: Name of the bond interface.
            desired_state: Desired policy configuration for the bond.
            node_selector: Node selector to apply the policy to.
            bond_ports: Bond ports (extracted from desired_state if not provided).
            mode: Bond mode (extracted from desired_state if not provided).
            **kwargs: Additional arguments passed to the parent class.
        """
        self.bond_name = bond_name
        self.bond_ports = bond_ports if bond_ports is not None else self._extract_bond_ports(desired_state, bond_name)
        self.mode = mode if mode is not None else self._extract_bond_mode(desired_state, bond_name)

        super().__init__(
            client=client,
            name=name,
            desired_state=desired_state,
            node_selector=node_selector,
            **kwargs,
        )

    @staticmethod
    def _extract_bond_ports(desired_state: DesiredState, bond_name: str) -> list[str]:
        for iface in desired_state.interfaces or []:
            if iface.name == bond_name and hasattr(iface, LINK_AGGREGATION_ATTR):
                return iface.link_aggregation.port  # type: ignore[attr-defined]
        return []

    @staticmethod
    def _extract_bond_mode(desired_state: DesiredState, bond_name: str) -> str:
        for iface in desired_state.interfaces or []:
            if iface.name == bond_name and hasattr(iface, LINK_AGGREGATION_ATTR):
                return iface.link_aggregation.mode  # type: ignore[attr-defined]
        return ""

    @retry(wait_timeout=300, sleep=5)
    def _wait_for_nncp_status_update(self, initial_transition_time: str) -> bool:
        for condition in self.instance.get("status", {}).get("conditions", []):
            if (
                condition.get("type") == self.Conditions.Type.AVAILABLE
                and condition.get("reason") == self.Conditions.Reason.SUCCESSFULLY_CONFIGURED
            ):
                current_ifaces = self.instance.get("status", {}).get("currentState", {}).get("interfaces", [])
                bond_iface = next(
                    (current_iface for current_iface in current_ifaces if current_iface["name"] == self.bond_name), None
                )
                if not bond_iface or bond_iface.get("state") == self.Interface.State.ABSENT:
                    return True
        return False
