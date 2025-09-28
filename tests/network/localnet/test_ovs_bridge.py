import pytest

from libs.net.traffic_generator import is_tcp_connection
from libs.net.vmspec import lookup_iface_status
from tests.network.localnet.liblocalnet import (
    LINK_STATE_UP,
    LOCALNET_OVS_BRIDGE_NETWORK,
    client_server_active_connection,
)
from utilities.network import get_vmi_ip_v4_by_name
from utilities.virt import migrate_vm_and_verify, vm_console_run_commands


@pytest.mark.ipv4
@pytest.mark.s390x
@pytest.mark.usefixtures("nncp_localnet_on_secondary_node_nic")
@pytest.mark.polarion("CNV-11905")
def test_connectivity_over_migration_between_ovs_bridge_localnet_vms(
    localnet_ovs_bridge_server, localnet_ovs_bridge_client
):
    migrate_vm_and_verify(vm=localnet_ovs_bridge_client.vm)
    assert is_tcp_connection(server=localnet_ovs_bridge_server, client=localnet_ovs_bridge_client)


@pytest.mark.ipv4
@pytest.mark.usefixtures("nncp_localnet_on_secondary_node_nic")
@pytest.mark.polarion("CNV-12006")
def test_connectivity_after_interface_state_change_in_ovs_bridge_localnet_vms(
    ovs_bridge_localnet_running_vms_one_with_interface_down,
):
    (vm1_with_initial_link_down, vm2) = ovs_bridge_localnet_running_vms_one_with_interface_down
    vm1_with_initial_link_down.set_interface_state(network_name=LOCALNET_OVS_BRIDGE_NETWORK, state=LINK_STATE_UP)

    lookup_iface_status(
        vm=vm1_with_initial_link_down,
        iface_name=LOCALNET_OVS_BRIDGE_NETWORK,
        predicate=lambda interface: "guest-agent" in interface["infoSource"]
        and interface["linkState"] == LINK_STATE_UP,
    )

    with client_server_active_connection(
        client_vm=vm2,
        server_vm=vm1_with_initial_link_down,
        spec_logical_network=LOCALNET_OVS_BRIDGE_NETWORK,
        port=8888,
    ) as (client, server):
        assert is_tcp_connection(server=server, client=client)


@pytest.mark.polarion("CNV-12349")
@pytest.mark.usefixtures("nncp_localnet_on_secondary_node_nic_config_mtu")
def test_tcp_connectivity_ovs_bridge_jumbo_frames_no_fragmentation(
    cudn_localnet_ovs_bridge_jumbo_frame,
    ovs_bridge_localnet_running_jumbo_frame_vms,
    localnet_ovs_bridge_jumbo_frame_server,
    localnet_ovs_bridge_jumbo_frame_client,
    cluster_hardware_mtu,
):
    icmp_header = 8
    ip_header = 20
    ping_packet_size = cluster_hardware_mtu - icmp_header - ip_header
    vm1, vm2 = ovs_bridge_localnet_running_jumbo_frame_vms
    dst_ip = get_vmi_ip_v4_by_name(vm=vm2, name=cudn_localnet_ovs_bridge_jumbo_frame.name)
    ping_cmd_jumbo_frame_no_fragmentation = f"ping -q -c 3 {dst_ip} -s {ping_packet_size} -M do"
    vm_console_run_commands(vm=vm1, commands=[ping_cmd_jumbo_frame_no_fragmentation])

    assert is_tcp_connection(
        server=localnet_ovs_bridge_jumbo_frame_server, client=localnet_ovs_bridge_jumbo_frame_client
    )
