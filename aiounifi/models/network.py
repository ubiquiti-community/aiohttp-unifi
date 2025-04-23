"""UniFi Network data model.

This module provides data classes and methods for interacting with UniFi Networks.
"""

from dataclasses import dataclass, field
try:
    from typing import Self, NotRequired, TypedDict, Dict, Any, List, Optional, Union
except ImportError:
    from typing_extensions import Self, NotRequired, TypedDict
    from typing import Dict, Any, List, Optional, Union

from .api import ApiItem, ApiRequest


class TypedNATOutboundIPAddresses(TypedDict):
    """NAT outbound IP addresses type definition."""

    ip_address: str
    ip_address_pool: NotRequired[List[str]]  # List of IP addresses or IP ranges
    mode: NotRequired[str]  # all|ip_address|ip_address_pool
    wan_network_group: NotRequired[str]  # WAN|WAN2


class TypedWANDHCPOptions(TypedDict):
    """WAN DHCP options type definition."""

    optionNumber: str  # Option number as string (handles empty strings)
    value: NotRequired[str]


class TypedWANProviderCapabilities(TypedDict):
    """WAN provider capabilities type definition."""

    download_kilobits_per_second: NotRequired[str]  # Int as string (handles empty strings)
    upload_kilobits_per_second: NotRequired[str]  # Int as string (handles empty strings)


class TypedNetwork(TypedDict):
    """Network configuration type definition."""

    _id: str
    site_id: str
    
    # Hidden attributes
    attr_hidden: NotRequired[bool]
    attr_hidden_id: NotRequired[str]
    attr_no_delete: NotRequired[bool]
    attr_no_edit: NotRequired[bool]
    
    # Network configuration
    auto_scale_enabled: NotRequired[bool]
    dhcpd_boot_enabled: NotRequired[bool]
    dhcpd_boot_filename: NotRequired[str]
    dhcpd_boot_server: NotRequired[str]
    dhcpd_conflict_checking: NotRequired[bool]
    dhcpd_dns_1: NotRequired[str]
    dhcpd_dns_2: NotRequired[str]
    dhcpd_dns_3: NotRequired[str]
    dhcpd_dns_4: NotRequired[str]
    dhcpd_dns_enabled: NotRequired[bool]
    dhcpd_enabled: NotRequired[bool]
    dhcpd_gateway: NotRequired[str]
    dhcpd_gateway_enabled: NotRequired[bool]
    dhcpd_ip_1: NotRequired[str]
    dhcpd_ip_2: NotRequired[str]
    dhcpd_ip_3: NotRequired[str]
    dhcpd_leasetime: NotRequired[int]
    dhcpd_mac_1: NotRequired[str]
    dhcpd_mac_2: NotRequired[str]
    dhcpd_mac_3: NotRequired[str]
    dhcpd_ntp_1: NotRequired[str]
    dhcpd_ntp_2: NotRequired[str]
    dhcpd_ntp_enabled: NotRequired[bool]
    dhcpd_start: NotRequired[str]
    dhcpd_stop: NotRequired[str]
    dhcpd_tftp_server: NotRequired[str]
    dhcpd_time_offset: NotRequired[int]
    dhcpd_time_offset_enabled: NotRequired[bool]
    dhcpd_unifi_controller: NotRequired[str]
    dhcpd_wpad_url: NotRequired[str]
    dhcpd_wins_1: NotRequired[str]
    dhcpd_wins_2: NotRequired[str]
    dhcpd_wins_enabled: NotRequired[bool]
    
    # DHCPv6 settings
    dhcpdv6_allow_slaac: NotRequired[bool]
    dhcpdv6_dns_1: NotRequired[str]
    dhcpdv6_dns_2: NotRequired[str]
    dhcpdv6_dns_3: NotRequired[str]
    dhcpdv6_dns_4: NotRequired[str]
    dhcpdv6_dns_auto: NotRequired[bool]
    dhcpdv6_enabled: NotRequired[bool]
    dhcpdv6_leasetime: NotRequired[int]
    dhcpdv6_start: NotRequired[str]
    dhcpdv6_stop: NotRequired[str]
    
    # Security settings
    dhcp_relay_enabled: NotRequired[bool]
    dhcpguard_enabled: NotRequired[bool]
    dpi_enabled: NotRequired[bool]
    dpigroup_id: NotRequired[str]
    
    # Network basics
    domain_name: NotRequired[str]
    enabled: NotRequired[bool]
    exposed_to_site_vpn: NotRequired[bool]
    gateway_device: NotRequired[str]
    gateway_type: NotRequired[str]
    
    # IGMP settings
    igmp_fastleave: NotRequired[bool]
    igmp_groupmembership: NotRequired[int]
    igmp_maxresponse: NotRequired[int]
    igmp_mcrtrexpiretime: NotRequired[int]
    igmp_proxy_downstream: NotRequired[bool]
    igmp_proxy_upstream: NotRequired[bool]
    igmp_querier: NotRequired[str]
    igmp_snooping: NotRequired[bool]
    igmp_supression: NotRequired[bool]
    
    # IPSec settings
    ipsec_dh_group: NotRequired[int]
    ipsec_dynamic_routing: NotRequired[bool]
    ipsec_encryption: NotRequired[str]
    ipsec_esp_dh_group: NotRequired[int]
    ipsec_esp_encryption: NotRequired[str]
    ipsec_esp_hash: NotRequired[str]
    ipsec_esp_lifetime: NotRequired[int]
    ipsec_hash: NotRequired[str]
    ipsec_ike_dh_group: NotRequired[int]
    ipsec_ike_encryption: NotRequired[str]
    ipsec_ike_hash: NotRequired[str]
    ipsec_ike_lifetime: NotRequired[int]
    ipsec_interface: NotRequired[str]
    ipsec_key_exchange: NotRequired[str]
    ipsec_local_identifier: NotRequired[str]
    ipsec_local_identifier_enabled: NotRequired[bool]
    ipsec_local_ip: NotRequired[str]
    ipsec_peer_ip: NotRequired[str]
    ipsec_pfs: NotRequired[bool]
    ipsec_profile: NotRequired[str]
    ipsec_remote_identifier: NotRequired[str]
    ipsec_remote_identifier_enabled: NotRequired[bool]
    ipsec_separate_ikev2_networks: NotRequired[bool]
    ipsec_tunnel_ip: NotRequired[str]
    ipsec_tunnel_ip_enabled: NotRequired[bool]
    
    # IP settings
    ip_subnet: NotRequired[str]
    
    # IPv6 settings
    ipv6_client_address_assignment: NotRequired[str]
    ipv6_interface_type: NotRequired[str]
    ipv6_pd_auto_prefixid_enabled: NotRequired[bool]
    ipv6_pd_interface: NotRequired[str]
    ipv6_pd_prefixid: NotRequired[str]
    ipv6_pd_start: NotRequired[str]
    ipv6_pd_stop: NotRequired[str]
    ipv6_ra_enabled: NotRequired[bool]
    ipv6_ra_preferred_lifetime: NotRequired[int]
    ipv6_ra_priority: NotRequired[str]
    ipv6_ra_valid_lifetime: NotRequired[int]
    ipv6_setting_preference: NotRequired[str]
    ipv6_single_network_interface: NotRequired[str]
    ipv6_subnet: NotRequired[str]
    ipv6_wan_delegation_type: NotRequired[str]
    
    # Interface settings
    interface_mtu: NotRequired[int]
    interface_mtu_enabled: NotRequired[bool]
    internet_access_enabled: NotRequired[bool]
    is_nat: NotRequired[bool]
    
    # L2TP settings
    l2tp_allow_weak_ciphers: NotRequired[bool]
    l2tp_interface: NotRequired[str]
    l2tp_local_wan_ip: NotRequired[str]
    local_port: NotRequired[int]
    lte_lan_enabled: NotRequired[bool]
    
    # MAC settings
    mac_override: NotRequired[str]
    mac_override_enabled: NotRequired[bool]
    mdns_enabled: NotRequired[bool]
    
    # NAT settings
    nat_outbound_ip_addresses: NotRequired[List[TypedNATOutboundIPAddresses]]
    
    # Basic network info
    name: NotRequired[str]
    networkgroup: NotRequired[str]
    network_isolation_enabled: NotRequired[bool]
    
    # OpenVPN settings
    openvpn_configuration: NotRequired[str]
    openvpn_configuration_filename: NotRequired[str]
    openvpn_encryption_cipher: NotRequired[str]
    openvpn_interface: NotRequired[str]
    openvpn_local_address: NotRequired[str]
    openvpn_local_port: NotRequired[int]
    openvpn_local_wan_ip: NotRequired[str]
    openvpn_mode: NotRequired[str]
    openvpn_remote_address: NotRequired[str]
    openvpn_remote_host: NotRequired[str]
    openvpn_remote_port: NotRequired[int]
    openvpn_username: NotRequired[str]
    
    # PPTP settings
    pptpc_require_mppe: NotRequired[bool]
    pptpc_route_distance: NotRequired[int]
    pptpc_server_ip: NotRequired[str]
    pptpc_username: NotRequired[str]
    
    # Priority and purpose
    priority: NotRequired[int]
    purpose: NotRequired[str]
    
    # RADIUS and remote site settings
    radiusprofile_id: NotRequired[str]
    remote_site_id: NotRequired[str]
    remote_site_subnets: NotRequired[List[str]]
    remote_vpn_dynamic_subnets_enabled: NotRequired[bool]
    remote_vpn_subnets: NotRequired[List[str]]
    report_wan_event: NotRequired[bool]
    require_mschapv2: NotRequired[bool]
    route_distance: NotRequired[int]
    
    # Preference settings
    setting_preference: NotRequired[str]
    single_network_lan: NotRequired[str]
    
    # Ubiquiti settings (uid)
    uid_policy_enabled: NotRequired[bool]
    uid_policy_name: NotRequired[str]
    uid_public_gateway_port: NotRequired[int]
    uid_traffic_rules_allowed_ips_and_hostnames: NotRequired[List[str]]
    uid_traffic_rules_enabled: NotRequired[bool]
    uid_vpn_custom_routing: NotRequired[List[str]]
    uid_vpn_default_dns_suffix: NotRequired[str]
    uid_vpn_masquerade_enabled: NotRequired[bool]
    uid_vpn_max_connection_time_seconds: NotRequired[int]
    uid_vpn_sync_public_ip: NotRequired[bool]
    uid_vpn_type: NotRequired[str]
    uid_workspace_url: NotRequired[str]
    
    # UPnP and VLAN settings
    upnp_lan_enabled: NotRequired[bool]
    usergroup_id: NotRequired[str]
    vlan: NotRequired[int]
    vlan_enabled: NotRequired[bool]
    
    # VPN client settings
    vpn_client_configuration_remote_ip_override: NotRequired[str]
    vpn_client_configuration_remote_ip_override_enabled: NotRequired[bool]
    vpn_client_default_route: NotRequired[bool]
    vpn_client_pull_dns: NotRequired[bool]
    vpn_protocol: NotRequired[str]
    vpn_type: NotRequired[str]
    
    # VRRP settings
    vrrp_ip_subnet_gw1: NotRequired[str]
    vrrp_ip_subnet_gw2: NotRequired[str]
    vrrp_vrid: NotRequired[int]
    
    # WAN settings
    wan_dhcp_cos: NotRequired[int]
    wan_dhcp_options: NotRequired[List[TypedWANDHCPOptions]]
    wan_dhcpv6_pd_size: NotRequired[int]
    wan_dns1: NotRequired[str]
    wan_dns2: NotRequired[str]
    wan_dns3: NotRequired[str]
    wan_dns4: NotRequired[str]
    wan_dns_preference: NotRequired[str]
    wan_dslite_remote_host: NotRequired[str]
    wan_egress_qos: NotRequired[int]
    wan_gateway: NotRequired[str]
    wan_gateway_v6: NotRequired[str]
    wan_ip: NotRequired[str]
    wan_ip_aliases: NotRequired[List[str]]
    wan_ipv6: NotRequired[str]
    wan_ipv6_dns1: NotRequired[str]
    wan_ipv6_dns2: NotRequired[str]
    wan_ipv6_dns_preference: NotRequired[str]
    wan_load_balance_type: NotRequired[str]
    wan_load_balance_weight: NotRequired[int]
    wan_netmask: NotRequired[str]
    wan_networkgroup: NotRequired[str]
    wan_pppoe_password_enabled: NotRequired[bool]
    wan_pppoe_username_enabled: NotRequired[bool]
    wan_prefixlen: NotRequired[int]
    wan_provider_capabilities: NotRequired[TypedWANProviderCapabilities]
    wan_smartq_down_rate: NotRequired[int]
    wan_smartq_enabled: NotRequired[bool]
    wan_smartq_up_rate: NotRequired[int]
    wan_type: NotRequired[str]
    wan_type_v6: NotRequired[str]
    wan_username: NotRequired[str]
    wan_vlan: NotRequired[int]
    wan_vlan_enabled: NotRequired[bool]
    
    # Wireguard settings
    wireguard_client_configuration_file: NotRequired[str]
    wireguard_client_configuration_filename: NotRequired[str]
    wireguard_client_mode: NotRequired[str]
    wireguard_client_peer_ip: NotRequired[str]
    wireguard_client_peer_port: NotRequired[int]
    wireguard_client_peer_public_key: NotRequired[str]
    wireguard_client_preshared_key: NotRequired[str]
    wireguard_client_preshared_key_enabled: NotRequired[bool]
    wireguard_interface: NotRequired[str]
    wireguard_local_wan_ip: NotRequired[str]
    wireguard_public_key: NotRequired[str]
    
    # Secret keys (x_ prefix)
    x_auth_key: NotRequired[str]
    x_ca_crt: NotRequired[str]
    x_ca_key: NotRequired[str]
    x_dh_key: NotRequired[str]
    x_ipsec_pre_shared_key: NotRequired[str]
    x_openvpn_password: NotRequired[str]
    x_openvpn_shared_secret_key: NotRequired[str]
    x_pptpc_password: NotRequired[str]
    x_server_crt: NotRequired[str]
    x_server_key: NotRequired[str]
    x_shared_client_crt: NotRequired[str]
    x_shared_client_key: NotRequired[str]
    x_wan_password: NotRequired[str]
    x_wireguard_private_key: NotRequired[str]


@dataclass
class NetworkListRequest(ApiRequest):
    """Request object for network list."""

    @classmethod
    def create(cls) -> Self:
        """Create network list request."""
        return cls(method="get", path="/rest/networkconf")


@dataclass
class NetworkDetailRequest(ApiRequest):
    """Request object for network detail."""

    @classmethod
    def create(cls, network_id: str) -> Self:
        """Create network detail request."""
        return cls(method="get", path=f"/rest/networkconf/{network_id}")


@dataclass
class NetworkCreateRequest(ApiRequest):
    """Request object for network creation."""

    @classmethod
    def create(cls, network: "Network") -> Self:
        """Create network create request."""
        return cls(
            method="post",
            path="/rest/networkconf",
            data=network.raw,
        )


@dataclass
class NetworkUpdateRequest(ApiRequest):
    """Request object for network update."""

    @classmethod
    def create(cls, network: "Network") -> Self:
        """Create network update request."""
        return cls(
            method="put", 
            path=f"/rest/networkconf/{network.id}", 
            data=network.raw,
        )


@dataclass
class NetworkDeleteRequest(ApiRequest):
    """Request object for network deletion."""

    @classmethod
    def create(cls, network_id: str) -> Self:
        """Create network delete request."""
        return cls(method="delete", path=f"/rest/networkconf/{network_id}")


class Network(ApiItem):
    """Represents a UniFi Network configuration."""

    raw: TypedNetwork
    
    @property
    def id(self) -> str:
        """Network ID."""
        return self.raw["_id"]

    @property
    def site_id(self) -> str:
        """Site ID."""
        return self.raw.get("site_id", "")
    
    @property
    def name(self) -> str:
        """Network name."""
        return self.raw.get("name", "")
    
    @property
    def purpose(self) -> str:
        """Network purpose."""
        return self.raw.get("purpose", "")
    
    @property
    def vlan(self) -> Optional[int]:
        """VLAN ID if enabled."""
        if self.vlan_enabled:
            return self.raw.get("vlan", None)
        return None
    
    @property
    def vlan_enabled(self) -> bool:
        """Whether VLAN is enabled."""
        return self.raw.get("vlan_enabled", False)
    
    @property
    def enabled(self) -> bool:
        """Whether network is enabled."""
        return self.raw.get("enabled", True)
    
    @property
    def ip_subnet(self) -> str:
        """IP subnet for the network."""
        return self.raw.get("ip_subnet", "")
    
    @property
    def dhcp_enabled(self) -> bool:
        """Whether DHCP server is enabled."""
        return self.raw.get("dhcpd_enabled", False)
    
    @property
    def dhcp_start(self) -> str:
        """DHCP range start address."""
        return self.raw.get("dhcpd_start", "")
    
    @property
    def dhcp_stop(self) -> str:
        """DHCP range end address."""
        return self.raw.get("dhcpd_stop", "")
    
    @property
    def dhcp_lease_time(self) -> int:
        """DHCP lease time in seconds."""
        return self.raw.get("dhcpd_leasetime", 0)
    
    @property
    def networkgroup(self) -> str:
        """Network group (LAN, WAN, etc)."""
        return self.raw.get("networkgroup", "")