"""UniFi devices are network infrastructure."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import enum
import logging
import re
try:
    from typing import Any, NotRequired, Self, TypedDict, cast
except ImportError:
    from typing_extensions import Any, NotRequired, Self, TypedDict, cast

from .api import ApiItem, ApiRequest

LOGGER = logging.getLogger(__name__)


class TypedDeviceAntennaTable(TypedDict):
    """Device antenna table type definition."""

    default: bool
    id: int
    name: str
    wifi0_gain: int
    wifi1_gain: int


class TypedDeviceConfigNetwork(TypedDict):
    """Device config network type definition."""

    ip: str
    type: str


class TypedDeviceEthernetOverrides(TypedDict):
    """Device ethernet overrides type definition."""

    ifname: str
    networkgroup: str


class TypedDeviceEthernetTable(TypedDict):
    """Device ethernet table type definition."""

    mac: str
    name: str
    num_port: int


class TypedDeviceLastUplink(TypedDict):
    """Device last uplink type definition."""

    port_idx: int
    type: str
    uplink_mac: str
    uplink_device_name: str
    uplink_remote_port: int


class TypedDeviceLldpTable(TypedDict):
    """Device LLDP table type definition."""

    chassis_id: str
    chassis_id_subtype: str
    is_wired: bool
    local_port_idx: int
    local_port_name: str
    port_id: str


class TypedDeviceNetworkTable(TypedDict):
    """Device network table type definition."""

    _id: str
    attr_hidden_id: str
    attr_no_delete: bool
    dhcp_relay_enabled: bool
    dhcpd_dns_1: str
    dhcpd_dns_enabled: bool
    dhcpd_enabled: bool
    dhcpd_gateway_enabled: bool
    dhcpd_leasetime: int
    dhcpd_start: str
    dhcpd_stop: str
    dhcpd_time_offset_enabled: bool
    dhcpd_unifi_controller: str
    domain_name: str
    enabled: bool
    ip: str
    ip_subnet: str
    is_guest: bool
    is_nat: bool
    lte_lan_enabled: bool
    mac: str
    name: str
    networkgroup: str
    num_sta: int
    purpose: str
    rx_bytes: int
    rx_packets: int
    site_id: str
    tx_bytes: int
    tx_packets: int
    up: str
    vlan_enabled: bool


class TypedDeviceOutletOverrides(TypedDict, total=False):
    """Device outlet overrides type definition."""

    cycle_enabled: bool
    index: int
    has_relay: bool
    has_metering: bool
    name: str
    relay_state: bool


class TypedDeviceOutletTable(TypedDict):
    """Device outlet table type definition."""

    cycle_enabled: NotRequired[bool]
    index: int
    has_relay: NotRequired[bool]
    has_metering: NotRequired[bool]
    name: str
    outlet_caps: int
    outlet_voltage: NotRequired[str]
    outlet_current: NotRequired[str]
    outlet_power: NotRequired[str]
    outlet_power_factor: NotRequired[str]
    relay_state: bool


class TypedDeviceQOSMarking(TypedDict, total=False):
    """Device QOS marking type definition."""
    
    cos_code: NotRequired[int]
    dscp_code: NotRequired[int]
    ip_precedence_code: NotRequired[int]
    queue: NotRequired[int]


class TypedDeviceQOSMatching(TypedDict, total=False):
    """Device QOS matching type definition."""
    # Add QOS matching fields as needed


class TypedDeviceQOSPolicies(TypedDict, total=False):
    """Device QOS policies type definition."""
    
    qos_marking: NotRequired[TypedDeviceQOSMarking]
    qos_matching: NotRequired[TypedDeviceQOSMatching]


class TypedDeviceQOSProfile(TypedDict, total=False):
    """Device QOS profile type definition."""
    
    qos_policies: NotRequired[list[TypedDeviceQOSPolicies]]
    qos_profile_mode: NotRequired[str]


class TypedDevicePortOverrides(TypedDict, total=False):
    """Device port overrides type definition."""

    # Required fields
    poe_mode: str
    port_idx: int
    portconf_id: str
    
    # Optional fields
    aggregate_num_ports: NotRequired[int]
    autoneg: NotRequired[bool]
    dot1x_ctrl: NotRequired[str]
    dot1x_idle_timeout: NotRequired[int]
    egress_rate_limit_kbps_enabled: NotRequired[bool]
    egress_rate_limit_kbps: NotRequired[int]
    excluded_networkconf_ids: NotRequired[list[str]]
    fec_mode: NotRequired[str]
    forward: NotRequired[str]
    full_duplex: NotRequired[bool]
    isolation: NotRequired[bool]
    lldpmed_enabled: NotRequired[bool]
    lldpmed_notify_enabled: NotRequired[bool]
    mirror_port_idx: NotRequired[int]
    name: NotRequired[str]
    native_networkconf_id: NotRequired[str]
    op_mode: NotRequired[str]
    port_keepalive_enabled: NotRequired[bool]
    port_poe: NotRequired[bool]
    port_security_enabled: NotRequired[bool]
    port_security_mac_address: NotRequired[list[str]]
    priority_queue1_level: NotRequired[int]
    priority_queue2_level: NotRequired[int]
    priority_queue3_level: NotRequired[int]
    priority_queue4_level: NotRequired[int]
    qos_profile: NotRequired[TypedDeviceQOSProfile]
    setting_preference: NotRequired[str]
    speed: NotRequired[int]
    stormctrl_bcast_enabled: NotRequired[bool]
    stormctrl_bcast_level: NotRequired[int]
    stormctrl_bcast_rate: NotRequired[int]
    stormctrl_mcast_enabled: NotRequired[bool]
    stormctrl_mcast_level: NotRequired[int]
    stormctrl_mcast_rate: NotRequired[int]
    stormctrl_type: NotRequired[str]
    stormctrl_ucast_enabled: NotRequired[bool]
    stormctrl_ucast_level: NotRequired[int]
    stormctrl_ucast_rate: NotRequired[int]
    stp_port_mode: NotRequired[bool]
    tagged_vlan_mgmt: NotRequired[str]
    voice_networkconf_id: NotRequired[str]


class TypedDevicePortTableLldpTable(TypedDict):
    """Device port table mac table type definition."""

    lldp_chassis_id: str
    lldp_port_id: str
    lldp_system_name: str


class TypedDevicePortTableMacTable(TypedDict):
    """Device port table mac table type definition."""

    age: int
    mac: str
    static: bool
    uptime: int
    vlan: int


class TypedDevicePortTablePortDelta(TypedDict):
    """Device port table port delta type definition."""

    rx_bytes: int
    rx_packets: int
    time_delta: int
    time_delta_activity: int
    tx_bytes: int
    tx_packets: int


class TypedDevicePortTable(TypedDict):
    """Device port table type definition."""

    aggregated_by: bool
    attr_no_edit: bool
    autoneg: bool
    bytes_r: int
    dot1x_mode: str
    dot1x_status: str
    enable: bool
    flowctrl_rx: bool
    flowctrl_tx: bool
    full_duplex: bool
    ifname: NotRequired[str]
    is_uplink: bool
    jumbo: bool
    lldp_table: list[TypedDevicePortTableLldpTable]
    mac_table: list[TypedDevicePortTableMacTable]
    masked: bool
    media: str
    name: str
    op_mode: str
    poe_caps: int
    poe_class: str
    poe_current: str
    poe_enable: bool
    poe_good: bool
    poe_mode: str
    poe_power: str
    poe_voltage: str
    port_delta: TypedDevicePortTablePortDelta
    port_idx: NotRequired[int]
    port_poe: bool
    portconf_id: str
    rx_broadcast: int
    rx_bytes: int
    rx_bytes_r: int
    rx_dropped: int
    rx_errors: int
    rx_multicast: int
    rx_packets: int
    speed: int
    speed_caps: int
    stp_pathcost: int
    stp_state: str
    tx_broadcast: int
    tx_bytes: int
    tx_bytes_r: int
    tx_dropped: int
    tx_errors: int
    tx_multicast: int
    tx_packets: int
    up: NotRequired[bool]


class TypedDeviceRadioTable(TypedDict):
    """Device radio table type definition."""

    antenna_gain: int
    builtin_ant_gain: int
    builtin_antenna: bool
    channel: int
    current_antenna_gain: int
    hard_noise_floor_enabled: bool
    has_dfs: bool
    has_fccdfs: bool
    ht: str
    is_11ac: bool
    max_txpower: int
    min_rssi_enabled: bool
    min_txpower: int
    name: str
    nss: int
    radio: str
    radio_caps: int
    sens_level_enabled: bool
    tx_power_mode: str
    wlangroup_id: str


class TypedDeviceRadioTableStats(TypedDict):
    """Device radio table statistics type definition."""

    ast_be_xmit: int
    ast_cst: int
    ast_txto: int
    channel: int
    cu_self_rx: int
    cu_self_tx: int
    cu_total: int
    extchannel: int
    gain: int
    guest_num_sta: int
    name: str
    num_sta: int
    radio: str
    satisfaction: int
    state: str
    tx_packets: str
    tx_power: str
    tx_retries: str
    user_num_sta: str


class TypedDeviceSwitchCaps(TypedDict):
    """Device switch caps type definition."""

    feature_caps: int
    max_aggregate_sessions: int
    max_mirror_sessions: int
    vlan_caps: int


class TypedDeviceSysStats(TypedDict):
    """Device sys stats type definition."""

    loadavg_1: str
    loadavg_15: str
    loadavg_5: str
    mem_buffer: int
    mem_total: int
    mem_used: int


class TypedDeviceSystemStats(TypedDict):
    """Device system stats type definition."""

    cpu: str
    mem: str
    uptime: str


class TypedDeviceTemperature(TypedDict):
    """Device temperature type definition."""

    name: str
    type: str
    value: float


class TypedDeviceUplink(TypedDict):
    """Device uplink type definition."""

    full_duplex: bool
    ip: str
    mac: str
    max_speed: int
    max_vlan: int
    media: str
    name: str
    netmask: str
    num_port: int
    rx_bytes: int
    rx_bytes_r: int
    rx_dropped: int
    rx_errors: int
    rx_multicast: int
    rx_packets: int
    speed: int
    tx_bytes: int
    tx_bytes_r: int
    tx_dropped: int
    tx_errors: int
    tx_packets: int
    type: str
    up: bool
    uplink_mac: str
    uplink_remote_port: int


class TypedDeviceUptimeStatsWanMonitor(TypedDict):
    """Device uptime stats wan monitor type definition."""

    availability: float
    latency_average: NotRequired[int]
    target: str
    type: str


class TypedDeviceUptimeStatsWan(TypedDict):
    """Device uptime stats wan type definition."""

    monitors: list[TypedDeviceUptimeStatsWanMonitor]


class TypedDeviceUptimeStats(TypedDict):
    """Device uptime stats type definition."""

    WAN: TypedDeviceUptimeStatsWan
    WAN2: TypedDeviceUptimeStatsWan


class TypedDeviceWlanOverrides(TypedDict):
    """Device wlan overrides type definition."""

    name: str
    radio: str
    radio_name: str
    wlan_id: str


class TypedDeviceSpeedtestStatus(TypedDict):
    """Device speedtest status type definition."""

    latency: int
    rundate: int
    runtime: int
    status_download: int
    status_ping: int
    status_summary: int
    status_upload: int
    xput_download: float
    xput_upload: float


class TypedDeviceStorage(TypedDict):
    """Device storage type definition."""

    mount_point: str
    name: str
    size: int
    type: str
    used: int


class TypedDevice(TypedDict):
    """Device type definition."""

    _id: str
    _uptime: int
    adoptable_when_upgraded: bool
    adopted: bool
    antenna_table: list[TypedDeviceAntennaTable]
    architecture: str
    adoption_completed: int
    board_rev: NotRequired[int]
    bytes: int
    bytes_d: int
    bytes_r: int
    cfgversion: int
    config_network: TypedDeviceConfigNetwork
    connect_request_ip: str
    connect_request_port: str
    considered_lost_at: int
    country_code: int
    countrycode_table: list  # type: ignore[type-arg]
    device_id: str
    dhcp_server_table: list  # type: ignore[type-arg]
    disabled: NotRequired[bool]
    disconnection_reason: str
    displayable_version: str
    dot1x_portctrl_enabled: bool
    downlink_table: list  # type: ignore[type-arg]
    element_ap_serial: str
    element_peer_mac: str
    element_uplink_ap_mac: str
    ethernet_overrides: list[TypedDeviceEthernetOverrides]
    ethernet_table: list[TypedDeviceEthernetTable]
    fan_level: int
    flowctrl_enabled: bool
    fw_caps: int
    gateway_mac: str
    general_temperature: NotRequired[int]
    guest_num_sta: int
    guest_wlan_num_sta: int
    guest_token: str
    has_eth1: bool
    has_fan: bool
    has_speaker: bool
    has_temperature: bool
    hash_id: str
    hide_ch_width: str
    hw_caps: int
    inform_ip: str
    inform_url: str
    internet: bool
    ip: NotRequired[str]
    isolated: bool
    jumboframe_enabled: bool
    kernel_version: str
    known_cfgversion: str
    last_seen: int
    last_uplink: TypedDeviceLastUplink
    lcm_brightness: int
    lcm_brightness_override: bool
    lcm_idle_timeout_override: bool
    lcm_night_mode_begins: str
    lcm_night_mode_enabled: bool
    lcm_night_mode_ends: str
    lcm_tracker_enabled: bool
    led_override: str
    led_override_color: str
    led_override_color_brightness: int
    license_state: str
    lldp_table: list[TypedDeviceLldpTable]
    locating: bool
    mac: str
    manufacturer_id: int
    meshv3_peer_mac: str
    model: str
    model_in_eol: bool
    model_in_lts: bool
    model_incompatible: bool
    name: str
    network_table: list[TypedDeviceNetworkTable]
    next_heartbeat_at: int
    next_interval: int
    num_desktop: int
    num_handheld: int
    num_mobile: int
    num_sta: int
    outdoor_mode_override: str
    outlet_ac_power_budget: str
    outlet_ac_power_consumption: str
    outlet_enabled: bool
    outlet_overrides: list[TypedDeviceOutletOverrides]
    outlet_table: list[TypedDeviceOutletTable]
    overheating: bool
    power_source_ctrl_enabled: bool
    prev_non_busy_state: int
    provisioned_at: int
    port_overrides: list[TypedDevicePortOverrides]
    port_table: NotRequired[list[TypedDevicePortTable]]
    radio_table: list[TypedDeviceRadioTable]
    radio_table_stats: list[TypedDeviceRadioTableStats]
    required_version: str
    rollupgrade: bool
    rx_bytes: int
    rx_bytes_d: int
    satisfaction: int
    scan_radio_table: list  # type: ignore[type-arg]
    scanning: bool
    serial: str
    site_id: str
    spectrum_scanning: bool
    speedtest_status: TypedDeviceSpeedtestStatus | None
    ssh_session_table: list  # type: ignore[type-arg]
    start_connected_millis: int
    start_disconnected_millis: int
    stat: dict  # type: ignore[type-arg]
    state: int
    storage: list[TypedDeviceStorage] | None
    stp_priority: str
    stp_version: str
    switch_caps: TypedDeviceSwitchCaps
    sys_error_caps: int
    sys_stats: TypedDeviceSysStats
    syslog_key: str
    system_stats: TypedDeviceSystemStats
    temperatures: list[TypedDeviceTemperature] | None
    two_phase_adopt: bool
    tx_bytes: int
    tx_bytes_d: int
    type: str
    unsupported: bool
    unsupported_reason: int
    upgradable: bool
    upgrade_state: int
    upgrade_to_firmware: str
    uplink: TypedDeviceUplink
    uplink_depth: int
    uplink_table: list  # type: ignore[type-arg]
    uptime: int
    uptime_stats: TypedDeviceUptimeStats | None
    user_num_sta: int
    user_wlan_num_sta: int
    usg_caps: int
    vap_table: list[dict]  # type: ignore[type-arg]
    version: str
    vwireEnabled: bool
    vwire_table: list  # type: ignore[type-arg]
    vwire_vap_table: list  # type: ignore[type-arg]
    wifi_caps: int
    wlan_overrides: list[TypedDeviceWlanOverrides]
    wlangroup_id_na: str
    wlangroup_id_ng: str
    x_aes_gcm: bool
    x_authkey: str
    x_fingerprint: str
    x_has_ssh_hostkey: bool
    x_inform_authkey: str
    x_ssh_hostkey_fingerprint: str
    x_vwirekey: str


class DeviceState(enum.IntEnum):
    """Enum for device states."""

    DISCONNECTED = 0
    CONNECTED = 1
    PENDING = 2
    FIRMWARE_MISMATCH = 3
    UPGRADING = 4
    PROVISIONING = 5
    HEARTBEAT_MISSED = 6
    ADOPTING = 7
    DELETING = 8
    INFORM_ERROR = 9
    ADOPTION_FALIED = 10
    ISOLATED = 11

    UNKNOWN = -1

    @classmethod
    def _missing_(cls, value: object) -> DeviceState:
        """Set default enum member if an unknown value is provided."""
        LOGGER.warning("Unsupported device state %s %s", value, cls)
        return DeviceState.UNKNOWN


class HardwareCapability(enum.IntFlag):
    """Enumeration representing hardware capabilities."""

    LED_RING = 2


@dataclass
class DeviceListRequest(ApiRequest):
    """Request object for device list."""

    @classmethod
    def create(cls) -> Self:
        """Create device list request."""
        return cls(method="get", path="/stat/device")


@dataclass
class DevicePowerCyclePortRequest(ApiRequest):
    """Request object for power cycle PoE port."""

    @classmethod
    def create(cls, mac: str, port_idx: int) -> Self:
        """Create power cycle of PoE request."""
        return cls(
            method="post",
            path="/cmd/devmgr",
            data={
                "cmd": "power-cycle",
                "mac": mac,
                "port_idx": port_idx,
            },
        )


@dataclass
class DeviceRestartRequest(ApiRequest):
    """Request object for device restart."""

    @classmethod
    def create(cls, mac: str, soft: bool = True) -> Self:
        """Create device restart request.

        Hard is specifically for PoE switches and will additionally cycle PoE ports.
        """
        return cls(
            method="post",
            path="/cmd/devmgr",
            data={
                "cmd": "restart",
                "mac": mac,
                "reboot_type": "soft" if soft else "hard",
            },
        )


@dataclass
class DeviceUpgradeRequest(ApiRequest):
    """Request object for device upgrade."""

    @classmethod
    def create(cls, mac: str) -> Self:
        """Create device upgrade request."""
        return cls(
            method="post",
            path="/cmd/devmgr",
            data={
                "cmd": "upgrade",
                "mac": mac,
            },
        )


@dataclass
class DeviceSetOutletRelayRequest(ApiRequest):
    """Request object for outlet relay state."""

    @classmethod
    def create(cls, device: Device, outlet_idx: int, state: bool) -> Self:
        """Create device outlet relay state request.

        True:  outlet power output on.
        False: outlet power output off.
        """
        existing_override = False
        for outlet_override in device.outlet_overrides:
            if outlet_idx == outlet_override["index"]:
                outlet_override["relay_state"] = state
                existing_override = True
                break

        if not existing_override:
            name = device.outlet_table[outlet_idx - 1].get("name", "")
            device.outlet_overrides.append(
                {
                    "index": outlet_idx,
                    "name": name,
                    "relay_state": state,
                }
            )

        return cls(
            method="put",
            path=f"/rest/device/{device.id}",
            data={"outlet_overrides": device.outlet_overrides},
        )


@dataclass
class DeviceSetOutletCycleEnabledRequest(ApiRequest):
    """Request object for outlet cycle_enabled flag."""

    @classmethod
    def create(cls, device: Device, outlet_idx: int, state: bool) -> Self:
        """Create device outlet outlet cycle_enabled flag request.

        True:  UniFi Network will power cycle this outlet if the internet goes down.
        False: UniFi Network will not power cycle this outlet if the internet goes down.
        """
        existing_override = False
        for outlet_override in device.outlet_overrides:
            if outlet_idx == outlet_override["index"]:
                outlet_override["cycle_enabled"] = state
                existing_override = True
                break

        if not existing_override:
            name = device.outlet_table[outlet_idx - 1].get("name", "")
            device.outlet_overrides.append(
                {
                    "index": outlet_idx,
                    "name": name,
                    "cycle_enabled": state,
                }
            )

        return cls(
            method="put",
            path=f"/rest/device/{device.id}",
            data={"outlet_overrides": device.outlet_overrides},
        )

@dataclass
class DeviceSetPortProfileRequest(ApiRequest):
    """Request object for setting the port profile."""

    @classmethod
    def create(
        cls,
        device: Device,
        port_override: TypedDevicePortOverrides,
    ) -> Self:
        """Create device set port profile request.
        
        Make sure to not overwrite any existing configs.
        """
        port_overrides = deepcopy(device.port_overrides) 
        original = next((p for p in port_overrides if hasattr(p, 'port_idx') and p.get("port_idx") == port_override.get("port_idx")), None)
        if original:
            idx = port_overrides.index(original)
            # Update existing override
            for key, value in port_override.items():
                if value is not None:
                    original[key] = value
            port_overrides[idx] = original
        else:
            # Add new override
            port_overrides.append(port_override)

        return cls(
            method="put",
            path=f"/rest/device/{device.id}",
            data={"port_overrides": port_overrides},
        )

@dataclass
class DeviceSetPoePortModeRequest(ApiRequest):
    """Request object for setting port PoE mode."""

    @classmethod
    def create(
        cls,
        device: Device,
        port_idx: int | None = None,
        mode: str | None = None,
        targets: list[tuple[int, str]] | None = None,
    ) -> Self:
        """Create device set port PoE mode request.

        Auto, 24v, passthrough, off.
        Make sure to not overwrite any existing configs.
        """
        overrides: list[tuple[int, str]] = []
        if port_idx is not None and mode is not None:
            overrides.append((port_idx, mode))
        elif targets is not None:
            overrides = targets
        else:
            raise AttributeError

        port_overrides = deepcopy(device.port_overrides)

        for override in overrides:
            port_idx, mode = override

            existing_override = False
            for port_override in port_overrides:
                if port_idx == port_override.get("port_idx"):
                    port_override["poe_mode"] = mode
                    existing_override = True
                    break

            if existing_override:
                continue

            port_override = {"port_idx": port_idx, "poe_mode": mode}
            if portconf_id := device.port_table[port_idx - 1].get("portconf_id"):
                port_override["portconf_id"] = portconf_id
            port_overrides.append(port_override)

        return cls(
            method="put",
            path=f"/rest/device/{device.id}",
            data={"port_overrides": port_overrides},
        )


@dataclass
class DeviceSetLedStatus(ApiRequest):
    """Request object for setting LED status of device."""

    @classmethod
    def create(
        cls,
        device: Device,
        status: str = "on",
        brightness: int | None = None,
        color: str | None = None,
    ) -> Self:
        """Set LED status of device."""

        data: dict[str, int | str] = {"led_override": status}
        if device.supports_led_ring:
            # Validate brightness parameter
            if brightness is not None:
                if not (0 <= brightness <= 100):
                    raise AttributeError(
                        "Brightness must be within the range [0, 100]."
                    )
                data["led_override_color_brightness"] = brightness

            # Validate color parameter
            if color is not None:
                if not re.match(r"^#(?:[0-9a-fA-F]{3}){1,2}$", color):
                    raise AttributeError(
                        "Color must be a valid hex color code (e.g., '#00FF00')."
                    )
                data["led_override_color"] = color

        return cls(
            method="put",
            path=f"/rest/device/{device.id}",
            data=data,
        )


class Device(ApiItem):
    """Represents a network device."""

    raw: TypedDevice

    @property
    def board_revision(self) -> int:
        """Board revision of device."""
        return self.raw.get("board_rev", 0)

    @property
    def considered_lost_at(self) -> int:
        """When device is considered lost."""
        return self.raw["considered_lost_at"]

    @property
    def disabled(self) -> bool:
        """Is device disabled."""
        return self.raw.get("disabled", False)

    @property
    def downlink_table(self) -> list[dict[str, Any]]:
        """All devices with device as uplink."""
        return self.raw.get("downlink_table", [])

    @property
    def fan_level(self) -> int | None:
        """Fan level of device."""
        return self.raw.get("fan_level")

    @property
    def general_temperature(self) -> int | None:
        """General temperature of device."""
        return self.raw.get("general_temperature")

    @property
    def has_fan(self) -> bool:
        """Do device have a fan."""
        return self.raw.get("has_fan", False)

    @property
    def has_temperature(self) -> bool:
        """Do the device have a general temperature."""
        return self.raw.get("has_temperature", False)

    @property
    def hw_caps(self) -> int:
        """Hardware capabilities."""
        return self.raw.get("hw_caps", 0)

    @property
    def id(self) -> str:
        """ID of device."""
        return self.raw["device_id"]

    @property
    def ip(self) -> str | None:
        """IP of device."""
        return self.raw.get("ip")

    @property
    def last_seen(self) -> int | None:
        """When was device last seen."""
        return self.raw.get("last_seen")

    @property
    def led_override(self) -> str | None:
        """LED override."""
        return self.raw.get("led_override")

    @property
    def led_override_color(self) -> str | None:
        """LED override color."""
        return self.raw.get("led_override_color")

    @property
    def led_override_color_brightness(self) -> int | None:
        """LED override color brightness."""
        return self.raw.get("led_override_color_brightness")

    @property
    def lldp_table(self) -> list[TypedDeviceLldpTable]:
        """All clients and devices directly attached to device."""
        return self.raw.get("lldp_table", [])

    @property
    def mac(self) -> str:
        """MAC address of device."""
        return self.raw["mac"]

    @property
    def model(self) -> str:
        """Model of device."""
        return self.raw["model"]

    @property
    def name(self) -> str:
        """Name of device."""
        return self.raw.get("name", "")

    @property
    def next_heartbeat_at(self) -> int | None:
        """Next heart beat full UNIX time."""
        return self.raw.get("next_heartbeat_at")

    @property
    def next_interval(self) -> int:
        """Next heart beat in seconds."""
        return self.raw.get("next_interval", 30)

    @property
    def overheating(self) -> bool:
        """Is device overheating."""
        return self.raw.get("overheating", False)

    @property
    def outlet_overrides(self) -> list[TypedDeviceOutletOverrides]:
        """Overridden outlet configuration."""
        return self.raw.get("outlet_overrides", [])

    @property
    def outlet_ac_power_budget(self) -> str | None:
        """The amount of power available to outlets."""
        return self.raw.get("outlet_ac_power_budget")

    @property
    def outlet_ac_power_consumption(self) -> str | None:
        """The amount of power consumed by all outlets."""
        return self.raw.get("outlet_ac_power_consumption")

    @property
    def outlet_table(self) -> list[TypedDeviceOutletTable]:
        """List of outlets."""
        return self.raw.get("outlet_table", [])

    @property
    def port_overrides(self) -> list[TypedDevicePortOverrides]:
        """Overridden port configuration."""
        return self.raw.get("port_overrides", [])

    @property
    def port_table(self) -> list[TypedDevicePortTable]:
        """List of ports and data."""
        return self.raw.get("port_table", [])

    @property
    def speedtest_status(self) -> TypedDeviceSpeedtestStatus | None:
        """Speedtest status."""
        if value := self.raw.get("speedtest-status"):
            return cast(TypedDeviceSpeedtestStatus, value)
        return None

    @property
    def state(self) -> DeviceState:
        """State of device."""
        return DeviceState(self.raw["state"])

    @property
    def storage(self) -> list[TypedDeviceStorage] | None:
        """Device storage information."""
        return self.raw.get("storage")

    @property
    def sys_stats(self) -> TypedDeviceSysStats:
        """Output from top."""
        return self.raw["sys_stats"]

    @property
    def system_stats(self) -> tuple[str, str, str]:
        """System statistics."""
        data = self.raw["system-stats"]  # type: ignore [typeddict-item]
        return (data.get("cpu", ""), data.get("mem", ""), data.get("uptime", ""))

    @property
    def temperatures(self) -> list[TypedDeviceTemperature] | None:
        """Device temperature sensors."""
        return self.raw.get("temperatures")

    @property
    def type(self) -> str:
        """Type of device."""
        return self.raw["type"]

    @property
    def version(self) -> str:
        """Firmware version."""
        return self.raw["version"]

    @property
    def upgradable(self) -> bool:
        """Is a new firmware available."""
        return self.raw.get("upgradable", False)

    @property
    def upgrade_to_firmware(self) -> str:
        """Firmware version to update to."""
        return self.raw.get("upgrade_to_firmware", "")

    @property
    def uplink(self) -> TypedDeviceUplink:
        """Information about uplink."""
        return self.raw["uplink"]

    @property
    def uplink_depth(self) -> int | None:
        """Hops to gateway."""
        return self.raw.get("uplink_depth")

    @property
    def uptime(self) -> int:
        """Uptime of device."""
        return self.raw.get("uptime", 0)

    @property
    def uptime_stats(self) -> TypedDeviceUptimeStats | None:
        """Uptime statistics."""
        return self.raw.get("uptime_stats")

    @property
    def user_num_sta(self) -> int:
        """Amount of connected clients."""
        value = self.raw.get("user-num_sta")
        assert isinstance(value, int)
        return value

    @property
    def wlan_overrides(self) -> list[TypedDeviceWlanOverrides]:
        """Wlan configuration override."""
        return self.raw.get("wlan_overrides", [])

    @property
    def supports_led_ring(self) -> bool:
        """Check if the hardware supports an LED ring based on the second bit of `hw_caps`."""
        return bool(self.hw_caps & HardwareCapability.LED_RING)

    def __repr__(self) -> str:
        """Return the representation."""
        return f"<Device {self.name}: {self.mac}>"
