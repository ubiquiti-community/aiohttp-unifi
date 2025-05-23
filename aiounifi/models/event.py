"""Event messages on state changes."""

from __future__ import annotations

import enum
import logging
from typing import TypedDict, final

from .api import ApiItem

LOGGER = logging.getLogger(__name__)


class EventKey(enum.Enum):
    """Key as part of event data object.

    "data": [{"key": "EVT_LU_Disconnected"}].
    """

    CONTROLLER_UPDATE_AVAILABLE = "EVT_AD_Update_Available"

    ACCESS_POINT_ADOPTED = "EVT_AP_Adopted"
    ACCESS_POINT_AUTO_READOPTED = "EVT_AP_AutoReadopted"
    ACCESS_POINT_CHANNEL_CHANGED = "EVT_AP_ChannelChanged"
    ACCESS_POINT_CONFIGURED = "EVT_AP_Configured"
    ACCESS_POINT_CONNECTED = "EVT_AP_Connected"
    ACCESS_POINT_DELETED = "EVT_AP_Deleted"
    ACCESS_POINT_DETECT_ROGUE_AP = "EVT_AP_DetectRogueAP"
    ACCESS_POINT_DISCOVERED_PENDING = "EVT_AP_DiscoveredPending"
    ACCESS_POINT_ISOLATED = "EVT_AP_Isolated"
    ACCESS_POINT_LOST_CONTACT = "EVT_AP_Lost_Contact"
    ACCESS_POINT_POSSIBLE_INTERFERENCE = "EVT_AP_PossibleInterference"
    ACCESS_POINT_RADAR_DETECTED = "EVT_AP_RadarDetected"
    ACCESS_POINT_RESTARTED = "EVT_AP_Restarted"
    ACCESS_POINT_RESTARTED_UNKNOWN = "EVT_AP_RestartedUnknown"
    ACCESS_POINT_UPGRADE_SCHEDULED = "EVT_AP_UpgradeScheduled"
    ACCESS_POINT_UPGRADE_FAILED = "EVT_AP_UpgradeFailed"
    ACCESS_POINT_UPGRADED = "EVT_AP_Upgraded"

    DREAM_MACHINE_CONNECTED = "EVT_DM_Connected"
    DREAM_MACHINE_LOST_CONTACT = "EVT_DM_Lost_Contact"
    DREAM_MACHINE_UPGRADED = "EVT_DM_Upgraded"

    GATEWAY_ADOPTED = "EVT_GW_Adopted"
    GATEWAY_AUTO_READOPTED = "EVT_GW_AutoReadopted"
    GATEWAY_CONFIGURED = "EVT_GW_Configured"
    GATEWAY_CONNECTED = "EVT_GW_Connected"
    GATEWAY_DELETED = "EVT_GW_Deleted"
    GATEWAY_LOST_CONTACT = "EVT_GW_Lost_Contact"
    GATEWAY_RESTARTED = "EVT_GW_Restarted"
    GATEWAY_RESTARTED_UNKNOWN = "EVT_GW_RestartedUnknown"
    GATEWAY_UPGRADED = "EVT_GW_Upgraded"
    GATEWAY_WAN_TRANSITION = "EVT_GW_WANTransition"

    SWITCH_ADOPTED = "EVT_SW_Adopted"
    SWITCH_AUTO_READOPTED = "EVT_SW_AutoReadopted"
    SWITCH_CONFIGURED = "EVT_SW_Configured"
    SWITCH_CONNECTED = "EVT_SW_Connected"
    SWITCH_DELETED = "EVT_SW_Deleted"
    SWITCH_DETECT_ROGUE_DHCP = "EVT_SW_DetectRogueDHCP"
    SWITCH_DISCOVERED_PENDING = "EVT_SW_DiscoveredPending"
    SWITCH_LOST_CONTACT = "EVT_SW_Lost_Contact"
    SWITCH_OVERHEAT = "EVT_SW_Overheat"
    SWITCH_POE_OVERLOAD = "EVT_SW_PoeOverload"
    SWITCH_POE_DISCONNECT = "EVT_SW_PoeDisconnect"
    SWITCH_RESTARTED = "EVT_SW_Restarted"
    SWITCH_RESTARTED_UNKNOWN = "EVT_SW_RestartedUnknown"
    SWITCH_STP_PORT_BLOCKING = "EVT_SW_StpPortBlocking"
    SWITCH_UPGRADE_SCHEDULED = "EVT_SW_UpgradeScheduled"
    SWITCH_UPGRADED = "EVT_SW_Upgraded"

    VOUCHER_CREATED = "EVT_AD_VoucherCreated"
    VOUCHER_DELETED = "EVT_AD_VoucherDeleted"

    WIRED_CLIENT_CONNECTED = "EVT_LU_Connected"
    WIRED_CLIENT_DISCONNECTED = "EVT_LU_Disconnected"
    WIRED_CLIENT_BLOCKED = "EVT_LC_Blocked"
    WIRED_CLIENT_UNBLOCKED = "EVT_LC_Unblocked"
    WIRELESS_CLIENT_CONNECTED = "EVT_WU_Connected"
    WIRELESS_CLIENT_DISCONNECTED = "EVT_WU_Disconnected"
    WIRELESS_CLIENT_BLOCKED = "EVT_WC_Blocked"
    WIRELESS_CLIENT_UNBLOCKED = "EVT_WC_Unblocked"
    WIRELESS_CLIENT_ROAM = "EVT_WU_Roam"
    WIRELESS_CLIENT_ROAM_RADIO = "EVT_WU_RoamRadio"

    WIRED_GUEST_CONNECTED = "EVT_LG_Connected"
    WIRED_GUEST_DISCONNECTED = "EVT_LG_Disconnected"
    WIRELESS_GUEST_AUTHENTICATION_ENDED = "EVT_WG_AuthorizationEnded"
    WIRELESS_GUEST_CONNECTED = "EVT_WG_Connected"
    WIRELESS_GUEST_DISCONNECTED = "EVT_WG_Disconnected"
    WIRELESS_GUEST_ROAM = "EVT_WG_Roam"
    WIRELESS_GUEST_ROAM_RADIO = "EVT_WG_RoamRadio"

    XG_AUTO_READOPTED = "EVT_XG_AutoReadopted"
    XG_CONNECTED = "EVT_XG_Connected"
    XG_LOST_CONTACT = "EVT_XG_Lost_Contact"
    XG_OUTLET_POWER_CYCLE = "EVT_XG_OutletPowerCycle"

    IPS_ALERT = "EVT_IPS_IpsAlert"

    AD_GUEST_UNAUTHORIZED = "EVT_AD_GuestUnauthorized"
    AD_LOGIN = "EVT_AD_Login"
    AD_SCHEDULE_UPGRADE_FAILED_NOT_FOUND = "EVT_AD_ScheduleUpgradeFailedNotFound"

    HOT_SPOT_AUTHED_BY_NO_AUTH = "EVT_HS_AuthedByNoAuth"
    HOT_SPOT_AUTHED_BY_PASSWORD = "EVT_HS_AuthedByPassword"
    HOT_SPOT_VOUCHER_USED = "EVT_HS_VoucherUsed"

    USP_RPS_POWER_DENIED_BY_PSU_OVERLOAD = "EVT_USP_RpsPowerDeniedByPsuOverload"

    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> EventKey:
        """Set default enum member if an unknown value is provided."""
        LOGGER.warning("Unsupported event key %s", value)
        return EventKey.UNKNOWN


class TypedEvent(TypedDict):
    """Event type definition."""

    _id: str
    ap: str
    bytes: int
    channel: int
    client: str
    datetime: str
    duration: int
    guest: str
    gw: str
    hostname: str
    key: str
    msg: str
    network: str
    radio: str
    site_id: str
    ssid: str
    sw: str
    sw_name: str
    subsystem: str
    time: int
    user: str
    version_from: str
    version_to: str


@final
class Event(ApiItem):
    """UniFi event."""

    raw: TypedEvent

    @property
    def datetime(self) -> str:
        """Datetime of event '2020-03-01T15:35:08Z'."""
        return self.raw["datetime"]

    @property
    def key(self) -> EventKey:
        """Event key e.g. 'EVT_WU_Disconnected'."""
        key = EventKey(self.raw["key"])
        if key == EventKey.UNKNOWN:
            LOGGER.warning("Unsupported event %s", self.raw)
        return key

    @property
    def event(self) -> str:
        """Event key e.g. 'EVT_WU_Disconnected'.

        To be removed.
        """
        return self.raw["key"]

    @property
    def msg(self) -> str:
        """Event message."""
        return self.raw["msg"]

    @property
    def time(self) -> int:
        """Time of event 1583076908000."""
        return self.raw["time"]

    @property
    def mac(self) -> str:
        """MAC of client or device."""
        if self.client:
            return self.client
        if self.device:
            return self.device
        return ""

    @property
    def ap(self) -> str:
        """Access point connected to."""
        return self.raw.get("ap", "")

    @property
    def bytes(self) -> int:
        """Bytes of data consumed."""
        return self.raw.get("bytes", 0)

    @property
    def channel(self) -> int:
        """Wi-Fi channel."""
        return self.raw.get("channel", 0)

    @property
    def client(self) -> str:
        """MAC address of client."""
        return (
            self.raw.get("user")
            or self.raw.get("client")
            or self.raw.get("guest")
            or ""
        )

    @property
    def device(self) -> str:
        """MAC address of device."""
        return self.raw.get("ap") or self.raw.get("gw") or self.raw.get("sw") or ""

    @property
    def duration(self) -> int:
        """Duration."""
        return self.raw.get("duration", 0)

    @property
    def hostname(self) -> str:
        """Nice name."""
        return self.raw.get("hostname", "")

    @property
    def radio(self) -> str:
        """Radio."""
        return self.raw.get("radio", "")

    @property
    def subsystem(self) -> str:
        """Subsystem like 'lan' or 'wlan'."""
        return self.raw.get("subsystem", "")

    @property
    def site_id(self) -> str:
        """Site ID."""
        return self.raw.get("site_id", "")

    @property
    def ssid(self) -> str:
        """SSID."""
        return self.raw.get("ssid", "")

    @property
    def version_from(self) -> str:
        """Version from."""
        return self.raw.get("version_from", "")

    @property
    def version_to(self) -> str:
        """Version to."""
        return self.raw.get("version_to", "")
