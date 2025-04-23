"""UniFi networks."""

from ..models.message import MessageKey
from ..models.network import Network, NetworkListRequest
from .api_handlers import APIHandler


class Networks(APIHandler[Network]):
    """Represents network configurations."""

    obj_id_key = "_id"
    item_cls = Network
    process_messages = (MessageKey.NETWORK_CONF_UPDATED,)
    api_request = NetworkListRequest.create()
