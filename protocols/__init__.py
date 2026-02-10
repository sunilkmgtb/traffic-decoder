from . import modbus_tcp
from . import cip

# List of all active protocol modules
ENABLED_PLUGINS = [
    modbus_tcp,
    cip
]
