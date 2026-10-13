"""Device registry helpers shared by the platforms.

The controller is the parent device. Since v1.8.0 every zone is a device of
its own, linked to the controller through via_device, so each zone can sit in
its own area and has its own page, as in the official Rain Bird integration.
"""
from __future__ import annotations

import inspect

from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN

# Home Assistant 2026.8 links a device to its parent by the parent's registry
# id (via_device_id) and deprecates the identifier tuple (via_device), which
# stops working in 2027.8. Older releases only accept the tuple, and the
# manifest still supports them, so the form is chosen by what this release's
# registry accepts.
_USE_VIA_DEVICE_ID = (
    "via_device_id"
    in inspect.signature(dr.DeviceRegistry.async_get_or_create).parameters
)


def controller_identifier(satellite_id: int | str) -> tuple[str, str]:
    """Identifier of the controller device."""
    return (DOMAIN, str(satellite_id))


def controller_device_info(satellite_id: int | str, satellite: dict) -> DeviceInfo:
    """Full device info of the controller."""
    return DeviceInfo(
        identifiers={controller_identifier(satellite_id)},
        name=satellite.get("name", "Rain Bird IQ4"),
        manufacturer="Rain Bird",
        model=satellite.get("model", "Rain Bird IQ4"),
        sw_version=satellite.get("version"),
    )


def zone_name(station: dict) -> str:
    """Display name of a zone, as the controller reports it."""
    return station.get("name") or f"Station {station.get('terminal', station.get('id'))}"


def zone_device_info(
    satellite_id: int | str, station: dict, controller_device_id: str
) -> DeviceInfo:
    """Device info of a single zone, attached to its controller.

    controller_device_id is the registry id of the controller device, which
    async_setup_entry registers before any platform loads.
    """
    info = DeviceInfo(
        identifiers={(DOMAIN, f"{satellite_id}_station_{station['id']}")},
        name=zone_name(station),
        manufacturer="Rain Bird",
    )
    if _USE_VIA_DEVICE_ID:
        info["via_device_id"] = controller_device_id
    else:
        info["via_device"] = controller_identifier(satellite_id)
    return info
