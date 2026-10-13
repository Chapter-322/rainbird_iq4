"""Rain Bird IQ4 switch platform — one on/off switch per zone."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import slugify

from .api import RainBirdAPI
from .const import CONF_DEFAULT_DURATION, DEFAULT_DURATION, DOMAIN
from .coordinator import RainBirdCoordinator
from .device import zone_device_info, zone_name

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up one switch per zone."""
    coordinators = hass.data[DOMAIN][entry.entry_id]
    coordinator: RainBirdCoordinator = coordinators["realtime"]
    satellite = (coordinators["config"].data or {}).get("satellite", {})
    duration = entry.options.get(CONF_DEFAULT_DURATION, DEFAULT_DURATION)

    async_add_entities(
        RainBirdZoneSwitch(
            coordinator,
            coordinators["api"],
            station,
            satellite.get("name", "Rain Bird IQ4"),
            duration,
            coordinators["controller_device_id"],
        )
        for station in (coordinator.data or {}).get("stations", [])
    )


class RainBirdZoneSwitch(CoordinatorEntity, SwitchEntity):
    """Starts and stops a single zone, like the official integration's switches.

    Turning it on runs the zone for the default duration set in the
    integration options; the start_zone action remains the way to choose a
    duration per run. The state follows the zone's status sensor: a paused
    zone reads as off, since nothing is watering.
    """

    _attr_has_entity_name = True
    # Named after the zone device, like the zone's status sensor.
    _attr_name = None
    _attr_icon = "mdi:sprinkler-variant"

    def __init__(
        self,
        coordinator: RainBirdCoordinator,
        api: RainBirdAPI,
        station: dict,
        satellite_name: str,
        duration_minutes: int,
        controller_device_id: str,
    ) -> None:
        super().__init__(coordinator)
        self._api = api
        self._station_id = station["id"]
        self._duration_seconds = int(duration_minutes) * 60
        satellite_id = coordinator.satellite_id
        # Deliberately not "_station_": the actions resolve their target from
        # that marker in the unique_id and must keep accepting only sensors.
        self._attr_unique_id = f"{satellite_id}_zone_switch_{self._station_id}"
        self._attr_device_info = zone_device_info(satellite_id, station, controller_device_id)
        # Same <controller>_<zone> pattern as the status sensor.
        self.entity_id = f"switch.{slugify(f'{satellite_name} {zone_name(station)}')}"

    def _station(self) -> dict:
        for station in (self.coordinator.data or {}).get("stations", []):
            if station["id"] == self._station_id:
                return station
        return {}

    @property
    def is_on(self) -> bool:
        station = self._station()
        if station.get("status") == "P":
            return False
        return bool(station.get("isRunning")) or station.get("status") == "R"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"run_minutes": self._duration_seconds // 60}

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.hass.async_add_executor_job(
            self._api.start_station, self._station_id, self._duration_seconds
        )
        # Only reached once the backend accepted the start; see
        # RainBirdCoordinator.set_optimistic_running.
        self.coordinator.set_optimistic_running(self._station_id, self._duration_seconds)
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.hass.async_add_executor_job(self._api.stop_station, self._station_id)
        self.coordinator.mark_stopped(self._station_id)
        await self.coordinator.async_request_refresh()
