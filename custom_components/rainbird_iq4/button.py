"""Rain Bird IQ4 button platform — manual refresh."""
from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .api import RainBirdAPI
from .coordinator import RainBirdCoordinator, RainBirdConfigCoordinator, RainBirdProgramCoordinator
from .device import controller_device_info

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Rain Bird IQ4 buttons from a config entry."""
    coordinators = hass.data[DOMAIN][entry.entry_id]
    entities: list[ButtonEntity] = [RainBirdRefreshButton(coordinators)]
    program_coordinator = coordinators["program"]
    for program in (program_coordinator.data or {}).get("programs", []):
        entities.append(RainBirdRunProgramButton(coordinators, program))
    async_add_entities(entities)


class RainBirdRefreshButton(ButtonEntity):
    """Button to force a refresh of all Rain Bird coordinators."""

    _attr_has_entity_name = True
    _attr_translation_key = "refresh"

    def __init__(self, coordinators: dict) -> None:
        self._coordinators = coordinators
        coordinator = coordinators["realtime"]
        satellite_id = coordinator.satellite_id
        self._attr_unique_id = f"{satellite_id}_refresh"
        self._attr_icon = "mdi:refresh"

    @property
    def device_info(self) -> DeviceInfo:
        coordinator = self._coordinators["realtime"]
        config_coordinator = self._coordinators["config"]
        satellite = config_coordinator.data.get("satellite", {}) if config_coordinator.data else {}
        return DeviceInfo(
            identifiers={(DOMAIN, str(coordinator.satellite_id))},
            name=satellite.get("name", "Rain Bird IQ4"),
            manufacturer="Rain Bird",
            model=satellite.get("model", "Rain Bird IQ4"),
            sw_version=satellite.get("version"),
        )

    async def async_press(self) -> None:
        """Force refresh all coordinators."""
        _LOGGER.debug("Manual refresh triggered")
        for key, coordinator in self._coordinators.items():
            if key in ("realtime", "config", "program"):
                await coordinator.async_request_refresh()


class RainBirdRunProgramButton(ButtonEntity):
    """Runs a saved program now, like the start_program action.

    One per program, including programs with no schedule: running one by hand
    is still possible from the app, with the program's own run times.
    """

    _attr_has_entity_name = True
    _attr_translation_key = "run_program"
    _attr_icon = "mdi:play-circle-outline"

    def __init__(self, coordinators: dict, program: dict) -> None:
        self._api: RainBirdAPI = coordinators["api"]
        self._config_coordinator: RainBirdConfigCoordinator = coordinators["config"]
        self._program_coordinator: RainBirdProgramCoordinator = coordinators["program"]
        self._realtime: RainBirdCoordinator = coordinators["realtime"]
        self._program_id = program["id"]
        satellite_id = self._realtime.satellite_id
        # Not "_program_": the actions resolve programs from that marker in
        # the unique_id and must keep accepting only program sensors.
        self._attr_unique_id = f"{satellite_id}_run_pgm_{self._program_id}"
        self._attr_translation_placeholders = {
            "program": program.get("shortName") or str(self._program_id)
        }

    @property
    def device_info(self) -> DeviceInfo:
        satellite = (self._config_coordinator.data or {}).get("satellite", {})
        return controller_device_info(self._realtime.satellite_id, satellite)

    async def async_press(self) -> None:
        await self.hass.async_add_executor_job(self._api.start_program, self._program_id)
        # Program runs show up in the live status, so a refresh is enough;
        # no optimistic state is needed (see _handle_start_program).
        await self._program_coordinator.async_request_refresh()
        await self._realtime.async_request_refresh()
