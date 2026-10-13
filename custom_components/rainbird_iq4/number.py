"""Rain Bird IQ4 number platform — rain delay."""
from __future__ import annotations

import logging

from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import RainBirdAPI
from .const import DOMAIN
from .coordinator import RainBirdConfigCoordinator
from .device import controller_device_info

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the rain delay number."""
    coordinators = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([RainBirdRainDelayNumber(coordinators["config"], coordinators["api"])])


class RainBirdRainDelayNumber(CoordinatorEntity, NumberEntity):
    """Rain delay in days, settable from the device page (0 clears it).

    Same range as the set_rain_delay action. The Rain Delay sensor stays as
    it was so existing history and automations keep working.
    """

    _attr_has_entity_name = True
    _attr_translation_key = "rain_delay"
    _attr_icon = "mdi:weather-rainy"
    _attr_native_min_value = 0
    _attr_native_max_value = 14
    _attr_native_step = 1
    _attr_native_unit_of_measurement = UnitOfTime.DAYS
    _attr_mode = NumberMode.SLIDER

    def __init__(self, coordinator: RainBirdConfigCoordinator, api: RainBirdAPI) -> None:
        super().__init__(coordinator)
        self._api = api
        self._attr_unique_id = f"{coordinator.satellite_id}_rain_delay_number"

    @property
    def device_info(self):
        satellite = (self.coordinator.data or {}).get("satellite", {})
        return controller_device_info(self.coordinator.satellite_id, satellite)

    @property
    def native_value(self) -> int:
        connection = (self.coordinator.data or {}).get("connection", {})
        return connection.get("rainDelayDaysRemaining") or 0

    async def async_set_native_value(self, value: float) -> None:
        await self.hass.async_add_executor_job(
            self._api.set_rain_delay, self.coordinator.satellite_id, int(value)
        )
        await self.coordinator.async_request_refresh()
