import unittest

from printerhmi_agent.telemetry import merge_status, normalized_status, subscription_for


class TelemetryTests(unittest.TestCase):
    def test_dynamic_subscription_includes_discovered_devices(self):
        subscription = subscription_for(
            ["print_stats", "extruder", "extruder1", "heater_bed", "fan_generic chamber"]
        )
        self.assertIn("print_stats", subscription)
        self.assertIn("extruder1", subscription)
        self.assertIn("fan_generic chamber", subscription)
        self.assertIsNone(subscription["extruder1"])

    def test_partial_updates_preserve_previous_fields(self):
        status = {"extruder": {"temperature": 200.0, "target": 210.0}}
        merge_status(status, {"extruder": {"temperature": 201.5}})
        self.assertEqual(status["extruder"]["temperature"], 201.5)
        self.assertEqual(status["extruder"]["target"], 210.0)

    def test_normalized_snapshot_prefers_virtual_sd_progress(self):
        normalized = normalized_status({
            "print_stats": {"state": "printing", "filename": "part.gcode"},
            "virtual_sdcard": {"progress": 0.42},
            "display_status": {"progress": 0.10},
            "extruder": {"temperature": 201.5, "target": 210.0},
            "temperature_sensor enclosure": {
                "temperature": 32.0,
                "humidity": 48.5,
            },
            "temperature_fan controller": {
                "temperature": 40.0,
                "target": 35.0,
                "speed": 0.6,
                "rpm": 4200,
            },
        })
        self.assertEqual(normalized["print"]["progress"], 0.42)
        self.assertEqual(normalized["temperatures"]["extruder"]["target"], 210.0)
        self.assertEqual(
            normalized["temperatures"]["temperature_sensor enclosure"]["humidity"],
            48.5,
        )
        self.assertEqual(
            normalized["fans"]["temperature_fan controller"]["rpm"],
            4200,
        )


if __name__ == "__main__":
    unittest.main()
