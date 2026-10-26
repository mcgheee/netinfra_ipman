import pytest

from netinfra_ipman.config import AppConfig, load_config


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), True, "100"])
def test_scan_rate_must_be_finite_positive_number(value):
    with pytest.raises(ValueError, match="scan_start_rate"):
        AppConfig(scan_start_rate=value)


@pytest.mark.parametrize("value", [-1, 1.5, True, "4096"])
def test_confirmation_threshold_must_be_nonnegative_integer(value):
    with pytest.raises(ValueError, match="manual_scan_confirmation_threshold"):
        AppConfig(manual_scan_confirmation_threshold=value)


@pytest.mark.parametrize("name", ["large_subnet_prefix", "max_subnet_prefix"])
def test_retired_prefix_settings_explain_migration(tmp_path, name):
    path = tmp_path / "config.yml"
    path.write_text(f"{name}: 16\n")
    with pytest.raises(ValueError, match="manual_scan_confirmation_threshold") as error:
        load_config(path)
    assert name in str(error.value)
    assert "all IPv4 subnet sizes are supported" in str(error.value)


def test_scan_defaults_and_zero_confirmation_threshold():
    config = AppConfig()
    assert config.scan_concurrency == 128
    assert config.scan_start_rate == 100
    assert config.manual_scan_confirmation_threshold == 4096
    assert AppConfig(manual_scan_confirmation_threshold=0).manual_scan_confirmation_threshold == 0
