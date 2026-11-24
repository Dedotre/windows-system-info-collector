from winsysinfo.units import format_bytes, format_days, percent_used


def test_format_bytes_zero_and_negative():
    assert format_bytes(0) == "0B"
    assert format_bytes(-5) == "0B"


def test_format_bytes_boundaries():
    assert format_bytes(1023) == "1023B"
    assert format_bytes(1024) == "1.0KB"
    assert format_bytes(1536) == "1.5KB"
    assert format_bytes(1024**3) == "1.0GB"


def test_format_bytes_large_values():
    assert format_bytes(int(1024**4 * 2.5)) == "2.5TB"
    assert format_bytes(1024**5) == "1.0PB"


def test_percent_used():
    assert percent_used(100, 25) == 75.0
    assert percent_used(0, 0) == 0.0
    assert percent_used(3, 3) == 0.0


def test_format_days_pluralises():
    assert format_days(0) == "0 days"
    assert format_days(1) == "1 day"
    assert format_days(2) == "2 days"
