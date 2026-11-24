import sys

import pytest

from winsysinfo import probe


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_live_probe_returns_json():
    result = probe.run_probe(timeout=120)
    assert result.error is None
    assert result.data is not None
    assert "os" in result.data
    assert "hotfixes" in result.data
