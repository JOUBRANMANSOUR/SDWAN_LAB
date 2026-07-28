import os
import platform
import shutil

import pytest


pytestmark = pytest.mark.live


@pytest.mark.skipif(os.getenv("SDWAN_RUN_LIVE") != "1", reason="requires privileged Ubuntu lab")
def test_live_prerequisites() -> None:
    assert platform.system() == "Linux"
    assert os.geteuid() == 0
    for executable in ("docker", "ovs-vsctl", "wg", "ip", "iptables", "tcpdump"):
        assert shutil.which(executable), f"missing live-test dependency: {executable}"
