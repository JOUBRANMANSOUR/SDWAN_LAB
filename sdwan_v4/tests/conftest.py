import pytest

from sdwan_v4.config_loader_v4 import load_bundle


@pytest.fixture(scope="session")
def bundle():
    return load_bundle()
