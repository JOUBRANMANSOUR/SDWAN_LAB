"""Compatibility entry point for the shared v4 configuration model."""

from .common.config_loader import CONFIG_DIR, PolicyBundle, load_bundle, validate_policies
from .common.model import ConfigurationError

__all__ = ["CONFIG_DIR", "ConfigurationError", "PolicyBundle", "load_bundle", "validate_policies"]
