"""Backward-compat shim for environment variables renamed during the Hotwash rebrand."""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


def getenv_compat(new_name: str, legacy_name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.getenv(new_name)
    if value is not None:
        return value
    legacy = os.getenv(legacy_name)
    if legacy is not None:
        logger.warning("%s is deprecated; rename to %s", legacy_name, new_name)
        return legacy
    return default
