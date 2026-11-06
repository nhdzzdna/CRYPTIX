"""
modules/logger.py
──────────────────
Centralised logging factory for CRYPTIX.

Usage::

    from modules.logger import get_logger
    logger = get_logger(__name__)
    logger.info("Something happened")

All loggers write to storage/logs/app.log (rotating, 5 MB, 3 backups)
and to the console when DEBUG=True.

Security rules enforced at call sites:
  • Never log passwords, keys, tokens, or message content.
  • Log user actions (login, upload, delete) at INFO level.
  • Log exceptions at ERROR level without leaking sensitive data.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler

import config

_FORMATTER = logging.Formatter(
    fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

_handler_cache: dict[str, bool] = {}   # tracks whether root handler is set up


def _setup_root_handler() -> None:
    """Configure the root handler once (idempotent)."""
    root = logging.getLogger("cryptix")
    if root.handlers:
        return

    log_path = config.LOG_PATH
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=5 * 1024 * 1024,   # 5 MB
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(_FORMATTER)
    root.addHandler(file_handler)

    if config.DEBUG:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(_FORMATTER)
        root.addHandler(console_handler)

    root.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
    root.propagate = False


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger of the 'cryptix' hierarchy.

    Parameters
    ----------
    name : str
        Typically ``__name__`` of the calling module.

    Returns
    -------
    logging.Logger
    """
    _setup_root_handler()
    # Prefix the name so all CRYPTIX loggers live under 'cryptix.*'
    if not name.startswith("cryptix"):
        logger_name = f"cryptix.{name}"
    else:
        logger_name = name
    return logging.getLogger(logger_name)
