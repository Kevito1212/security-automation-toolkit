from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict


_LOGGER_NAME = "sat"
_CONFIGURED = False


def setup_logger(cfg: Dict[str, Any]) -> logging.Logger:
    """
    Configura logging em console + arquivo.
    Deve ser chamado UMA vez no início da CLI.
    """
    global _CONFIGURED

    logger = logging.getLogger(_LOGGER_NAME)
    if _CONFIGURED:
        return logger

    level_str = str(cfg["logging"]["level"]).upper()
    level = getattr(logging, level_str, logging.INFO)
    logger.setLevel(level)
    logger.propagate = False  # evita logs duplicados

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # console
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(formatter)

    # arquivo
    log_file = Path(cfg["logging"]["file"])
    log_file.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(formatter)

    logger.addHandler(ch)
    logger.addHandler(fh)

    _CONFIGURED = True
    return logger


def get_logger(module_name: str) -> logging.Logger:
    return logging.getLogger(f"{_LOGGER_NAME}.{module_name}")
