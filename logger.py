# -*- coding: utf-8 -*-

import logging
import config


def setup_logger():
    """Configure the logger."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(config.LOG_FILE),  # Log to file
            logging.StreamHandler()                # Log to console
        ]
    )
    return logging.getLogger(__name__)


logger = setup_logger()