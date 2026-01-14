import logging

from functions import logging as logging_utils


def test_configure_module_logger_inits_without_root_handlers():
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level
    try:
        root_logger.handlers = []
        root_logger.setLevel(logging.NOTSET)

        logger = logging_utils.configure_module_logger("jk.test")

        assert logger.handlers == root_logger.handlers
        assert len(logger.handlers) == 1
        assert logger.propagate is False
        assert logger.level == logging.INFO
    finally:
        root_logger.handlers = original_handlers
        root_logger.setLevel(original_level)


def test_configure_module_logger_reuses_existing_handlers():
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level
    try:
        handler = logging.StreamHandler()
        root_logger.handlers = [handler]
        root_logger.setLevel(logging.WARNING)

        logger = logging_utils.configure_module_logger("jk.reuse")
        second_call_logger = logging_utils.configure_module_logger("jk.reuse")

        assert logger is second_call_logger
        assert logger.handlers == [handler]
        assert logger.propagate is False
        assert getattr(logger, "_jk_configured", False) is True
    finally:
        root_logger.handlers = original_handlers
        root_logger.setLevel(original_level)
