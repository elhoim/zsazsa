import logging
from pymisp import PyMISP
import config

logger = logging.getLogger(__name__)


def get_misp() -> PyMISP:
    # Default to verifying the certificate when the setting is absent, so an
    # older config file does not silently disable verification.
    return PyMISP(config.MISP_URL, config.MISP_KEY, getattr(config, "MISP_VERIFYCERT", True))


def get_misp_webapp() -> PyMISP:
    return PyMISP(config.MISP_WEBAPP_URL, config.MISP_WEBAPP_KEY,
                  getattr(config, "MISP_WEBAPP_VERIFYCERT", True))
