from . import Logger
from .lib.Loader import Loader
from .lib.NetworkActivityDataStreamer import NetworkActivityDataStreamer
from .lib.NetworkMonitorModel import NetworkMonitorModel
from .lib.SecureNetworkMonitor import SecureNetworkMonitor

class SecureNetworkMonitorBuilder:
    def __init__(self, training_directory: str = None, log_directory: str = "logs"):
        self._training_directory = training_directory
        self._log_directory = log_directory

    def build(self) -> SecureNetworkMonitor:
        logger = Logger(self._log_directory, "NetworkMonitor")
        logger.info("Creating Data Loader...")
        data_loader = Loader(self._training_directory, logger)
        logger.info("Loading data...")
        data_streamer = NetworkActivityDataStreamer(data_loader, logger)
        logger.info("Building model...")
        model = NetworkMonitorModel(data_streamer, logger)
        return SecureNetworkMonitor(model)