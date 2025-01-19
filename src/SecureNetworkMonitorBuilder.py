from . import Logger
from .lib.Loader import Loader
from .lib.NetworkActivityDataStreamer import NetworkActivityDataStreamer
from .lib.NetworkMonitorModel import NetworkMonitorModel
from .lib.SecureNetworkMonitor import SecureNetworkMonitor

class SecureNetworkMonitorBuilder:
    def __init__(self, training_directory: str, validation_directory: str = None, log_directory: str = "logs"):
        self._training_directory = training_directory
        self._validation_directory = validation_directory
        self._log_directory = log_directory

    def build(self) -> SecureNetworkMonitor:
        logger = Logger(self._log_directory, "NetworkMonitor")

        logger.info("Initializing training loader...")
        training_data_loader = Loader(self._training_directory, logger)

        logger.info("Loading training data...")
        training_data_streamer = NetworkActivityDataStreamer(training_data_loader, logger)

        logger.info(f"{"Loading Validation Data" if self._validation_directory else "Bypassing Validation..."}")
        validation_data_streamer = NetworkActivityDataStreamer(Loader(self._validation_directory, logger), logger) if self._validation_directory else None

        logger.info("Building model...")
        model = NetworkMonitorModel(training_data_streamer, validation_data_streamer, logger)
        return SecureNetworkMonitor(model)