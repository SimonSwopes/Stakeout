import logging
from os import path, makedirs
from sys import stdout

class Logger:

    def __init__(self, log_directory: str = "logs", logger_name: str = "AppLogger"):
        # Create a logger
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG)

        # Add a console handler
        console_handler = logging.StreamHandler(stdout)
        console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        self.logger.addHandler(console_handler)

        self.log_directory = log_directory
        if not path.exists(self.log_directory):
            makedirs(self.log_directory)
            self.logger.info(f"Created log directory: {self.log_directory}")

        # Add a file handler
        file_handler = logging.FileHandler(path.join(self.log_directory, "application.log"))
        file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        self.logger.addHandler(file_handler)

    def info(self, message: str) -> None:
        self.logger.info(message)

    def error(self, message: str) -> None:
        self.logger.error(message)

    def warning(self, message: str) -> None:
        self.logger.warning(message)

    def write_file(self, filename: str, data: str, mode: str = "w") -> None:
        try:
            with open(path.join(self.log_directory, filename), mode) as file:
                file.write(data)
        except IOError as e:
            self.logger.error(f"Error writing to file {filename}: {e}")