from . import Logger
from pandas import DataFrame, read_csv, concat
from os import path
from glob import glob

class Loader:
    def __init__(self, data_directory: str, logger: Logger):
        self._data_directory = data_directory
        self.logger = logger

    def load_data(self) -> DataFrame:
        csv_files = glob(path.join(self._data_directory, '*.csv'))

        if not csv_files:
            msg = f"No CSV files found in the data directory: {self._data_directory}"
            self.logger.error(msg)
            raise FileNotFoundError(msg)

        data_sets = []
        for file in csv_files:
            self.logger.info(f"Loading CSV file: {file}")
            data_sets.append(read_csv(file))

        return concat(data_sets, ignore_index=True)
    