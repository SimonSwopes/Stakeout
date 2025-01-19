from . import Loader
from . import Logger
from .constants import *
from typing import List
from pandas import DataFrame
from numpy import random
from sklearn.preprocessing import MinMaxScaler


class NetworkActivityDataStreamer:
    def __init__(self, data_loader: Loader, logger: Logger):
        self.logger = logger
        raw_data = data_loader.load_data()
        self._data = self._format_data(raw_data)

    @property
    def data(self) -> DataFrame:
        return self._data

    def _format_data(self, data: DataFrame) -> DataFrame:
        self.logger.info("Formatting data...")
        self._validate_columns(data)

        self.logger.info("Synthesizing IP addresses...")
        data[value_column] = self._synthesize_ip(len(data))

        self.logger.info("Mapping labels...")
        data[target_node] = data[target_node].apply(lambda x: 0 if x == positive_label else 1)

        self.logger.info("Selecting relevant columns removing missing data...")
        data = data[feature_nodes + [target_node] + [value_column]].copy()
        
        data = data.dropna()

        self.logger.info("Normalizing data...")
        scaler = MinMaxScaler()
        data[feature_nodes] = \
            scaler.fit_transform(data[feature_nodes])

        return data
    
    def _validate_columns(self, data: DataFrame) -> None:
        self.logger.info("Validating data columns...")
        required_cols = feature_nodes + [target_node]
        if not all(col in data.columns for col in required_cols):
            self.logger.error(f"Data is in unexpected format. Expected columns: {required_cols}")
            raise ValueError(f"Data is in unexpected format. Expected columns: {required_cols}")
                             

    def _synthesize_ip(self, num: int) -> List[str]:
        return [
            f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
            for _ in range(num)
        ]

    def assign_column(self, **kwargs) -> None:
        self._data = self._data.assign(**kwargs)

    def __getitem__(self, key):
        return self._data.__getitem__(key)

    def __setitem__(self, key, value):
        self._data.__setitem__(key, value)