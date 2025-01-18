from . import Loader
from . import Logger
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
        data['Source IP'] = self._synthesize_ip(len(data))
        data['Destination IP'] = self._synthesize_ip(len(data))

        self.logger.info("Mapping labels...")
        data['Label'] = data['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

        self.logger.info("Selecting relevant columns removing missing data...")
        data = data[['Source IP', 'Destination IP', 'Flow Duration',
                     'Total Fwd Packets', 'Total Backward Packets', 'Label']]
        
        data = data.dropna()

        self.logger.info("Normalizing data...")
        scaler = MinMaxScaler()
        data[['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']] = \
            scaler.fit_transform(data[['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']])

        return data
    
    def _validate_columns(self, data: DataFrame) -> None:
        self.logger.info("Validating data columns...")
        required_cols = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Label']
        if not all(col in data.columns for col in required_cols):
            self.logger.error("Data is in unexpected format. Expected columns: "
                              "'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Label'")
            raise ValueError("Data is in unexpected format. Expected columns: ")
                             

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