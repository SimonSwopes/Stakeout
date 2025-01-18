import argparse
import sys
import logging
from pandas import DataFrame, read_csv, concat
from numpy import random
from glob import glob
from os import path, makedirs
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from typing import List

def main():
    logger = Logger("logs", "MainLogger")

    parser = argparse.ArgumentParser(description="Network Activity Monitor")
    parser.add_argument("-t", "--training", help="Training directory", required=True)
    parser.add_argument("-o", "--output", help="Output directory", default="logs")
    args = parser.parse_args()

    # Build and run
    monitor = ModelNetworkMonitorBuilder(args.training, args.output).build()
    malicious_ips = monitor.detect_malicious_ips()
    logger.info(f"Malicious IPs found: {malicious_ips}")

class Logger:

    def __init__(self, log_directory: str = "logs", logger_name: str = "AppLogger"):
        self.log_directory = log_directory
        if not path.exists(self.log_directory):
            makedirs(self.log_directory)

        # Create a logger
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG)

        # Add a file handler
        file_handler = logging.FileHandler(path.join(self.log_directory, "application.log"))
        file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        self.logger.addHandler(file_handler)

        # Add a console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        self.logger.addHandler(console_handler)

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


class DataLoader:
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


class NetworkActivityDataStreamer:
    def __init__(self, data_loader: DataLoader, logger: Logger):
        self.logger = logger
        raw_data = data_loader.load_data()
        self._data = self._format_data(raw_data)

    @property
    def data(self) -> DataFrame:
        return self._data

    def _format_data(self, data: DataFrame) -> DataFrame:
        self._validate_columns(data)

        # Synthesize source/dest IP addresses
        data['Source IP'] = self._synthesize_ip(len(data))
        data['Destination IP'] = self._synthesize_ip(len(data))

        # Convert 'Label' to 0/1
        data['Label'] = data['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

        # Keep only the relevant columns
        data = data[['Source IP', 'Destination IP', 'Flow Duration',
                     'Total Fwd Packets', 'Total Backward Packets', 'Label']]

        data.dropna(inplace=True)

        # Scale numeric features
        scaler = MinMaxScaler()
        data[['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']] = \
            scaler.fit_transform(data[['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']])

        return data

    def _validate_columns(self, data: DataFrame) -> None:
        required_cols = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Label']
        if not all(col in data.columns for col in required_cols):
            self.logger.error("Data is in unexpected format. Expected columns: "
                              "'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Label'")
            sys.exit(1)  # or raise ValueError

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

class RegressionMonitorModel:
    def __init__(self, data_streamer: NetworkActivityDataStreamer, logger: Logger):
        self._data_streamer = data_streamer
        self.logger = logger
        self._model = self._train_eval_model()

    def predict_malicious_ips(self) -> list:
        X = self._data_streamer.data[["Flow Duration", "Total Fwd Packets", "Total Backward Packets"]]
        predictions = self._model.predict(X)

        # Add predictions to the data
        self._data_streamer.assign_column(Prediction=predictions)

        # Filter out malicious IPs
        malicious_ips = self._data_streamer.data.query("Prediction == 1")["Source IP"].unique()

        self._store_malicious_ips(malicious_ips)
        return malicious_ips

    def _store_malicious_ips(self, malicious_ips: list) -> None:
        log_data = "\n".join(malicious_ips)
        self.logger.write_file("malicious_ips.log", log_data)

    def _train_eval_model(self) -> LogisticRegression:
        df = self._data_streamer.data
        X = df[['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']]
        y = df['Label']

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        model = LogisticRegression()
        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)
        report = classification_report(y_test, y_pred)
        self.logger.write_file("classification_report.log", report)

        return model


class ModelNetworkMonitor:
    def __init__(self, model: RegressionMonitorModel):
        self._model = model

    def detect_malicious_ips(self):
        return self._model.predict_malicious_ips()


class ModelNetworkMonitorBuilder:
    def __init__(self, training_directory: str = None, log_directory: str = "logs"):
        self._training_directory = training_directory
        self._log_directory = log_directory

    def build(self) -> ModelNetworkMonitor:
        logger = Logger(self._log_directory, "NetworkMonitor")
        data_loader = DataLoader(self._training_directory, logger)
        data_streamer = NetworkActivityDataStreamer(data_loader, logger)
        model = RegressionMonitorModel(data_streamer, logger)
        return ModelNetworkMonitor(model)


if __name__ == '__main__':
    main()
