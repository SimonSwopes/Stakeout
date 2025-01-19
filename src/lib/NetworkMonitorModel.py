from . import Logger, NetworkActivityDataStreamer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from typing import List

class NetworkMonitorModel:
    def __init__(self, data_streamer: NetworkActivityDataStreamer, logger: Logger):
        self._data_streamer = data_streamer
        self.logger = logger
        self._model = self._train_eval_model()

    def predict_malicious_ips(self, threshold: float = 0.5) -> List[str]:
        self.logger.info("Predicting malicious IPs...")
        X = self._data_streamer.data[["Flow Duration", "Total Fwd Packets", "Total Backward Packets"]]
        probabilities = self._model.predict_proba(X)[:, 1]
        predictions = (probabilities >= threshold).astype(int) 

        self.logger.info("Assigning predictions to data streamer...")
        self._data_streamer.assign_column(Prediction=predictions)

        self.logger.info("Extracting malicious IPs...")
        malicious_ips = self._data_streamer.data.query("Prediction == 1")["Source IP"].unique()

        self.logger.info("Storing malicious IPs...")
        self._log_results_summary(malicious_ips)
        return malicious_ips
    

    def _log_results_summary(self, malicious_ips: list) -> None:
        total_ips = len(self._data_streamer.data["Source IP"].unique())
        total_malicious_ips = len(malicious_ips)
    
        # Compute key metrics
        true_positives = len(self._data_streamer.data.query("Label == 1 and Prediction == 1"))
        false_positives = len(self._data_streamer.data.query("Label == 0 and Prediction == 1"))
        false_negatives = len(self._data_streamer.data.query("Label == 1 and Prediction == 0"))
    
        # Precision and Recall
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    
        self.logger.info(f"{total_malicious_ips} out of {total_ips} predicted as malicious.")
        self.logger.info(f"Precision: {precision:.2f}, Recall: {recall:.2f}")



    def _train_eval_model(self) -> LogisticRegression:
        self.logger.info("Training model...")
        df = self._data_streamer.data
        X = df[['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']]
        y = df['Label']

        self.logger.info("Splitting data into training and test sets...")
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        model = LogisticRegression(class_weight="balanced")
        model.fit(X_train, y_train)

        self.logger.info("Evaluating model...")
        y_pred = model.predict(X_test)
        report = classification_report(y_test, y_pred, zero_division=1)
        self.logger.write_file("classification_report.log", report)

        return model