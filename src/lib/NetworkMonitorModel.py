from . import Logger, NetworkActivityDataStreamer
from .constants import *
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from imblearn.over_sampling import SMOTE
from typing import List

class NetworkMonitorModel:
    def __init__(self, training_data: NetworkActivityDataStreamer, validation_data: NetworkActivityDataStreamer, logger: Logger):
        self._training_data = training_data
        self._validation_data = validation_data
        self.logger = logger
        self._model = self._train_eval_model()

    def validate(self, threshold: float = 0.5) -> List[str]:
        if not self._validation_data:
            self.logger.warning("Validate Invoked without validation data. Bypassing...")
            return []

        self.logger.info("Predicting malicious IPs...")
        X = self._validation_data.data[feature_nodes]
        y_true = self._validation_data.data[target_node]
        probabilities = self._model.predict_proba(X)[:, 1]
        predictions = (probabilities >= threshold).astype(int) 

        self.logger.info("Assigning predictions to data streamer...")
        self._validation_data.assign_column(**{prediction_column: predictions})

        self.logger.info("Evaluating validation performance...")
        report = classification_report(y_true, predictions, zero_division=1)
        self.logger.info(f"Validation classification report:\n{report}")
        self.logger.write_file("validation_report.log", report)

        self.logger.info("Extracting malicious IPs...")
        malicious_ips = self._validation_data.data.query(f"{prediction_column}== 1")[value_column].unique()
        self.logger.info(f"Detected malicious IPs: {len(malicious_ips)}")

        return malicious_ips
    

    def _train_eval_model(self) -> LogisticRegression:
        self.logger.info("Training model...")
        df = self._training_data.data
        X = df[feature_nodes]
        y = df[target_node]

        self.logger.info("Splitting data into training and test sets...")
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

        # This helps with imbalanced data by oversampling the minority class
        smote = SMOTE(random_state=42)
        X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)


        model = LogisticRegression(class_weight="balanced")
        model.fit(X_train_resampled, y_train_resampled)

        self.logger.info("Evaluating model...")
        y_pred = model.predict(X_test)
        report = classification_report(y_test, y_pred, zero_division=1)
        self.logger.info(f"Evaluation Classification report:\n{report}")
        self.logger.write_file("classification_report.log", report)

        return model