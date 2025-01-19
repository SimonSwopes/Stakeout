from . import Logger, NetworkActivityDataStreamer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
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
        X = self._validation_data.data[["Flow Duration", "Total Fwd Packets", "Total Backward Packets"]]
        y_true = self._validation_data.data["Label"]
        probabilities = self._model.predict_proba(X)[:, 1]
        predictions = (probabilities >= threshold).astype(int) 

        self.logger.info("Assigning predictions to data streamer...")
        self._validation_data.assign_column(Prediction=predictions)

        # Calculate metrics
        self.logger.info("Evaluating validation performance...")
        report = classification_report(y_true, predictions, zero_division=1)
        self.logger.info(f"Validation classification report:\n{report}")

        # Write the report to a file
        self.logger.write_file("validation_report.log", report)

        # Extract and return malicious IPs
        self.logger.info("Extracting malicious IPs...")
        malicious_ips = self._validation_data.data.query("Prediction == 1")["Source IP"].unique()
        self.logger.info(f"Detected malicious IPs: {len(malicious_ips)}")
        return malicious_ips
    

    def _train_eval_model(self) -> LogisticRegression:
        self.logger.info("Training model...")
        df = self._training_data.data
        X = df[['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']]
        y = df['Label']

        self.logger.info("Splitting data into training and test sets...")
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        model = LogisticRegression(class_weight="balanced")
        model.fit(X_train, y_train)

        self.logger.info("Evaluating model...")
        y_pred = model.predict(X_test)
        report = classification_report(y_test, y_pred, zero_division=1)
        self.logger.info(f"Evaluation Classification report:\n{report}")
        self.logger.write_file("classification_report.log", report)

        return model