from . import Logger, NetworkActivityDataStreamer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

class NetworkMonitorModel:
    def __init__(self, data_streamer: NetworkActivityDataStreamer, logger: Logger):
        self._data_streamer = data_streamer
        self.logger = logger
        self._model = self._train_eval_model()

    def predict_malicious_ips(self) -> list:
        self.logger.info("Predicting malicious IPs...")
        X = self._data_streamer.data[["Flow Duration", "Total Fwd Packets", "Total Backward Packets"]]
        predictions = self._model.predict(X)

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
        amount_correct = len(self._data_streamer.data.query("Label == 1 and Prediction == 1"))
        amount_incorrect = len(self._data_streamer.data.query("Label == 0 and Prediction == 1"))
        self.logger.info(f"{total_malicious_ips} out of {total_ips} predicted as malicious. {amount_correct} were correct and {amount_incorrect} were incorrect.")

        log_data = "\n".join(malicious_ips)
        self.logger.write_file("malicious_ips.log", log_data)



    def _train_eval_model(self) -> LogisticRegression:
        self.logger.info("Training model...")
        df = self._data_streamer.data
        X = df[['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']]
        y = df['Label']

        self.logger.info("Splitting data into training and test sets...")
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        model = LogisticRegression()
        model.fit(X_train, y_train)

        self.logger.info("Evaluating model...")
        y_pred = model.predict(X_test)
        report = classification_report(y_test, y_pred, zero_division=1)
        self.logger.write_file("classification_report.log", report)

        return model