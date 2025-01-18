from . import RegressionMonitorModel

class ModelNetworkMonitor:
    def __init__(self, model: RegressionMonitorModel):
        self._model = model

    def detect_malicious_ips(self):
        return self._model.predict_malicious_ips()
    