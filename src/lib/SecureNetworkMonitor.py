from . import NetworkMonitorModel

class SecureNetworkMonitor:
    def __init__(self, model: NetworkMonitorModel):
        self._model = model

    def detect_malicious_ips(self):
        return self._model.predict_malicious_ips()
    