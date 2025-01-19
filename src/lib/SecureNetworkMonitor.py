from . import NetworkMonitorModel
from typing import List

class SecureNetworkMonitor:
    def __init__(self, model: NetworkMonitorModel):
        self._model = model

    def detect_malicious_ips(self) -> List[str]:
        return list(self._model.validate())
    