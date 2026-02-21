"""Monitoring and health checks for Policy Test Bench"""
from datetime import datetime
from typing import Dict, Any


class HealthCheck:
    @staticmethod
    def check_system() -> Dict[str, Any]:
        try:
            return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e), "timestamp": datetime.utcnow().isoformat()}


class Metrics:
    def __init__(self):
        self.metrics = {"policies_tested": 0, "violations_found": 0}
    
    def record_test(self, violations: int = 0):
        self.metrics["policies_tested"] += 1
        self.metrics["violations_found"] += violations
    
    def get_metrics(self) -> Dict[str, Any]:
        return {**self.metrics, "timestamp": datetime.utcnow().isoformat()}


_metrics = Metrics()


def get_metrics() -> Dict[str, Any]:
    return _metrics.get_metrics()


def get_health_status() -> Dict[str, Any]:
    return {"system": HealthCheck.check_system(), "metrics": get_metrics()}

