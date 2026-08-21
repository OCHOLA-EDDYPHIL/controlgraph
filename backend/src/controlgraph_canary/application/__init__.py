"""Cloud-independent use cases and narrow provider protocols."""

from controlgraph_canary.application.monitoring import (
    MonitoringCollectedPoint,
    MonitoringCollectionError,
    MonitoringCollectionErrorCode,
    MonitoringCollectionResult,
    MonitoringCollectionScope,
    MonitoringQueryCollection,
    MonitoringQueryCollector,
    MonitoringWindowCollector,
)

__all__ = [
    "MonitoringCollectedPoint",
    "MonitoringCollectionError",
    "MonitoringCollectionErrorCode",
    "MonitoringCollectionResult",
    "MonitoringCollectionScope",
    "MonitoringQueryCollection",
    "MonitoringQueryCollector",
    "MonitoringWindowCollector",
]
