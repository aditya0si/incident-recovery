"""Isolated tenant-api-platform staging adapter.

This package is the *narrow* boundary between the reviewed recovery control
plane and the real staging tenant workload (service ``tenant-api-staging``).  It
fixes the service identity, the closed revision set, the authenticated
observation sources, and the traffic-routing recovery path.  It deliberately
does not generalise into a broad infrastructure framework: there are no
arbitrary URLs, SQL, Docker resources, or shell commands anywhere in this
package, and the model never sees a credential.
"""

from .contracts import (
    STAGING_HEALTHY_REVISION,
    STAGING_FAULTY_REVISION,
    STAGING_REVISIONS,
    STAGING_SERVICE_ID,
    StagingFaultRequest,
    StagingObservation,
    StagingSwitchRequest,
)

__all__ = [
    "STAGING_SERVICE_ID",
    "STAGING_HEALTHY_REVISION",
    "STAGING_FAULTY_REVISION",
    "STAGING_REVISIONS",
    "StagingObservation",
    "StagingSwitchRequest",
    "StagingFaultRequest",
]
