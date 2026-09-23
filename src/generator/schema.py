"""Authentication event schema definitions and validation models for CampaignScope."""

from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional
import json


RAW_COLUMNS: List[str] = [
    "timestamp",
    "ip_address",
    "username",
    "endpoint",
    "user_agent",
    "status_code",
    "country",
    "response_time",
    "device_id",
]

EVALUATION_COLUMNS: List[str] = [
    "timestamp",
    "ip_address",
    "username",
    "endpoint",
    "user_agent",
    "status_code",
    "country",
    "response_time",
    "device_id",
    "is_malicious",
    "campaign_id",
    "attack_type",
]


@dataclass
class AuthenticationEvent:
    """Represents a single authentication attempt event."""

    timestamp: str
    ip_address: str
    username: str
    endpoint: str
    user_agent: str
    status_code: int
    country: str
    response_time: int
    device_id: str
    # Ground-truth evaluation fields (strictly isolated from unsupervised detection)
    is_malicious: int = 0
    campaign_id: str = "benign"
    attack_type: str = "benign"

    def to_raw_dict(self) -> Dict[str, Any]:
        """Returns only the raw telemetry fields available to production ingestion."""
        return {
            "timestamp": self.timestamp,
            "ip_address": self.ip_address,
            "username": self.username,
            "endpoint": self.endpoint,
            "user_agent": self.user_agent,
            "status_code": self.status_code,
            "country": self.country,
            "response_time": self.response_time,
            "device_id": self.device_id,
        }

    def to_evaluation_dict(self) -> Dict[str, Any]:
        """Returns the full record including ground-truth labels for Phase 9 benchmark scoring."""
        return asdict(self)

    def to_json(self, include_ground_truth: bool = False) -> str:
        """Serializes the event to a JSON string."""
        data = self.to_evaluation_dict() if include_ground_truth else self.to_raw_dict()
        return json.dumps(data)


@dataclass
class EventBatch:
    """A batch container for authentication events."""

    events: List[AuthenticationEvent]

    def __len__(self) -> int:
        return len(self.events)

    def to_raw_dicts(self) -> List[Dict[str, Any]]:
        return [e.to_raw_dict() for e in self.events]

    def to_evaluation_dicts(self) -> List[Dict[str, Any]]:
        return [e.to_evaluation_dict() for e in self.events]
