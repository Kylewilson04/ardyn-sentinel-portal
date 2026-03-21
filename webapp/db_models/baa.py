"""BAA (Business Associate Agreement) Model - HIPAA Compliance"""
import uuid
import time
from typing import Dict
from dataclasses import dataclass
from enum import Enum

class BAAStatus(str, Enum):
    DRAFT = "draft"
    PENDING_SIGNATURE = "pending_signature"
    FULLY_EXECUTED = "fully_executed"
    EXPIRED = "expired"

@dataclass
class BusinessAssociateAgreement:
    id: str
    org_id: str
    status: BAAStatus
    covered_entity_name: str
    covered_entity_address: str
    ba_name: str = "Ardyn AI, Inc."
    breach_notification_hours: int = 24
    created_at: float = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "org_id": self.org_id, "status": self.status.value,
            "covered_entity_name": self.covered_entity_name,
            "covered_entity_address": self.covered_entity_address,
            "ba_name": self.ba_name,
            "breach_notification_hours": self.breach_notification_hours,
            "created_at": self.created_at
        }

def create_baa(org_id: str, covered_entity_name: str, covered_entity_address: str) -> BusinessAssociateAgreement:
    return BusinessAssociateAgreement(
        id=str(uuid.uuid4()),
        org_id=org_id,
        status=BAAStatus.DRAFT,
        covered_entity_name=covered_entity_name,
        covered_entity_address=covered_entity_address
    )
