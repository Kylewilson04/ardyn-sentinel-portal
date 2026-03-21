"""Matter Isolation System - Legal Case Management

Provides strict isolation between legal matters (cases).
Each matter is a silo - documents, conversations, and data
are scoped to a specific matter and cannot leak between matters.
"""
import uuid
import time
from typing import Optional, List, Dict
from dataclasses import dataclass
from enum import Enum

class MatterStatus(str, Enum):
    ACTIVE = "active"
    PENDING = "pending"
    CLOSED = "closed"
    ARCHIVED = "archived"
    FROZEN = "frozen"

class MatterType(str, Enum):
    LITIGATION = "litigation"
    TRANSACTIONAL = "transactional"
    REGULATORY = "regulatory"
    IP = "ip"
    CORPORATE = "corporate"
    EMPLOYMENT = "employment"
    OTHER = "other"

@dataclass
class Matter:
    id: str
    org_id: str
    client_name: str
    case_number: Optional[str]
    matter_name: str
    matter_type: MatterType
    status: MatterStatus
    created_by: str
    created_at: float
    updated_at: float
    description: Optional[str] = None
    jurisdiction: Optional[str] = None
    opposing_party: Optional[str] = None
    lead_attorney: Optional[str] = None
    associated_attorneys: List[str] = None
    metadata: Dict = None
    encryption_key_id: Optional[str] = None
    data_retention_days: int = 2555
    litigation_hold: bool = False

    def __post_init__(self):
        if self.associated_attorneys is None:
            self.associated_attorneys = []
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "client_name": self.client_name,
            "case_number": self.case_number,
            "matter_name": self.matter_name,
            "matter_type": self.matter_type.value,
            "status": self.status.value,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "description": self.description,
            "jurisdiction": self.jurisdiction,
            "opposing_party": self.opposing_party,
            "lead_attorney": self.lead_attorney,
            "associated_attorneys": self.associated_attorneys,
            "metadata": self.metadata,
            "encryption_key_id": self.encryption_key_id,
            "data_retention_days": self.data_retention_days,
            "litigation_hold": self.litigation_hold
        }

@dataclass
class MatterDocument:
    id: str
    matter_id: str
    org_id: str
    filename: str
    document_type: str
    uploaded_by: str
    uploaded_at: float
    file_size: int
    mime_type: str
    storage_path: str
    extracted_text: Optional[str] = None
    privilege_status: Optional[str] = None
    confidentiality: str = "internal"
    tags: List[str] = None
    version: int = 1
    checksum: Optional[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "matter_id": self.matter_id,
            "org_id": self.org_id,
            "filename": self.filename,
            "document_type": self.document_type,
            "uploaded_by": self.uploaded_by,
            "uploaded_at": self.uploaded_at,
            "file_size": self.file_size,
            "mime_type": self.mime_type,
            "storage_path": self.storage_path,
            "extracted_text": self.extracted_text,
            "privilege_status": self.privilege_status,
            "confidentiality": self.confidentiality,
            "tags": self.tags,
            "version": self.version,
            "checksum": self.checksum
        }

def create_matter(org_id: str, client_name: str, created_by: str, matter_name: str,
                  matter_type: MatterType = MatterType.OTHER, case_number: Optional[str] = None,
                  description: Optional[str] = None, jurisdiction: Optional[str] = None,
                  lead_attorney: Optional[str] = None) -> Matter:
    now = time.time()
    return Matter(
        id=str(uuid.uuid4()),
        org_id=org_id,
        client_name=client_name,
        case_number=case_number,
        matter_name=matter_name,
        matter_type=matter_type,
        status=MatterStatus.ACTIVE,
        created_by=created_by,
        created_at=now,
        updated_at=now,
        description=description,
        jurisdiction=jurisdiction,
        lead_attorney=lead_attorney or created_by,
        associated_attorneys=[created_by]
    )
