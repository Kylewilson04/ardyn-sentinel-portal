"""
Vertical Registry — Loads vertical configurations and provides them to the pipeline.

Verticals are defined as YAML config files in webapp/verticals/.
The registry makes the platform domain-agnostic: the core ADS pipeline
doesn't know or care about specific verticals.
"""
import yaml
import logging
from pathlib import Path
from typing import Dict, Optional, List

logger = logging.getLogger(__name__)

VERTICALS_DIR = Path(__file__).parent / "verticals"


class VerticalConfig:
    """Parsed vertical configuration."""

    def __init__(self, data: dict):
        self.id: str = data["id"]
        self.name: str = data["name"]
        self.description: str = data.get("description", "")
        self.icon: str = data.get("icon", "📦")
        self.compliance_frameworks: List[str] = data.get("compliance_frameworks", [])
        self.system_prompt_template: str = data.get("system_prompt_template", "")
        self.mandatory_disclosure: str = data.get("mandatory_disclosure", "")
        self.recommended_model: str = data.get("recommended_model", "llama4:scout")
        self.mock_endpoints: List[dict] = data.get("mock_endpoints", [])
        self.demo_scenario: dict = data.get("demo_scenario", {})
        self.rag_sources: dict = data.get("rag_sources", {})
        self.detectors: List[str] = data.get("detectors", [])
        self.personas: List[dict] = data.get("personas", [])
        self._raw = data

    def to_dict(self) -> dict:
        return self._raw


class VerticalRegistry:
    """Loads and caches vertical configurations from YAML files."""

    def __init__(self, verticals_dir: Path = VERTICALS_DIR):
        self._verticals: Dict[str, VerticalConfig] = {}
        self._dir = verticals_dir
        self._load()

    def _load(self):
        if not self._dir.exists():
            logger.warning(f"Verticals directory not found: {self._dir}")
            return
        for path in sorted(self._dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(path.read_text())
                if data and "id" in data:
                    cfg = VerticalConfig(data)
                    self._verticals[cfg.id] = cfg
                    logger.info(f"Loaded vertical: {cfg.id} ({cfg.name})")
            except Exception as e:
                logger.error(f"Failed to load vertical config {path}: {e}")

    def get(self, vertical_id: str) -> Optional[VerticalConfig]:
        return self._verticals.get(vertical_id)

    def list_verticals(self) -> List[VerticalConfig]:
        return list(self._verticals.values())

    def get_system_prompt_addon(self, vertical_id: str) -> str:
        """Get the system prompt addon for a vertical (replaces old VERTICAL_ADDONS dict)."""
        cfg = self.get(vertical_id)
        return cfg.system_prompt_template if cfg else ""

    def get_recommended_model(self, vertical_id: str) -> str:
        cfg = self.get(vertical_id)
        return cfg.recommended_model if cfg else "llama4:scout"

    def get_mandatory_disclosure(self, vertical_id: str) -> str:
        cfg = self.get(vertical_id)
        return cfg.mandatory_disclosure if cfg else ""

    def ids(self) -> List[str]:
        return list(self._verticals.keys())


# Singleton
vertical_registry = VerticalRegistry()
