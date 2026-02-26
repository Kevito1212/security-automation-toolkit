from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import json


@dataclass
class SocEvent:
    timestamp: str
    source: str
    event_type: str
    severity: str
    user: Optional[str] = None
    src_ip: Optional[str] = None
    message: Optional[str] = None
    raw: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)