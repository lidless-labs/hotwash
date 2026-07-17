"""
Integration ORM model for external tool connections.
"""

from sqlalchemy import Boolean, Column, DateTime, Integer, String, func
from api.orm_models import Base


class Integration(Base):
    __tablename__ = "integrations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tool_name = Column(String, unique=True, nullable=False)
    display_name = Column(String, nullable=False)
    base_url = Column(String, default="")
    api_key = Column(String, default="")
    username = Column(String, default="")
    password = Column(String, default="")
    enabled = Column(Boolean, default=False)
    verify_ssl = Column(Boolean, default=True)
    mock_mode = Column(Boolean, default=True)
    last_checked = Column(DateTime, nullable=True)
    last_status = Column(String, default="unchecked")
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


# Default integrations to seed
DEFAULT_INTEGRATIONS = [
    {"tool_name": "thehive", "display_name": "TheHive"},
    {"tool_name": "http_webhook", "display_name": "HTTP Webhook"},
    {"tool_name": "cortex", "display_name": "Cortex"},
    {"tool_name": "wazuh", "display_name": "Wazuh"},
    {"tool_name": "misp", "display_name": "MISP"},
]
