"""Initial and v2.0 complete schema migration for CHRYA BOX.

Revision ID: 0001_chrya_v2_schema
Revises:
Create Date: 2026-11-10
"""
from __future__ import annotations
from alembic import op
from models import Base, ensure_schema_migrations

revision = '0001_chrya_v2_schema'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind)
    ensure_schema_migrations(bind.engine)


def downgrade() -> None:
    # Destructive downgrade intentionally omitted to protect encrypted user vault data
    pass
