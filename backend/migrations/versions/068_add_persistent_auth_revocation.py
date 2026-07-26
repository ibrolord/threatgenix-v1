"""Add persistent account token revocation.

Revision ID: 068
Revises: 067
Create Date: 2026-07-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "068"
down_revision = "067"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    user_columns = {
        column["name"] for column in inspector.get_columns("users")
    }
    if "auth_version" not in user_columns:
        op.add_column(
            "users",
            sa.Column(
                "auth_version",
                sa.Integer(),
                server_default="0",
                nullable=False,
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    user_columns = {
        column["name"] for column in inspector.get_columns("users")
    }
    if "auth_version" in user_columns:
        op.drop_column("users", "auth_version")
