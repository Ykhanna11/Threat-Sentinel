"""add account display name

Revision ID: 8d2a4c6f1b30
Revises: 0557465b3944
Create Date: 2026-11-18 22:58:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "8d2a4c6f1b30"
down_revision: Union[str, None] = "0557465b3944"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("display_name", sa.String(length=100), nullable=True))
    op.create_check_constraint(
        "ck_users_display_name_not_blank",
        "users",
        "display_name IS NULL OR length(trim(display_name)) > 0",
    )


def downgrade() -> None:
    op.drop_constraint("ck_users_display_name_not_blank", "users", type_="check")
    op.drop_column("users", "display_name")
