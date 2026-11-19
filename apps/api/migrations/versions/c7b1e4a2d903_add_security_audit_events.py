"""add durable security audit events

Revision ID: c7b1e4a2d903
Revises: 39ac72e0fd51
Create Date: 2026-11-19 18:10:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c7b1e4a2d903"
down_revision: Union[str, None] = "39ac72e0fd51"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column(
            "outcome",
            sa.String(length=16),
            server_default=sa.text("'success'"),
            nullable=False,
        ),
        sa.Column("target_type", sa.String(length=100), nullable=True),
        sa.Column("target_id", sa.Uuid(), nullable=True),
        sa.Column("request_id", sa.String(length=36), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="SET NULL",
        ),
        sa.CheckConstraint(
            "length(trim(action)) > 0",
            name="ck_security_audit_action_not_blank",
        ),
        sa.CheckConstraint(
            "outcome IN ('success', 'failure')",
            name="ck_security_audit_outcome",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_security_audit_events_actor_created",
        "security_audit_events",
        ["actor_user_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_security_audit_events_org_created",
        "security_audit_events",
        ["organization_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_security_audit_events_org_created",
        table_name="security_audit_events",
    )
    op.drop_index(
        "ix_security_audit_events_actor_created",
        table_name="security_audit_events",
    )
    op.drop_table("security_audit_events")
