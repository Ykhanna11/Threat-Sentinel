"""add organization targets and TXT verification challenge persistence

Revision ID: 1c2f78b9d640
Revises: c7b1e4a2d903
Create Date: 2026-11-20 08:40:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "1c2f78b9d640"
down_revision: Union[str, None] = "c7b1e4a2d903"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_targets",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("hostname", sa.String(length=253), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(hostname) BETWEEN 1 AND 253",
            name="ck_security_targets_hostname_length",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "hostname",
            name="uq_security_targets_organization_hostname",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "id",
            name="uq_security_targets_organization_id",
        ),
    )
    op.create_index(
        "ix_security_targets_organization_created",
        "security_targets",
        ["organization_id", "created_at"],
        unique=False,
    )
    op.create_table(
        "target_verification_challenges",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("issued_by_user_id", sa.Uuid(), nullable=False),
        sa.Column("challenge_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "length(challenge_hash) = 64",
            name="ck_target_challenges_hash_length",
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="ck_target_challenges_expiry_after_creation",
        ),
        sa.ForeignKeyConstraint(
            ["issued_by_user_id"],
            ["users.id"],
            name="fk_target_challenges_issuer",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "target_id"],
            ["security_targets.organization_id", "security_targets.id"],
            name="fk_target_challenges_target_same_organization",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("challenge_hash", name="uq_target_challenges_hash"),
        sa.UniqueConstraint(
            "organization_id",
            "target_id",
            name="uq_target_challenges_one_per_target",
        ),
    )
    op.create_index(
        "ix_target_challenges_organization_target_expiry",
        "target_verification_challenges",
        ["organization_id", "target_id", "expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_target_challenges_organization_target_expiry",
        table_name="target_verification_challenges",
    )
    op.drop_table("target_verification_challenges")
    op.drop_index(
        "ix_security_targets_organization_created",
        table_name="security_targets",
    )
    op.drop_table("security_targets")
