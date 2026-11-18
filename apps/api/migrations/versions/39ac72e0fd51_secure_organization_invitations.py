"""secure organization invitation lifecycle

Revision ID: 39ac72e0fd51
Revises: 8d2a4c6f1b30
Create Date: 2026-11-18 23:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "39ac72e0fd51"
down_revision: Union[str, None] = "8d2a4c6f1b30"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "organization_invitations",
        sa.Column(
            "role",
            sa.Enum(
                "owner",
                "admin",
                "member",
                "viewer",
                name="organization_role",
                native_enum=False,
                create_constraint=True,
            ),
            server_default=sa.text("'member'"),
            nullable=False,
        ),
    )
    op.add_column(
        "organization_invitations",
        sa.Column("token_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "organization_invitations",
        sa.Column("intended_identity_id", sa.Uuid(), nullable=True),
    )
    op.execute(
        sa.text(
            "UPDATE organization_invitations "
            "SET status = 'revoked', revoked_at = CURRENT_TIMESTAMP "
            "WHERE status = 'pending'"
        )
    )
    op.create_index(
        "uq_organization_invitations_token_hash",
        "organization_invitations",
        ["token_hash"],
        unique=True,
    )
    op.create_foreign_key(
        "fk_org_invitations_intended_identity",
        "organization_invitations",
        "external_identities",
        ["intended_identity_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        "ck_organization_invitations_pending_token_hash",
        "organization_invitations",
        "status != 'pending' OR token_hash IS NOT NULL",
    )
    op.create_check_constraint(
        "ck_organization_invitations_pending_identity",
        "organization_invitations",
        "status != 'pending' OR intended_identity_id IS NOT NULL",
    )
    op.create_check_constraint(
        "ck_organization_invitations_cannot_grant_owner",
        "organization_invitations",
        "role != 'owner'",
    )
    op.create_check_constraint(
        "ck_organization_invitations_token_hash_length",
        "organization_invitations",
        "token_hash IS NULL OR length(token_hash) = 64",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_organization_invitations_token_hash_length",
        "organization_invitations",
        type_="check",
    )
    op.drop_constraint(
        "ck_organization_invitations_cannot_grant_owner",
        "organization_invitations",
        type_="check",
    )
    op.drop_constraint(
        "ck_organization_invitations_pending_identity",
        "organization_invitations",
        type_="check",
    )
    op.drop_constraint(
        "ck_organization_invitations_pending_token_hash",
        "organization_invitations",
        type_="check",
    )
    op.drop_index(
        "uq_organization_invitations_token_hash",
        table_name="organization_invitations",
    )
    op.drop_constraint(
        "fk_org_invitations_intended_identity",
        "organization_invitations",
        type_="foreignkey",
    )
    op.drop_column("organization_invitations", "intended_identity_id")
    op.drop_column("organization_invitations", "token_hash")
    op.drop_column("organization_invitations", "role")
