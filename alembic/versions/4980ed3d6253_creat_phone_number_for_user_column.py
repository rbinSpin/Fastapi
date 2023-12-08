"""Creat phone number for user column

Revision ID: 4980ed3d6253
Revises: 
Create Date: 2023-11-28 22:59:57.360145

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4980ed3d6253'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('phone_number', sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'phone_number')
