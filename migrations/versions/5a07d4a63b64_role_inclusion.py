"""Role inclusion

Revision ID: 5a07d4a63b64
Revises: a29870f95175
Create Date: 2021-04-05 15:00:26.205433

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5a07d4a63b64'
down_revision = 'a29870f95175'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('role-inclusion',
    sa.Column('role_id', sa.Integer(), nullable=False),
    sa.Column('included_role_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['included_role_id'], ['role.id'], ),
    sa.ForeignKeyConstraint(['role_id'], ['role.id'], ),
    sa.PrimaryKeyConstraint('role_id', 'included_role_id')
    )


def downgrade():
    op.drop_table('role-inclusion')
