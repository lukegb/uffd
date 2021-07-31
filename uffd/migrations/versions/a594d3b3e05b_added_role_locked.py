"""added role.locked

Revision ID: a594d3b3e05b
Revises: 5cab70e95bf8
Create Date: 2021-06-14 00:32:47.792794

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a594d3b3e05b'
down_revision = '5cab70e95bf8'
branch_labels = None
depends_on = None

def upgrade():
	with op.batch_alter_table('role', schema=None) as batch_op:
		batch_op.add_column(sa.Column('locked', sa.Boolean(name=op.f('ck_role_locked')), nullable=False, default=False))

def downgrade():
	with op.batch_alter_table('role', schema=None) as batch_op:
		batch_op.drop_column('locked')
