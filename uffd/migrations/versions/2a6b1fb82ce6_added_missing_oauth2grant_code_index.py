"""added missing oauth2grant.code index

Revision ID: 2a6b1fb82ce6
Revises: cbca20cf64d9
Create Date: 2021-04-13 23:03:46.280189

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '2a6b1fb82ce6'
down_revision = 'cbca20cf64d9'
branch_labels = None
depends_on = None

def upgrade():
	with op.batch_alter_table('oauth2grant', schema=None) as batch_op:
		batch_op.create_index(batch_op.f('ix_oauth2grant_code'), ['code'], unique=False)

def downgrade():
	with op.batch_alter_table('oauth2grant', schema=None) as batch_op:
		batch_op.drop_index(batch_op.f('ix_oauth2grant_code'))
