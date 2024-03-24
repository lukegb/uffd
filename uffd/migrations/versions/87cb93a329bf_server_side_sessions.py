"""Server-side sessions

Revision ID: 87cb93a329bf
Revises: 01fdd7820f29
Create Date: 2024-03-23 23:57:44.019456

"""
from alembic import op
import sqlalchemy as sa

revision = '87cb93a329bf'
down_revision = '01fdd7820f29'
branch_labels = None
depends_on = None

def upgrade():
	op.create_table('session',
		sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
		sa.Column('secret', sa.Text(), nullable=True),
		sa.Column('user_id', sa.Integer(), nullable=False),
		sa.Column('created', sa.DateTime(), nullable=False),
		sa.Column('last_used', sa.DateTime(), nullable=False),
		sa.Column('user_agent', sa.Text(), nullable=False),
		sa.Column('ip_address', sa.Text(), nullable=True),
		sa.Column('mfa_done', sa.Boolean(create_constraint=True), nullable=False),
		sa.ForeignKeyConstraint(['user_id'], ['user.id'], name=op.f('fk_session_user_id_user'), onupdate='CASCADE', ondelete='CASCADE'),
		sa.PrimaryKeyConstraint('id', name=op.f('pk_session'))
	)

def downgrade():
	op.drop_table('session')
