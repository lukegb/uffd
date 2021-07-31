"""device login

Revision ID: a8c6b6e91c28
Revises: bad6fc529510
Create Date: 2021-07-19 14:37:02.559667

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a8c6b6e91c28'
down_revision = 'bad6fc529510'
branch_labels = None
depends_on = None

def upgrade():
	op.create_table('device_login_initiation',
		sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
		sa.Column('type', sa.Enum('OAUTH2', name='devicelogintype'), nullable=False),
		sa.Column('code0', sa.String(length=32), nullable=False),
		sa.Column('code1', sa.String(length=32), nullable=False),
		sa.Column('secret', sa.String(length=128), nullable=False),
		sa.Column('created', sa.DateTime(), nullable=False),
		sa.Column('oauth2_client_id', sa.String(length=40), nullable=True),
		sa.PrimaryKeyConstraint('id', name=op.f('pk_device_login_initiation')),
		sa.UniqueConstraint('code0', name=op.f('uq_device_login_initiation_code0')),
		sa.UniqueConstraint('code1', name=op.f('uq_device_login_initiation_code1'))
	)
	op.create_table('device_login_confirmation',
		sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
		sa.Column('initiation_id', sa.Integer(), nullable=False),
		sa.Column('user_dn', sa.String(length=128), nullable=False),
		sa.Column('code0', sa.String(length=32), nullable=False),
		sa.Column('code1', sa.String(length=32), nullable=False),
		sa.ForeignKeyConstraint(['initiation_id'], ['device_login_initiation.id'], name=op.f('fk_device_login_confirmation_initiation_id_device_login_initiation')),
		sa.PrimaryKeyConstraint('id', name=op.f('pk_device_login_confirmation')),
		sa.UniqueConstraint('initiation_id', 'code0', name=op.f('uq_device_login_confirmation_initiation_id_code0')),
		sa.UniqueConstraint('initiation_id', 'code1', name=op.f('uq_device_login_confirmation_initiation_id_code1')),
		sa.UniqueConstraint('user_dn', name=op.f('uq_device_login_confirmation_user_dn'))
	)

def downgrade():
	op.drop_table('device_login_confirmation')
	op.drop_table('device_login_initiation')
