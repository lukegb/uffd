"""added RoleGroup.requires_mfa and cleanup

Revision ID: bad6fc529510
Revises: aff5f350dcdf
Create Date: 2021-06-22 15:58:10.515330

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'bad6fc529510'
down_revision = 'aff5f350dcdf'
branch_labels = None
depends_on = None

def upgrade():
	meta = sa.MetaData(bind=op.get_bind())
	table = sa.Table('role-group', meta,
		sa.Column('role_id', sa.Integer(), nullable=False),
		sa.Column('dn', sa.String(128), nullable=False),
		sa.ForeignKeyConstraint(['role_id'], ['role.id'], name=op.f('fk_role-group_role_id_role')),
		sa.PrimaryKeyConstraint('role_id', 'dn', name=op.f('pk_role-group'))
	)
	with op.batch_alter_table(table.name, copy_from=table, recreate='always') as batch_op:
		batch_op.alter_column('dn', new_column_name='group_dn', nullable=False)
		batch_op.add_column(sa.Column('requires_mfa', sa.Boolean(name=op.f('ck_role-group_requires_mfa')), nullable=False, default=False))

def downgrade():
	meta = sa.MetaData(bind=op.get_bind())
	table = sa.Table('role-group', meta,
		sa.Column('role_id', sa.Integer(), nullable=False),
		sa.Column('group_dn', sa.String(128), nullable=False),
		sa.ForeignKeyConstraint(['role_id'], ['role.id'], name=op.f('fk_role-group_role_id_role'))
	)
	with op.batch_alter_table(table.name, copy_from=table, recreate='always') as batch_op:
		batch_op.add_column(sa.Column('id', sa.INTEGER(), nullable=False, autoincrement=True, primary_key=True))
		batch_op.alter_column('group_dn', new_column_name='dn', nullable=True)
		batch_op.add_column(sa.Column('requires_mfa', sa.Boolean(name=op.f('ck_role-group_requires_mfa')), nullable=False, default=False))
