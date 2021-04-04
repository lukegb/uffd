"""Initial migration.

Revision ID: a29870f95175
Revises: 
Create Date: 2021-04-04 22:46:24.930356

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a29870f95175'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('invite',
    sa.Column('token', sa.String(length=128), nullable=False),
    sa.Column('created', sa.DateTime(), nullable=False),
    sa.Column('valid_until', sa.DateTime(), nullable=False),
    sa.Column('single_use', sa.Boolean(), nullable=False),
    sa.Column('allow_signup', sa.Boolean(), nullable=False),
    sa.Column('used', sa.Boolean(), nullable=False),
    sa.Column('disabled', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('token')
    )
    op.create_table('mailToken',
    sa.Column('token', sa.String(length=128), nullable=False),
    sa.Column('created', sa.DateTime(), nullable=True),
    sa.Column('loginname', sa.String(length=32), nullable=True),
    sa.Column('newmail', sa.String(length=255), nullable=True),
    sa.PrimaryKeyConstraint('token')
    )
    op.create_table('mfa_method',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('type', sa.Enum('RECOVERY_CODE', 'TOTP', 'WEBAUTHN', name='mfatype'), nullable=True),
    sa.Column('created', sa.DateTime(), nullable=True),
    sa.Column('name', sa.String(length=128), nullable=True),
    sa.Column('dn', sa.String(length=128), nullable=True),
    sa.Column('recovery_salt', sa.String(length=64), nullable=True),
    sa.Column('recovery_hash', sa.String(length=256), nullable=True),
    sa.Column('totp_key', sa.String(length=64), nullable=True),
    sa.Column('webauthn_cred', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('oauth2grant',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_dn', sa.String(length=128), nullable=True),
    sa.Column('client_id', sa.String(length=40), nullable=True),
    sa.Column('code', sa.String(length=255), nullable=False),
    sa.Column('redirect_uri', sa.String(length=255), nullable=True),
    sa.Column('expires', sa.DateTime(), nullable=True),
    sa.Column('_scopes', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('oauth2grant', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_oauth2grant_code'), ['code'], unique=False)

    op.create_table('oauth2token',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_dn', sa.String(length=128), nullable=True),
    sa.Column('client_id', sa.String(length=40), nullable=True),
    sa.Column('token_type', sa.String(length=40), nullable=True),
    sa.Column('access_token', sa.String(length=255), nullable=True),
    sa.Column('refresh_token', sa.String(length=255), nullable=True),
    sa.Column('expires', sa.DateTime(), nullable=True),
    sa.Column('_scopes', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('access_token'),
    sa.UniqueConstraint('refresh_token')
    )
    op.create_table('passwordToken',
    sa.Column('token', sa.String(length=128), nullable=False),
    sa.Column('created', sa.DateTime(), nullable=True),
    sa.Column('loginname', sa.String(length=32), nullable=True),
    sa.PrimaryKeyConstraint('token')
    )
    op.create_table('ratelimit_event',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.Column('name', sa.String(length=128), nullable=True),
    sa.Column('key', sa.String(length=128), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('role',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('name', sa.String(length=32), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('signup',
    sa.Column('token', sa.String(length=128), nullable=False),
    sa.Column('created', sa.DateTime(), nullable=False),
    sa.Column('loginname', sa.Text(), nullable=True),
    sa.Column('displayname', sa.Text(), nullable=True),
    sa.Column('mail', sa.Text(), nullable=True),
    sa.Column('pwhash', sa.Text(), nullable=True),
    sa.Column('user_dn', sa.String(length=128), nullable=True),
    sa.Column('type', sa.String(length=50), nullable=True),
    sa.PrimaryKeyConstraint('token')
    )
    op.create_table('invite_grant',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('invite_token', sa.String(length=128), nullable=False),
    sa.Column('user_dn', sa.String(length=128), nullable=False),
    sa.ForeignKeyConstraint(['invite_token'], ['invite.token'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('invite_roles',
    sa.Column('invite_token', sa.String(length=128), nullable=False),
    sa.Column('role_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['invite_token'], ['invite.token'], ),
    sa.ForeignKeyConstraint(['role_id'], ['role.id'], ),
    sa.PrimaryKeyConstraint('invite_token', 'role_id')
    )
    op.create_table('invite_signup',
    sa.Column('token', sa.String(length=128), nullable=False),
    sa.Column('invite_token', sa.String(length=128), nullable=False),
    sa.ForeignKeyConstraint(['invite_token'], ['invite.token'], ),
    sa.ForeignKeyConstraint(['token'], ['signup.token'], ),
    sa.PrimaryKeyConstraint('token')
    )
    op.create_table('role-group',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('dn', sa.String(length=128), nullable=True),
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['role_id'], ['role.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('dn', 'role_id')
    )
    op.create_table('role-user',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('dn', sa.String(length=128), nullable=True),
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['role_id'], ['role.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('dn', 'role_id')
    )


def downgrade():
    op.drop_table('role-user')
    op.drop_table('role-group')
    op.drop_table('invite_signup')
    op.drop_table('invite_roles')
    op.drop_table('invite_grant')
    op.drop_table('signup')
    op.drop_table('role')
    op.drop_table('ratelimit_event')
    op.drop_table('passwordToken')
    op.drop_table('oauth2token')
    with op.batch_alter_table('oauth2grant', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_oauth2grant_code'))

    op.drop_table('oauth2grant')
    op.drop_table('mfa_method')
    op.drop_table('mailToken')
    op.drop_table('invite')
