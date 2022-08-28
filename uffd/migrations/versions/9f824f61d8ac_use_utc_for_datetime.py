"""Use UTC for DateTime

Revision ID: 9f824f61d8ac
Revises: a60ce68b9214
Create Date: 2022-08-16 00:51:04.635182

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '9f824f61d8ac'
down_revision = 'a60ce68b9214'
branch_labels = None
depends_on = None

import datetime

def localtime_to_utc(dt):
	return dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)

def utc_to_localtime(dt):
	return dt.replace(tzinfo=datetime.timezone.utc).astimezone().replace(tzinfo=None)

def iter_rows_paged(table, pk='id', limit=1000):
	conn = op.get_bind()
	pk_column = getattr(table.c, pk)
	last_pk = None
	while True:
		expr = table.select().order_by(pk_column).limit(limit)
		if last_pk is not None:
			expr = expr.where(pk_column > last_pk)
		result = conn.execute(expr)
		pk_index = list(result.keys()).index(pk)
		rows = result.fetchall()
		if not rows:
			break
		yield from rows
		last_pk = rows[-1][pk_index]

invite = sa.table('invite',
	sa.column('id', sa.Integer),
	sa.column('created', sa.DateTime),
	sa.column('valid_until', sa.DateTime),
)

password_token = sa.table('passwordToken',
	sa.column('id', sa.Integer),
	sa.column('created', sa.DateTime),
)

mail_token = sa.table('mailToken',
	sa.column('id', sa.Integer),
	sa.column('created', sa.DateTime),
)

device_login_initiation = sa.table('device_login_initiation',
	sa.column('id', sa.Integer),
	sa.column('created', sa.DateTime),
)

signup = sa.table('signup',
	sa.column('id', sa.Integer),
	sa.column('created', sa.DateTime),
)

def upgrade():
	for obj_id, created, valid_until in iter_rows_paged(invite):
		op.execute(invite.update().where(invite.c.id==obj_id).values(
			created=localtime_to_utc(created),
			valid_until=localtime_to_utc(valid_until),
		))
	for obj_id, created in iter_rows_paged(password_token):
		op.execute(password_token.update().where(password_token.c.id==obj_id).values(
			created=localtime_to_utc(created),
		))
	for obj_id, created in iter_rows_paged(mail_token):
		op.execute(mail_token.update().where(mail_token.c.id==obj_id).values(
			created=localtime_to_utc(created),
		))
	for obj_id, created in iter_rows_paged(device_login_initiation):
		op.execute(device_login_initiation.update().where(device_login_initiation.c.id==obj_id).values(
			created=localtime_to_utc(created),
		))
	for obj_id, created in iter_rows_paged(signup):
		op.execute(signup.update().where(signup.c.id==obj_id).values(
			created=localtime_to_utc(created),
		))

def downgrade():
	for obj_id, created, valid_until in iter_rows_paged(invite):
		op.execute(invite.update().where(invite.c.id==obj_id).values(
			created=utc_to_localtime(created),
			valid_until=utc_to_localtime(valid_until),
		))
	for obj_id, created in iter_rows_paged(password_token):
		op.execute(password_token.update().where(password_token.c.id==obj_id).values(
			created=utc_to_localtime(created),
		))
	for obj_id, created in iter_rows_paged(mail_token):
		op.execute(mail_token.update().where(mail_token.c.id==obj_id).values(
			created=utc_to_localtime(created),
		))
	for obj_id, created in iter_rows_paged(device_login_initiation):
		op.execute(device_login_initiation.update().where(device_login_initiation.c.id==obj_id).values(
			created=utc_to_localtime(created),
		))
	for obj_id, created in iter_rows_paged(signup):
		op.execute(signup.update().where(signup.c.id==obj_id).values(
			created=utc_to_localtime(created),
		))
