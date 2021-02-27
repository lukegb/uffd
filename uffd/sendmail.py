import smtplib
from email.message import EmailMessage
import email.utils

from flask import render_template, current_app

def sendmail(addr, subject, template_name, **kwargs):
	msg = EmailMessage()
	msg.set_content(render_template(template_name, **kwargs))
	msg['Subject'] = subject
	msg['From'] = current_app.config['MAIL_FROM_ADDRESS']
	msg['To'] = addr
	msg['Date'] = email.utils.formatdate(localtime=1)
	msg['Message-ID'] = email.utils.make_msgid()
	try:
		if current_app.debug:
			current_app.last_mail = None
			current_app.logger.debug('Trying to send email to %s:\n'%(addr)+str(msg))
		if current_app.debug and current_app.config.get('MAIL_SKIP_SEND', False):
			if current_app.config['MAIL_SKIP_SEND'] == 'fail':
				raise smtplib.SMTPException()
			current_app.last_mail = msg
			return True
		server = smtplib.SMTP(host=current_app.config['MAIL_SERVER'], port=current_app.config['MAIL_PORT'])
		if current_app.config['MAIL_USE_STARTTLS']:
			server.starttls()
		server.login(current_app.config['MAIL_USERNAME'], current_app.config['MAIL_PASSWORD'])
		server.send_message(msg)
		server.quit()
		if current_app.debug:
			current_app.last_mail = msg
		return True
	except smtplib.SMTPException:
		return False
