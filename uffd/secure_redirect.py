from flask import redirect

def secure_local_redirect(target):
	# Reject URLs that include a scheme or host part
	if not target.startswith('/') or target.startswith('//'):
		target = '/'
	return redirect(target)
