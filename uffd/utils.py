import secrets
import math

def token_with_alphabet(alphabet, nbytes=None):
	'''Return random text token that consists of characters from `alphabet`'''
	if nbytes is None:
		nbytes = max(secrets.DEFAULT_ENTROPY, 32)
	nbytes_per_char = math.log(len(alphabet), 256)
	nchars = math.ceil(nbytes / nbytes_per_char)
	return ''.join([secrets.choice(alphabet) for _ in range(nchars)])

def token_typeable(nbytes=None):
	'''Return random text token that is easy to type (on mobile)'''
	alphabet = '123456789abcdefghkmnopqrstuvwx' # No '0ijlyz'
	return token_with_alphabet(alphabet, nbytes=nbytes)

def token_urlfriendly(nbytes=None):
	'''Return random text token that is urlsafe and works around common parsing bugs'''
	alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
	return token_with_alphabet(alphabet, nbytes=nbytes)
