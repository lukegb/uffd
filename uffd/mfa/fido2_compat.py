# pylint: skip-file

import fido2 as __fido2

if __fido2.__version__.startswith('0.5.'):
	from fido2.client import ClientData
	from fido2.server import Fido2Server, RelyingParty as __PublicKeyCredentialRpEntity
	from fido2.ctap2 import AttestationObject, AuthenticatorData, AttestedCredentialData
	from fido2 import cbor
	cbor.encode = cbor.dumps
	cbor.decode = lambda arg: cbor.loads(arg)[0]
	class PublicKeyCredentialRpEntity(__PublicKeyCredentialRpEntity):
		def __init__(self, name, id):
			super().__init__(id, name)
elif __fido2.__version__.startswith('0.9.'):
	from fido2.client import ClientData
	from fido2.webauthn import PublicKeyCredentialRpEntity
	from fido2.server import Fido2Server
	from fido2.ctap2 import AttestationObject, AuthenticatorData, AttestedCredentialData
	from fido2 import cbor
elif __fido2.__version__.startswith('1.'):
	from fido2.webauthn import PublicKeyCredentialRpEntity, CollectedClientData as ClientData, AttestationObject, AuthenticatorData, AttestedCredentialData
	from fido2.server import Fido2Server
	from fido2 import cbor
else:
	raise ImportError(f'Unsupported fido2 version: {__fido2.__version__}')
