from uffd.ldap import LDAPModel, LDAPAttribute

class Mail(LDAPModel):
	ldap_base = 'ou=postfix,dc=example,dc=com'
	ldap_dn_attribute = 'uid'
	ldap_dn_base = 'ou=postfix,dc=example,dc=com'
	ldap_filter = '(objectClass=postfixVirtual)'
	ldap_object_classes = ['top', 'postfixVirtual']

	uid = LDAPAttribute('uid')
	receivers = LDAPAttribute('mailacceptinggeneralid', multi=True)
	destinations = LDAPAttribute('maildrop', multi=True)
