from uffd.ldap import LDAPModel, LDAPAttribute
from uffd.lazyconfig import lazyconfig_str, lazyconfig_list

class Mail(LDAPModel):
	ldap_base = lazyconfig_str('LDAP_BASE_MAIL')
	ldap_dn_attribute = 'uid'
	ldap_dn_base = lazyconfig_str('LDAP_BASE_MAIL')
	ldap_filter = '(objectClass=postfixVirtual)'
	ldap_object_classes = lazyconfig_list('MAIL_LDAP_OBJECTCLASSES')

	uid = LDAPAttribute('uid')
	receivers = LDAPAttribute('mailacceptinggeneralid', multi=True)
	destinations = LDAPAttribute('maildrop', multi=True)
