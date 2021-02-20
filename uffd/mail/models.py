from uffd.ldap import ldap
from uffd.lazyconfig import lazyconfig_str, lazyconfig_list

class Mail(ldap.Model):
	ldap_base = lazyconfig_str('LDAP_BASE_MAIL')
	ldap_dn_attribute = 'uid'
	ldap_dn_base = lazyconfig_str('LDAP_BASE_MAIL')
	ldap_filter = '(objectClass=postfixVirtual)'
	ldap_object_classes = lazyconfig_list('MAIL_LDAP_OBJECTCLASSES')

	uid = ldap.Attribute('uid')
	receivers = ldap.Attribute('mailacceptinggeneralid', multi=True)
	destinations = ldap.Attribute('maildrop', multi=True)
