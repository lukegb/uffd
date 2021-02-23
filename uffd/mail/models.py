from uffd.ldap import ldap
from uffd.lazyconfig import lazyconfig_str, lazyconfig_list

class Mail(ldap.Model):
	ldap_search_base = lazyconfig_str('LDAP_BASE_MAIL')
	ldap_filter_params = lazyconfig_list('LDAP_FILTER_MAIL')
	ldap_object_classes = lazyconfig_list('MAIL_LDAP_OBJECTCLASSES')
	ldap_dn_attribute = 'uid'
	ldap_dn_base = lazyconfig_str('LDAP_BASE_MAIL')

	uid = ldap.Attribute('uid')
	receivers = ldap.Attribute('mailacceptinggeneralid', multi=True)
	destinations = ldap.Attribute('maildrop', multi=True)
