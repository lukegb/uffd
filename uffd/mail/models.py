from uffd.ldap import ldap
from uffd.lazyconfig import lazyconfig_str, lazyconfig_list

class Mail(ldap.Model):
	ldap_search_base = lazyconfig_str('LDAP_MAIL_SEARCH_BASE')
	ldap_filter_params = lazyconfig_list('LDAP_MAIL_SEARCH_FILTER')
	ldap_object_classes = lazyconfig_list('LDAP_MAIL_OBJECTCLASSES')
	ldap_dn_attribute = lazyconfig_str('LDAP_MAIL_DN_ATTRIBUTE')
	ldap_dn_base = lazyconfig_str('LDAP_MAIL_SEARCH_BASE')

	uid = ldap.Attribute(lazyconfig_str('LDAP_MAIL_UID_ATTRIBUTE'))
	receivers = ldap.Attribute(lazyconfig_str('LDAP_MAIL_RECEIVERS_ATTRIBUTE'), multi=True)
	destinations = ldap.Attribute(lazyconfig_str('LDAP_MAIL_DESTINATIONS_ATTRIBUTE'), multi=True)
