# Cronjobs for uffd

@daily	uffd	flock -n /var/run/uffd/cron.roles-update-all.lock /usr/bin/uffd-admin roles-update-all --check-only 2> /dev/null
@daily	uffd	flock -n /var/run/uffd/cron.cleanup.lock /usr/bin/uffd-admin cleanup > /dev/null
