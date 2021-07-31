# Cronjobs for uffd

@daily	uffd	[ -f /usr/bin/uffd-admin ] && flock -n /var/run/uffd/cron.roles-update-all.lock /usr/bin/uffd-admin roles-update-all --check-only 2> /dev/null
