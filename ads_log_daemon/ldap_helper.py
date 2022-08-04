import ldap

from .config import (
    LOG_DAEMON_HOST_PREFIXES,
    LOG_DAEMON_LDAP_SEARCH_BASE,
    LOG_DAEMON_LDAP_SERVER,
)


class LDAPHelper:
    """
    LDAP helper class to find PLCs.

    Parameters
    ----------
    server : str, optional
        LDAP server, defaults to LOG_DAEMON_LDAP_SERVER.

    base : str, optional
        LDAP base to search, defaults to LOG_DAEMON_LDAP_SEARCH_BASE.

    host_prefixes : list, optional
        List of host prefixes, including glob syntax.
        Defaults to comma-delimited LOG_DAEMON_HOST_PREFIXES.

    Attributes
    ----------
    hosts : dict
        Common host name to dictionary of information, with keys
        ``{"location", "desc", "mac", "host_name", "ip_address"}``
    """

    def __init__(
        self,
        server=LOG_DAEMON_LDAP_SERVER,
        base=LOG_DAEMON_LDAP_SEARCH_BASE,
        host_prefixes=LOG_DAEMON_HOST_PREFIXES,
    ):
        self.client = ldap.initialize(server)
        self.server = server
        self.hosts = {}
        self.base = base
        self.host_prefixes = host_prefixes
        self._last_hosts = set()

    def duplicate(self):  # -> __copy__
        """Create a new LDAP helper with the same settings."""
        helper = type(self)(
            server=self.server,
            base=self.base,
            host_prefixes=list(self.host_prefixes),
        )
        helper.hosts = dict(self.hosts)
        helper._last_hosts = set(self._last_hosts)
        return helper

    def update_hosts(self):
        """
        Update hosts dictionary with the LDAP client.

        After an update, refer to the ``.hosts`` dictionary.

        Returns
        -------
        removed : set
            Removed host names.

        added : set
            Added host names.
        """
        host_filter = "".join(
            f"(cn={host_prefix})" for host_prefix in self.host_prefixes
        )
        search_filter = f"(|{host_filter})"

        def get_value(entry, key):
            value, *_ = entry.get(key, [b""])
            if isinstance(value, bytes):
                return value.decode("ascii")
            return value

        found_hosts = set()
        added_hosts = set()
        for _, entry in self.client.search_s(
            self.base, ldap.SCOPE_SUBTREE, search_filter
        ):
            ip_address = get_value(entry, "ipHostNumber")
            common_name = get_value(entry, "cn")

            is_new = (
                common_name not in self.hosts
                or ip_address != self.hosts[common_name]["ip_address"]
            )
            if is_new:
                added_hosts.add(common_name)
            self.hosts[common_name] = dict(
                location=get_value(entry, "location"),
                desc=get_value(entry, "description"),
                mac=get_value(entry, "macAddress"),
                host_name=common_name,
                ip_address=ip_address,
            )
            found_hosts.add(common_name)

        removed_hosts = self._last_hosts - found_hosts
        for host in removed_hosts:
            self.hosts.pop(host, None)

        self._last_hosts = added_hosts
        return removed_hosts, added_hosts
