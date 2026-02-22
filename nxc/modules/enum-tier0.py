### Recursive nested counting

from nxc.helpers.misc import CATEGORY
from nxc.logger import nxc_logger
from impacket.ldap.ldap import LDAPSearchError
from impacket.ldap.ldapasn1 import SearchResultEntry


class NXCModule:
    """
    Enumerate Tier 0 groups and report member counts. This includes nested group memberships.
    """

    name = "enum-tier0"
    description = "List Tier 0 groups and how many members each has"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        # No options for now
        pass

    def on_login(self, context, connection):
        tier0_groups = [
            "Administrators",
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Enterprise Read-only Domain Controllers",
            "Backup Operators",
            "Account Operators",
            "Print Operators",
            "Remote Desktop Users",
        ]
        # Build an LDAP filter that searches groups matching cn or displayName
        or_parts = []
        for g in tier0_groups:
            or_parts.append(f"(cn={g})")
            or_parts.append(f"(displayName={g})")
        search_filter = f"(&(objectClass=group)(|{''.join(or_parts)}))"

        attrs = ["cn", "sAMAccountName", "member", "distinguishedName", "objectClass"]

        try:
            context.log.debug(f"Search Filter={search_filter}")
            resp = connection.ldap_connection.search(searchFilter=search_filter, attributes=attrs, sizeLimit=0)
        except LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                context.log.debug("sizeLimitExceeded exception caught, processing partial results")
                resp = e.getAnswers()
            else:
                nxc_logger.debug(e)
                context.log.fail("LDAP search failed")
                return False

        # cache: dn -> (is_group(bool), members(list of dn strings))
        cache = {}

        def fetch_dn(dn):
            if dn in cache:
                return cache[dn]
            try:
                r = connection.ldap_connection.search(searchFilter=f"(distinguishedName={dn})", attributes=["objectClass", "member"], sizeLimit=1)
            except LDAPSearchError as e:
                if e.getErrorString().find("sizeLimitExceeded") >= 0:
                    r = e.getAnswers()
                else:
                    nxc_logger.debug(e)
                    return (False, [])

            is_group = False
            members = []
            for item in r:
                if not isinstance(item, SearchResultEntry):
                    continue
                for attribute in item["attributes"]:
                    atype = str(attribute["type"]) 
                    if atype == "objectClass":
                        objcls = [str(v).lower() for v in attribute["vals"]]
                        if any("group" in v for v in objcls):
                            is_group = True
                    elif atype == "member":
                        members = [str(v) for v in attribute["vals"]]
            cache[dn] = (is_group, members)
            return cache[dn]

        def collect_members(dn, unique_set, visited):
            if dn in visited:
                return
            visited.add(dn)
            is_group, members = fetch_dn(dn)
            if not is_group:
                unique_set.add(dn)
                return
            for m in members:
                collect_members(m, unique_set, visited)

        found = False
        for item in resp:
            if not isinstance(item, SearchResultEntry):
                continue

            cn = None
            dn = None
            members = []
            objcls = []
            try:
                for attribute in item["attributes"]:
                    atype = str(attribute["type"]) 
                    if atype in ("cn", "displayName") and cn is None:
                        cn = str(attribute["vals"][0])
                    elif atype == "distinguishedName":
                        dn = str(attribute["vals"][0])
                    elif atype == "member":
                        members = [str(v) for v in attribute["vals"]]
                    elif atype == "objectClass":
                        objcls = [str(v).lower() for v in attribute["vals"]]

                if dn is None:
                    continue

                # seed cache for this group
                cache[dn] = (any("group" in v for v in objcls), members)

                unique = set()
                visited = set()
                collect_members(dn, unique, visited)

                count = len(unique)
                context.log.highlight(f"{cn}: {count}")
                found = True
            except Exception:
                context.log.debug("Failed to parse group entry", exc_info=True)

        if not found:
            context.log.fail("No Tier 0 groups found by name.")
        return True
