from nxc.helpers.misc import CATEGORY
from nxc.logger import nxc_logger
from impacket.ldap.ldap import LDAPSearchError
from impacket.ldap.ldapasn1 import SearchResultEntry


class NXCModule:
    """
    Search `description` fields for potential passwords using a keyword list.
    """

    name = "find-desc-pass"
    description = "Search user description fields for password-like keywords"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        KEYWORDS    Optional comma separated keywords to search for (default: password,pass,passwd,pwd,psw)

        Optional usage shown in help: -o KEYWORDS=password,pass,passwd

        Examples:
        nxc ldap $DC -u User -p Pass -M find-desc-pass
        nxc ldap $DC -u User -p Pass -M find-desc-pass -o KEYWORDS=password,pass,passwd
        """
        default = "password,pass,passwd,pwd,psw"
        self.keywords = []
        if "KEYWORDS" in module_options:
            self.keywords = [k.strip() for k in module_options["KEYWORDS"].split(",") if k.strip()]
        else:
            self.keywords = [k.strip() for k in default.split(",")]

    def on_login(self, context, connection):
        search_filter = '(objectClass=user)'
        attributes = ["distinguishedName", "sAMAccountName", "description", "name"]

        try:
            context.log.debug(f"Search Filter={search_filter}")
            resp = connection.ldap_connection.search(searchFilter=search_filter, attributes=attributes, sizeLimit=0)
        except LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                context.log.debug("sizeLimitExceeded exception caught, processing partial results")
                resp = e.getAnswers()
            else:
                nxc_logger.debug(e)
                return False

        keywords_lower = [k.lower() for k in self.keywords]
        findings = []

        for item in resp:
            if isinstance(item, SearchResultEntry) is not True:
                continue

            try:
                attrs = {str(a["type"]): a["vals"] for a in item["attributes"]}
            except Exception:
                continue

            desc = None
            sam = None
            dn = None
            name = None
            if "description" in attrs and attrs["description"]:
                desc = "".join([str(v) for v in attrs["description"]])
            if "sAMAccountName" in attrs and attrs["sAMAccountName"]:
                sam = str(attrs["sAMAccountName"][0])
            if "distinguishedName" in attrs and attrs["distinguishedName"]:
                dn = str(attrs["distinguishedName"][0])
            if "name" in attrs and attrs["name"]:
                name = str(attrs["name"][0])

            if not desc:
                continue

            desc_lower = desc.lower()
            matches = [k for k in keywords_lower if k in desc_lower]
            if matches:
                findings.append({
                    "sam": sam or name or "(unknown)",
                    "dn": dn or "(unknown)",
                    "description": desc,
                    "matches": matches,
                })

        if not findings:
            context.log.success("No potential password keywords found in user descriptions.")
            return

        context.log.success(f"Found {len(findings)} user(s) with potential password keywords:")
        for f in findings:
            context.log.highlight(f"- {f['sam']:<30} DN={f['dn']}")
            context.log.display(f"    Matches: {', '.join(f['matches'])}")
            context.log.display(f"    Description: {f['description']}")