from nxc.helpers.misc import CATEGORY
from nxc.logger import nxc_logger
from impacket.ldap.ldap import LDAPSearchError
from impacket.ldap.ldapasn1 import SearchResultEntry


class NXCModule:
    """
    Enumerate Managed Service Accounts (MSA), Delegated Managed Service Accounts (dMSA), and Group Managed Service Accounts (gMSA).
    """

    name = "enum-msas"
    description = "Enumerate managed service accounts and delegated MSAs"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        # No options required
        pass

    def on_login(self, context, connection):
        """
        Searches AD for objects with objectClass msDS-ManagedServiceAccount, msDS-DelegatedManagedServiceAccount, and msDS-GroupManagedServiceAccount and prints useful attributes.
        """
        search_filter = '(|(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-DelegatedManagedServiceAccount))'
        attributes = [
            # include 'name' as a fallback when sAMAccountName is not present
            "name",
            "sAMAccountName",
            "distinguishedName",
            "objectClass",
            "msDS-ManagedBy",
            "msDS-DelegatedMSAState",
            "msDS-ManagedPassword",
            "msDS-GroupMSAMembership",
        ]

        try:
            context.log.debug(f"Search Filter={search_filter}")
            resp = connection.ldap_connection.search(searchFilter=search_filter, attributes=attributes, sizeLimit=0)
        except LDAPSearchError as e:
            # sizeLimitExceeded is handled by impacket exception in other modules
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                context.log.debug("sizeLimitExceeded exception caught, processing partial results")
                resp = e.getAnswers()
            else:
                nxc_logger.debug(e)
                return False

        entries = []
        for item in resp:
            if isinstance(item, SearchResultEntry) is not True:
                continue

            sam = ""
            dn = ""
            objcls = []
            delegated_state = None
            managed_by = None
            has_managed_password = False
            try:
                for attribute in item["attributes"]:
                    atype = str(attribute["type"])
                    if atype == "sAMAccountName":
                        sam = str(attribute["vals"][0])
                    elif atype == "name" and sam == "":
                        # fallback when sAMAccountName is missing
                        sam = str(attribute["vals"][0])
                    elif atype == "distinguishedName":
                        dn = str(attribute["vals"][0])
                    elif atype == "objectClass":
                        # objectClass can be multiple values
                        objcls = [str(v).lower() for v in attribute["vals"]]
                    elif atype == "msDS-DelegatedMSAState":
                        delegated_state = attribute["vals"][0]
                    elif atype == "msDS-ManagedBy":
                        managed_by = attribute["vals"][0]
                    elif atype == "msDS-ManagedPassword":
                        has_managed_password = True
                entries.append({
                    "sam": sam,
                    "dn": dn,
                    "objectClass": objcls,
                    "delegated_state": delegated_state,
                    "managed_by": managed_by,
                    "has_managed_password": has_managed_password,
                })
            except Exception as e:
                context.log.debug("Exception while parsing entry", exc_info=True)

        if len(entries) == 0:
            context.log.fail("No managed service accounts (MSA/gMSA) found.")
            return

        # Display results grouped by type: gMSA, delegated MSA (dMSA), regular MSA
        gmsa_found = False
        dmsa_found = False
        msa_found = False
        for e in entries:
            if any("groupmanagedserviceaccount" in s for s in e["objectClass"]):
                gmsa_found = True
            if any("delegatedmanagedserviceaccount" in s for s in e["objectClass"]):
                dmsa_found = True
            if any("managedserviceaccount" in s for s in e["objectClass"]) and not any("groupmanagedserviceaccount" in s for s in e["objectClass"]) and not any("delegatedmanagedserviceaccount" in s for s in e["objectClass"]):
                msa_found = True

        if gmsa_found:
            context.log.success("Found Group Managed Service Accounts (gMSA):")
            for e in entries:
                if any("groupmanagedserviceaccount" in s for s in e["objectClass"]):
                    context.log.highlight(f"- {e['sam']:<30} DN={e['dn']}")
                    if e["managed_by"]:
                        context.log.display(f"    ManagedBy: {e['managed_by']}")

        if dmsa_found:
            context.log.success("Found Delegated Managed Service Accounts (dMSA):")
            for e in entries:
                if any("delegatedmanagedserviceaccount" in s for s in e["objectClass"]):
                    state = e.get("delegated_state")
                    state_str = str(state) if state is not None else "Unknown"
                    context.log.highlight(f"- {e['sam']:<30} DN={e['dn']} (Delegated State: {state_str})")
                    if e["managed_by"]:
                        context.log.display(f"    ManagedBy: {e['managed_by']}")

        if msa_found:
            context.log.success("Found Managed Service Accounts (MSA):")
            for e in entries:
                if any("managedserviceaccount" in s and "groupmanagedserviceaccount" not in s and "delegatedmanagedserviceaccount" not in s for s in e["objectClass"]):
                    delegated = "(Delegated)" if e["delegated_state"] else ""
                    context.log.highlight(f"- {e['sam']:<30} DN={e['dn']} {delegated}")
                    if e["delegated_state"]:
                        context.log.display(f"    Delegated state: {e['delegated_state']}")
                    if e["managed_by"]:
                        context.log.display(f"    ManagedBy: {e['managed_by']}")

        # If none matched specific types but entries exist, show generic listing
        if not gmsa_found and not msa_found:
            context.log.success("Found managed accounts:")
            for e in entries:
                context.log.highlight(f"- {e['sam']:<30} DN={e['dn']} Classes={','.join(e['objectClass'])}")