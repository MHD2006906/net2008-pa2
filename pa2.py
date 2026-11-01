# Name: Mohannad Fakhoury
# Student ID: 101354778

"""NET2008 Practical Assessment 2 - Fleet Compliance Auditor."""

import sys
import json
import yaml
import xml.etree.ElementTree as ET


class AuditError(Exception):
    pass

class Device:
    """Store information about a device."""

    def __init__(self, device):
        self.device = device

    def get_id(self):
        return self.device.get("id")


#turns version to number to compare later
def compare_versions(version):
    numbers = [int(number) for number in version.split(".")]

    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()

    return numbers

# Read the Inventory, Policy, and Violation

def read_inventory(file, policy_file):

    try:
        inventory_data = ET.parse(file)
        inventory = inventory_data.getroot()

        with open(policy_file, "r") as policy_data:
            policy = yaml.safe_load(policy_data)

        if not isinstance(policy, dict):
            if policy is None:
                policy = {}
            else:
                raise AuditError(f"{policy_file}: policy must be a mapping")

    except (OSError, ET.ParseError, yaml.YAMLError) as error:
        raise AuditError(f"Input file error: {error}") from error

    site = inventory.get("site")
    total_devices = 0
    skipped_devices = 0
    roles = {}
    interfaces = {"up": 0, "down": 0, "other": 0}
    violations = []
    compliant = []

    for device in inventory.findall("device"):
        device_info = Device(device)
        device_id = device_info.get_id()

        if not device_id:
            skipped_devices += 1
            continue

        total_devices += 1

        role = device.get("role", "")
        roles[role] = roles.get(role, 0) + 1

        # Unknown Role
        if "min_os" in policy:
            if role not in policy["min_os"]:
                violations.append({
                    "device": device_id,
                    "type": "unknown_role",
                    "role": role
                })

        # Outdated OS
        if "min_os" in policy:
            if role in policy["min_os"]:
                found = device.get("os", "")
                required = policy["min_os"][role]

                if compare_versions(found) < compare_versions(required):
                    violations.append({
                        "device": device_id,
                        "type": "os_outdated",
                        "found": found,
                        "required": required
                    })

        # Missing Owner
        if policy.get("require_owner", False):
            owner = device.findtext("owner")

            if not owner or not owner.strip():
                violations.append({
                    "device": device_id,
                    "type": "missing_owner"
                })

        down = 0
        for interface in device.findall("interface"):
            status = interface.get("status")

            if status == "up":
                interfaces["up"] += 1

            elif status == "down":
                interfaces["down"] += 1
                down += 1

            else:
                interfaces["other"] += 1

        # Too Many Down
        if "max_down_interfaces" in policy:
            if down > policy["max_down_interfaces"]:
                violations.append({
                    "device": device_id,
                    "type": "too_many_down",
                    "down": down
                })

        if not any(v["device"] == device_id for v in violations):
            compliant.append(device_id)

  

    report = {
        "site": site,
        "total_devices": total_devices,
        "skipped_devices": skipped_devices,
        "roles": roles,
        "interfaces": interfaces,
        "violations": violations,
        "compliant": sorted(compliant)
    }

    with open("audit.json", "w") as audit_file:
        json.dump(report, audit_file, indent=4)

    print("Site:", site)
    print("Total devices:", total_devices)
    print("Skipped devices:", skipped_devices)
    print("Roles:", roles)
    print("Interfaces:", interfaces)
    print("Violations:", violations)
    print("Compliant:", sorted(compliant))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        sys.exit(2)

    try:
        read_inventory(sys.argv[1], sys.argv[2])
    except AuditError as error:
        print(error)
        sys.exit(1)