import nmap

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]


def fast_nmap_scan(target):
    try:
        nm = nmap.PortScanner()

        nm.scan(target, arguments="-Pn -T4 -F --host-timeout 10s")

        open_ports = set()

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    if nm[host][proto][port]["state"] == "open":
                        open_ports.add(port)

        return {
            "target": target,
            "method": "nmap-fast",
            "ports": sorted(list(open_ports)),  # ✅ FIXED KEY
            "port_count": len(open_ports)
        }

    except Exception as e:
        return {
            "target": target,
            "method": "nmap-fast",
            "ports": [],
            "port_count": 0,
            "error": str(e)
        }


def fallback_nmap_scan(target):
    try:
        nm = nmap.PortScanner()

        nm.scan(target, arguments="-Pn -T3 --top-ports 20 --host-timeout 15s")

        open_ports = set()

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    if nm[host][proto][port]["state"] == "open":
                        open_ports.add(port)

        return {
            "target": target,
            "method": "nmap-fallback",
            "ports": sorted(list(open_ports)),  # ✅ FIXED
            "port_count": len(open_ports)
        }

    except Exception as e:
        return {
            "target": target,
            "method": "nmap-fallback",
            "ports": [],
            "port_count": 0,
            "error": str(e)
        }


# ✅ MATCH YOUR API NAME
def run_nmap_scan(target):
    result = fast_nmap_scan(target)

    if result.get("error") or result["port_count"] == 0:
        return fallback_nmap_scan(target)

    return result