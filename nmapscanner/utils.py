import re
import ipaddress



from PySide6.QtGui import QColor


def clean_and_parse_ips(raw_text):
    ip_pattern = r'\b((?:\d{1,3}\.){3}\d{1,3})\b'
    range_pattern = r'\b((?:\d{1,3}\.){3}\d{1,3})-(\d{1,3})\b'
    cidr_pattern = r'\b(?:\d{1,3}\.){3}\d{1,2}\b'
    found_ips, found_ranges, found_cidrs = re.findall(ip_pattern, raw_text), re.findall(range_pattern, raw_text), re.findall(cidr_pattern, raw_text)
    processed_ips = set(found_ips)
    for base, end_str in found_ranges:
        try:
            start_ip, end_octet = ipaddress.ip_address(base), int(end_str)
            start_octet = int(str(start_ip).split('.')[-1])
            if start_octet > end_octet: start_octet, end_octet = end_octet, start_octet
            base_prefix = ".".join(str(start_ip).split('.')[:-1])
            for i in range(start_octet, end_octet + 1): processed_ips.add(f"{base_prefix}.{i}")
        except (ValueError, IndexError): continue
    for cidr in found_cidrs:
        try:
            if cidr.endswith('/'): continue
            for ip in ipaddress.ip_network(cidr, strict=False): processed_ips.add(str(ip))
        except ValueError: continue
    sorted_ips = sorted(list(processed_ips), key=lambda ip: int(ipaddress.ip_address(ip)))
    formatted_output, last_prefix = [], None
    for ip in sorted_ips:
        current_prefix = ".".join(ip.split('.')[:3])
        if last_prefix and last_prefix != current_prefix: formatted_output.append("")
        formatted_output.append(ip)
        last_prefix = current_prefix
    return formatted_output, len(sorted_ips)

def get_color_for_ip(ip_str):
    color_palette = ["#4E79A7", "#F28E2B", "#E15759", "#76B7B2", "#59A14F",
                     "#EDC948", "#B07AA1", "#FF9DA7", "#9C755F", "#BAB0AC"]
    try:
        third_octet = int(ip_str.split('.')[2])
        return QColor(color_palette[third_octet % len(color_palette)])
    except:
        return QColor("black")


def register_project_report(widget, path, source, type_, language=""):
    """Z libovolného dialogu zaregistruje vytvořený soubor reportu do projektu.

    Vyjde po stromu rodičů až k hlavnímu oknu (které má ``register_export``).
    Tiše ignoruje, pokud okno helper nemá (např. samostatně spuštěný dialog).
    """
    w = widget
    seen = 0
    while w is not None and seen < 12:
        if hasattr(w, "register_export"):
            try:
                w.register_export(path, source, type_, language)
            except Exception:
                pass
            return True
        w = w.parent() if hasattr(w, "parent") else None
        seen += 1
    return False
