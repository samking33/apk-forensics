"""
Crystal Reports Exporter for fSOC APK Forensics
Generates XML datasets compatible with SAP Crystal Reports
"""

import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Any, List

class CrystalExporter:
    """Generates Crystal Reports compatible XML datasets from forensic reports."""

    def __init__(self, text_report_path: str, output_xml_path: str = None):
        self.text_report_path = text_report_path

        if output_xml_path is None:
            base_path = os.path.splitext(text_report_path)[0]
            self.output_xml_path = f"{base_path}.xml"
        else:
            self.output_xml_path = output_xml_path

    def _parse_report(self) -> Dict[str, Any]:
        """Parse the unstructured text report into structured data."""
        with open(self.text_report_path, 'r', encoding='utf-8') as f:
            content = f.read()

        data = {
            'metadata': {},
            'findings': [],
            'iocs': [],
            'permissions': []
        }

        # Extract Executive Summary info
        malware_type_match = re.search(r'Malware Type:\s*(.+)', content, re.IGNORECASE)
        risk_level_match = re.search(r'Risk Level:\s*(.+)', content, re.IGNORECASE)

        data['metadata']['malware_type'] = malware_type_match.group(1).strip() if malware_type_match else "Unknown"
        data['metadata']['risk_level'] = risk_level_match.group(1).strip() if risk_level_match else "Unknown"
        data['metadata']['analysis_date'] = datetime.now().isoformat()
        data['metadata']['analyst'] = "fSOC Automated Analyst"

        # Extract Hash (assuming it appears as SHA-256: ...)
        hash_match = re.search(r'SHA-256:?\s*([a-fA-F0-9]{64})', content)
        data['metadata']['sha256'] = hash_match.group(1) if hash_match else "Not Found"

        # Extract IoCs (URLs)
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)
        for url in set(urls): # dedup
            data['iocs'].append({'type': 'URL', 'value': url})

        # Extract IoCs (IPs)
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
        for ip in set(ips):
            if not ip.startswith("127.0.") and not ip.startswith("0."): # Filter localhost
                data['iocs'].append({'type': 'IPv4', 'value': ip})

        return data

    def generate(self) -> str:
        """Generate the XML file."""
        data = self._parse_report()

        root = ET.Element("ForensicReport")

        # Metadata Section
        meta_node = ET.SubElement(root, "Metadata")
        for k, v in data['metadata'].items():
            elem = ET.SubElement(meta_node, k.replace('_', '').title())
            elem.text = str(v)

        # IoCs Section
        iocs_node = ET.SubElement(root, "IoCs")
        for ioc in data['iocs']:
            ioc_elem = ET.SubElement(iocs_node, "IoC")
            type_elem = ET.SubElement(ioc_elem, "Type")
            type_elem.text = ioc['type']
            val_elem = ET.SubElement(ioc_elem, "Value")
            val_elem.text = ioc['value']

        # Create the XML tree
        tree = ET.ElementTree(root)

        # Indent for pretty printing (Py3.9+ has indent, but let's be safe for 3.8)
        try:
            ET.indent(tree, space="  ", level=0)
        except AttributeError:
            pass # older python versions

        try:
            tree.write(self.output_xml_path, encoding='utf-8', xml_declaration=True)
            return self.output_xml_path
        except Exception as e:
            raise Exception(f"Failed to generate Crystal XML: {e}")

def convert_report_to_crystal(text_report_path: str, output_xml_path: str = None) -> str:
    """Wrapper function to generate Crystal Reports XML."""
    exporter = CrystalExporter(text_report_path, output_xml_path)
    return exporter.generate()
