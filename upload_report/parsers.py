"""
Complete file parsers module for handling various report formats.
Supports: PDF, CSV, Excel, XML, Nessus (.nessus), Nessus HTML
"""

import os
import re
import html
import json
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
import pandas as pd
from PyPDF2 import PdfReader

# BeautifulSoup import with safe fallback
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    BeautifulSoup = None


# ==================== HELPER FUNCTIONS ==================== #



def _safe_text(elem, tag_name: str) -> str:
    """Helper: get text of a child tag or empty string."""
    child = elem.find(tag_name)
    return (child.text or "").strip() if child is not None and child.text else ""

def _clean_text(node) -> str:
    """Return cleaned text from a BeautifulSoup node or string."""
    if not node:
        return ""
    if isinstance(node, str):
        return html.unescape(node).strip()
    return html.unescape(node.get_text(" ", strip=True)).strip()


def _text_of_next_sibling(node) -> str:
    """Return cleaned text of the next sibling element."""
    if node is None:
        return ""
    nxt = node.find_next_sibling()
    if nxt:
        return _clean_text(nxt)
    return ""


def _html_table_to_map(table) -> Dict[str, Any]:
    """Convert a two-column HTML table into a dictionary."""
    data: Dict[str, Any] = {}
    if not table:
        return data
    for row in table.find_all("tr"):
        cells = row.find_all("td")
        if len(cells) >= 2:
            key = _clean_text(cells[0]).rstrip(":")
            value = _clean_text(cells[1])
            if key:
                data[key] = value
    return data


def _shape_dataframe_payload(df: pd.DataFrame) -> Dict[str, Any]:
    """Create a lightweight representation of dataframe for API."""
    preview_rows = df.head(50).fillna("").to_dict(orient="records")
    return {
        "columns": df.columns.tolist(),
        "rows": len(df.index),
        "preview": preview_rows,
    }


# -------------------- Text Helpers -------------------- #

def _split_text_to_points(text: str) -> List[str]:
    """Split a blob of text into bullet-style points."""
    if not text:
        return []
    parts = re.split(r"\n+|\r+", text)
    cleaned: List[str] = []
    for part in parts:
        value = part.strip(" -•\t")
        if value:
            cleaned.append(value)
    return cleaned


# ==================== PDF PARSER ==================== #

def parse_pdf(file_path: str) -> Dict[str, Any]:
    """Parse PDF and extract text content."""
    try:
        reader = PdfReader(file_path)
        texts: List[str] = []
        for page in reader.pages:
            try:
                texts.append(page.extract_text() or "")
            except Exception:
                texts.append("")
        full_text = "\n".join(texts).strip()
        return {
            "type": "pdf",
            "pages": len(reader.pages),
            "text_preview": full_text[:5000],
            "text_full": full_text,
        }
    except Exception as exc:
        return {"error": f"PDF parse error: {exc}"}


# ==================== CSV PARSER ==================== #

def parse_csv(file_path: str) -> Dict[str, Any]:
    """Parse CSV file into structured data."""
    try:
        df = pd.read_csv(file_path)
        return {"type": "csv", **_shape_dataframe_payload(df)}
    except Exception as exc:
        return {"error": f"CSV parse error: {exc}"}


# ==================== EXCEL PARSER ==================== #

def parse_excel(file_path: str) -> Dict[str, Any]:
    """Parse Excel file into structured data."""
    try:
        df = pd.read_excel(file_path)
        return {"type": "excel", **_shape_dataframe_payload(df)}
    except Exception as exc:
        return {"error": f"Excel parse error: {exc}"}


# ==================== NESSUS XML PARSER ==================== #

# def parse_nessus_xml(file_path: str) -> Dict[str, Any]:
#     """
#     Parse Nessus XML (.nessus or .xml) format.
    
#     Returns structured data with vulnerabilities grouped by host.
#     """
#     try:
#         tree = ET.parse(file_path)
#         root = tree.getroot()
#     except Exception as exc:
#         return {"error": f"XML parse error: {exc}"}

#     # Find Report root
#     report = root.find(".//Report") or root.find("Report") or root

#     # Extract scan information
#     scan_info: Dict[str, Any] = {}
#     policy = root.find(".//Policy")
#     if policy is not None:
#         scan_info["policy_name"] = (policy.findtext("policyName") or "").strip()
    
#     preferences = root.find(".//Preferences")
#     if preferences is not None:
#         for pref in preferences.findall("preference"):
#             name = pref.findtext("name")
#             value = pref.findtext("value")
#             if name:
#                 scan_info[name] = value

#     vulnerabilities_by_host: List[Dict[str, Any]] = []

#     # Iterate through each ReportHost
#     for report_host in report.findall(".//ReportHost"):
#         host_name = report_host.get("name", "unknown-host")
        
#         host_entry = {
#             "host_name": host_name,
#             "host_information": {},
#             "vulnerabilities": []
#         }

#         # Extract HostProperties
#         host_props = report_host.find("HostProperties")
#         if host_props is not None:
#             for tag in host_props.findall("tag"):
#                 tag_name = tag.get("name")
#                 if tag_name:
#                     host_entry["host_information"][tag_name] = (tag.text or "").strip()

#         # Extract ReportItem entries (vulnerabilities)
#         for item in report_host.findall(".//ReportItem"):
#             vuln = {
#                 "plugin_id": item.get("pluginID"),
#                 "plugin_name": item.get("pluginName"),
#                 "port": item.get("port"),
#                 "protocol": item.get("protocol"),
#                 "severity": item.get("severity"),
#                 "risk_factor": (item.findtext("risk_factor") or "").strip(),
#                 "synopsis": (item.findtext("synopsis") or "").strip(),
#                 "description": (item.findtext("description") or "").strip(),
#                 "solution": (item.findtext("solution") or "").strip(),
#                 "see_also": [e.text.strip() for e in item.findall("see_also") if e.text],
#                 "cvss_v3_base_score": (
#                     item.findtext(".//cvss3_base_score") or 
#                     item.findtext(".//cvss_base_score") or ""
#                 ).strip(),
#                 "plugin_information": (item.findtext("plugin_publication_date") or "").strip(),
#                 "plugin_output": (item.findtext("plugin_output") or "").strip()[:5000],  # Limit size
#             }
#             host_entry["vulnerabilities"].append(vuln)

#         vulnerabilities_by_host.append(host_entry)

#     total_hosts = len(vulnerabilities_by_host)
#     total_vulnerabilities = sum(len(h["vulnerabilities"]) for h in vulnerabilities_by_host)

#     return {
#         "type": "nessus",
#         "scan_info": scan_info,
#         "total_hosts": total_hosts,
#         "total_vulnerabilities": total_vulnerabilities,
#         "vulnerabilities_by_host": vulnerabilities_by_host
#     }





def parse_nessus_xml_streaming(file_path: str) -> Dict[str, Any]:
    """
    Stream-parse a Nessus XML (.nessus / .xml) file and return structured data.

    Memory: uses ET.iterparse and calls elem.clear() for processed subtrees,
    so it can handle very large .nessus files without loading whole file.
    """
    try:
        # Use iterparse to stream through the document.
        # We watch for 'start' and 'end' events so we can build hosts and reportitems.
        context = ET.iterparse(file_path, events=("start", "end"))
    except Exception as exc:
        return {"error": f"XML open/iterparse error: {exc}"}

    # Variables to build results
    vulnerabilities_by_host: List[Dict[str, Any]] = []
    scan_info: Dict[str, Any] = {}
    current_host: Dict[str, Any] = None
    in_report = False

    # Helper to get the localname of a tag (in case namespaces are present)
    def local(tag: str) -> str:
        if '}' in tag:
            return tag.split('}', 1)[1].lower()
        return tag.lower()

    try:
        for event, elem in context:
            tag = local(elem.tag)

            # Detect the root Report element start (optional)
            if event == "start" and tag == "report":
                in_report = True

            # Start of ReportHost -> create current_host
            if event == "start" and tag == "reporthost":
                host_name = elem.get("name") or ""
                current_host = {
                    "host_name": host_name,
                    "host_information": {},
                    "vulnerabilities": []
                }

            # HostProperties tag processing - tags inside HostProperties are <tag name="...">value</tag>
            if event == "end" and tag == "tag" and current_host is not None:
                name = elem.get("name")
                if name:
                    # Use elem.text (may be None)
                    current_host["host_information"][name] = (elem.text or "").strip()
                # Clear tag element to free memory
                elem.clear()

            # End of a ReportItem (a vulnerability) inside a ReportHost
            if event == "end" and tag == "reportitem" and current_host is not None:
                # Build vuln dict from children; use find/findtext as needed
                # We prefer direct attributes for plugin id/name etc.
                vuln = {
                    "plugin_id": elem.get("pluginID") or elem.get("pluginid") or None,
                    "plugin_name": elem.get("pluginName") or elem.get("pluginname") or None,
                    "port": elem.get("port"),
                    "protocol": elem.get("protocol"),
                    "severity": elem.get("severity"),
                    # risk_factor may appear as <risk_factor> or as text of some child - safe getter below
                    "risk_factor": (_safe_text(elem, "risk_factor") or _safe_text(elem, "riskfactor") or "").strip(),
                    "synopsis": _safe_text(elem, "synopsis"),
                    "description": _safe_text(elem, "description"),
                    "description_points": [],
                    "solution": _safe_text(elem, "solution"),
                    "see_also": [],
                    "cvss_v3_base_score": (_safe_text(elem, "cvss3_base_score") or _safe_text(elem, "cvss_base_score") or "").strip(),
                    "plugin_information": _safe_text(elem, "plugin_publication_date") or _safe_text(elem, "plugin_publication") or "",
                    # plugin_output may be large; keep limited
                    "plugin_output": (_safe_text(elem, "plugin_output") or "")[:20000],
                }

                # Try to extract multiple <see_also> children (if present)
                see_also_list = []
                for see in elem.findall("see_also"):
                    if see is not None and see.text:
                        text = see.text.strip()
                        if text:
                            see_also_list.append(text)
                vuln["see_also"] = see_also_list

                # Turn description into bullet points if multi-line
                desc = vuln["description"] or ""
                if desc:
                    # split on newlines and common separators, keep short list
                    pts = [p.strip(" -•\t") for p in desc.splitlines() if p.strip()]
                    vuln["description_points"] = pts[:200]

                current_host["vulnerabilities"].append(vuln)

                # Clear the ReportItem subtree to free memory
                elem.clear()

            # End of this ReportHost -> append to list and clear memory
            if event == "end" and tag == "reporthost":
                # Only include host if it has vulnerabilities or host_information (keeps result compact)
                if current_host is not None and (current_host["vulnerabilities"] or current_host["host_information"]):
                    vulnerabilities_by_host.append(current_host)
                # Clear host element
                elem.clear()
                current_host = None

            # Optionally capture scan-level metadata from Policy/Preferences etc.
            # When we hit end of Policy or Preferences children, pick useful info.
            if event == "end" and tag == "policy":
                # policyName under Policy
                pname = elem.findtext("policyName")
                if pname:
                    scan_info["policy_name"] = pname.strip()
                elem.clear()

            if event == "end" and tag == "preferences":
                # preferences contains multiple <preference><name>..</name><value>..</value></preference>
                for pref in elem.findall("preference"):
                    name = pref.findtext("name")
                    val = pref.findtext("value")
                    if name:
                        scan_info[name] = val or ""
                elem.clear()

        # End for loop
    except Exception as exc:
        # In case of unexpected parse error, return a helpful message
        return {"error": f"Nessus XML streaming parse error: {exc}"}

    # Summarize results
    total_hosts = len(vulnerabilities_by_host)
    total_vulnerabilities = sum(len(h.get("vulnerabilities", [])) for h in vulnerabilities_by_host)

    return {
        "type": "nessus",
        "scan_info": scan_info,
        "total_hosts": total_hosts,
        "total_vulnerabilities": total_vulnerabilities,
        "vulnerabilities_by_host": vulnerabilities_by_host
    }

# Backwards-compat alias if you want to keep old name
parse_nessus_xml = parse_nessus_xml_streaming
parse_nessus = parse_nessus_xml_streaming


# ==================== NESSUS HTML PARSER ==================== #

def parse_nessus_html(file_path: str) -> Dict[str, Any]:
    """
    Parse Nessus HTML export format.
    
    Extracts:
    - Scan information
    - Vulnerabilities by Host
    - Host Information
    - Vulnerability details (Synopsis, Description, See Also, Solution, 
      Risk Factor, CVSS v3.0 Base Score, Plugin Information, Plugin Output)
    
    Returns structured data ready for MongoDB storage.
    """
    if not BS4_AVAILABLE:
        return {"error": "BeautifulSoup4 is required. Install: pip install beautifulsoup4"}

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
            content = fp.read()
    except Exception as exc:
        return {"error": f"Could not open HTML file: {exc}"}

    soup = BeautifulSoup(content, "html.parser")
    text_lower = soup.get_text(" ", strip=True).lower()

    # Verify this is a Nessus report - check for multiple indicators
    is_nessus = (
        "tenable" in text_lower or 
        "nessus" in text_lower or 
        "report generated by" in text_lower or
        "vulnerabilities by host" in text_lower
    )
    
    if not is_nessus:
        return parse_html(file_path)  # Fallback to generic HTML parser

    # Extract scan information
    scan_info = {}
    
    # Report title
    title_tag = soup.find("title")
    if title_tag:
        scan_info["report_name"] = _clean_text(title_tag)
    
    # Find scan date from header
    for heading in soup.find_all(["h3", "h4", "h5"]):
        text = _clean_text(heading)
        if re.search(r"\d{4}", text):  # Contains year
            scan_info["scan_date"] = text
            break

    # Extract scan time from "Scan Information" table
    scan_info_div = soup.find(lambda tag: tag.name in ("h6", "div") and "vulnerabilities by host" in _clean_text(tag).lower())
    if scan_info_div:
        scan_table = scan_info_div.find_next("div", class_="table-wrapper", string=False)
        if scan_table:
            table = scan_table.find("table")
            if table:
                scan_data = _html_table_to_map(table)
                scan_info.update(scan_data)

    # Find all host sections - look for divs with font-size: 22px and font-weight: 700
    vulnerabilities_by_host: List[Dict[str, Any]] = []
    
    # Pattern: div with style containing "font-size: 22px" and "font-weight: 700"
    all_divs = soup.find_all("div")
    host_headers = []
    for div in all_divs:
        style = div.get("style", "")
        if "font-size: 22px" in style and "font-weight: 700" in style:
            host_text = _clean_text(div)
            # Check if it looks like an IP address or hostname
            if host_text and (re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host_text) or len(host_text) < 300):
                host_headers.append((div, host_text))
    
    for idx, (host_header, host_name) in enumerate(host_headers):
        if not host_name:
            continue
        
        host_entry = {
            "host_name": host_name,
            "host_information": {},
            "vulnerabilities": []
        }
        
        # Find next host header to determine boundary
        next_host_header = None
        if idx + 1 < len(host_headers):
            next_host_header = host_headers[idx + 1][0]
        
        # Process content between this host and next host
        current = host_header.next_sibling
        
        while current:
            # Stop at next host
            if current == next_host_header:
                break
            
            if not hasattr(current, 'name'):
                current = current.next_sibling if hasattr(current, 'next_sibling') else None
                continue
            
            # Check for "Host Information" section
            if current.name == "div":
                classes = current.get("class", [])
                if "details-header" in classes:
                    header_text = _clean_text(current).lower()
                    
                    if "host information" in header_text:
                        # Extract host properties table
                        table_wrapper = current.find_next_sibling("div", class_="table-wrapper")
                        if table_wrapper:
                            table = table_wrapper.find("table")
                            if table:
                                host_entry["host_information"] = _html_table_to_map(table)
                
                # Check for vulnerability toggle divs (containing plugin ID and name)
                onclick = current.get("onclick", "")
                if "toggleSection" in onclick:
                    vuln_title = _clean_text(current)
                    
                    # Parse plugin ID and name from title (format: "51192 - SSL Certificate Cannot Be Trusted")
                    plugin_id = None
                    plugin_name = vuln_title
                    match = re.match(r"^\s*(\d+)\s*[-:]\s*(.+)$", vuln_title)
                    if match:
                        plugin_id = match.group(1).strip()
                        plugin_name = match.group(2).strip()
                    
                    # Find vulnerability details container (next sibling with class "section-wrapper")
                    vuln_container = current.find_next_sibling("div", class_="section-wrapper")
                    
                    if vuln_container:
                        vuln_data = {
                            "plugin_id": plugin_id,
                            "plugin_name": plugin_name,
                            "synopsis": "",
                            "description": "",
                            "see_also": [],
                            "solution": "",
                            "risk_factor": "",
                            "cvss_v3_base_score": "",
                            "plugin_information": "",
                            "plugin_output": ""
                        }
                        
                        # Parse all field sections within the vulnerability container
                        field_headers = vuln_container.find_all("div", class_="details-header")
                        
                        for field_header in field_headers:
                            field_name = _clean_text(field_header).strip()
                            field_name_lower = field_name.lower()
                            
                            # Get the content div after this header
                            content_div = field_header.find_next_sibling("div")
                            
                            # Handle "See Also" - it might be in a table
                            if "see also" in field_name_lower:
                                # Look for table with links
                                see_also_table = field_header.find_next("div", class_="table-wrapper")
                                links = []
                                if see_also_table:
                                    table = see_also_table.find("table")
                                    if table:
                                        for link_tag in table.find_all("a", href=True):
                                            href = link_tag.get("href", "")
                                            if href:
                                                links.append(href)
                                elif content_div:
                                    # Fallback: extract links from text
                                    text = _clean_text(content_div)
                                    links = [l.strip() for l in re.split(r'[\n,;]+', text) if l.strip() and l.strip().startswith(('http://', 'https://'))]
                                
                                vuln_data["see_also"] = links[:50]
                            
                            # Handle "Plugin Output" - it contains h2 tags with port info and monospace divs
                            elif "plugin output" in field_name_lower:
                                # Find all h2 tags (port/service identifiers) and their associated content
                                h2_tags = field_header.find_all_next("h2", limit=50)
                                output_parts = []
                                
                                for h2 in h2_tags:
                                    if h2.find_parent("div", class_="section-wrapper") != vuln_container:
                                        break
                                    
                                    port_service = _clean_text(h2)
                                    if port_service:
                                        output_parts.append(port_service)
                                    
                                    # Find monospace-styled div after h2
                                    monospace_div = h2.find_next_sibling("div")
                                    if monospace_div:
                                        style = monospace_div.get("style", "")
                                        if "monospace" in style.lower() or "font-family: monospace" in style.lower():
                                            output_parts.append(_clean_text(monospace_div))
                                
                                vuln_data["plugin_output"] = "\n".join(output_parts).strip()[:20000]
                            
                            # Handle other fields - extract text content from following div
                            elif content_div:
                                content_text = _clean_text(content_div)
                                
                                if "synopsis" in field_name_lower:
                                    synopsis_text = content_div.get_text("\n", strip=True)
                                    vuln_data["synopsis"] = synopsis_text[:20000]
                                elif "description" in field_name_lower:
                                    desc_text = content_div.get_text("\n", strip=True)
                                    vuln_data["description"] = desc_text[:20000]
                                    vuln_data["description_points"] = _split_text_to_points(desc_text)
                                elif "solution" in field_name_lower:
                                    vuln_data["solution"] = content_text[:20000]
                                elif "risk factor" in field_name_lower:
                                    vuln_data["risk_factor"] = content_text.strip()
                                elif "cvss" in field_name_lower and "v3" in field_name_lower:
                                    # Extract just the score number from text like "6.5 (CVSS:3.0/AV:N/...)"
                                    score_match = re.search(r"([\d.]+)", content_text)
                                    if score_match:
                                        vuln_data["cvss_v3_base_score"] = score_match.group(1)
                                    else:
                                        vuln_data["cvss_v3_base_score"] = content_text.strip()[:50]
                                elif "plugin information" in field_name_lower:
                                    vuln_data["plugin_information"] = content_text[:20000]
                        
                        host_entry["vulnerabilities"].append(vuln_data)
            
            # Move to next sibling
            try:
                current = current.next_sibling if hasattr(current, 'next_sibling') else None
            except:
                break
        
        # Only add host if it has vulnerabilities or host information
        if host_entry["vulnerabilities"] or host_entry["host_information"]:
            vulnerabilities_by_host.append(host_entry)
    
    def _filter_hosts_by_severity(hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        allowed = {"critical", "high", "medium", "low"}
        filtered_hosts: List[Dict[str, Any]] = []
        for host in hosts:
            filtered_vulns: List[Dict[str, Any]] = []
            for vuln in host.get("vulnerabilities", []):
                risk = (vuln.get("risk_factor") or "").strip().lower()
                if risk and risk not in allowed:
                    continue
                filtered_vulns.append(vuln)
            if filtered_vulns:
                new_host = {
                    "host_name": host.get("host_name"),
                    "host_information": host.get("host_information", {}),
                    "vulnerabilities": filtered_vulns
                }
                filtered_hosts.append(new_host)
        return filtered_hosts

    filtered_hosts = _filter_hosts_by_severity(vulnerabilities_by_host)
    total_hosts = len(filtered_hosts)
    total_vulnerabilities = sum(len(h["vulnerabilities"]) for h in filtered_hosts)
    
    # If we found nothing, fallback to generic HTML
    if total_vulnerabilities == 0 and total_hosts == 0:
        return parse_html(file_path)
    
    return {
        "type": "nessus_html",
        "scan_info": scan_info,
        "total_hosts": total_hosts,
        "total_vulnerabilities": total_vulnerabilities,
        "vulnerabilities_by_host": filtered_hosts
    }


# ==================== GENERIC HTML PARSER ==================== #

def parse_html(file_path: str) -> Dict[str, Any]:
    """Generic HTML parser for non-Nessus HTML files."""
    if not BS4_AVAILABLE:
        return {"error": "BeautifulSoup4 is required. Install: pip install beautifulsoup4"}
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
            content = fp.read()
        
        soup = BeautifulSoup(content, "html.parser")
        
        # Extract title
        title = ""
        if soup.title and soup.title.string:
            title = soup.title.string.strip()
        
        # Extract headings
        headings = []
        for h in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"]):
            text = _clean_text(h)
            if text:
                headings.append(text)
        
        # Extract links
        links = []
        for a in soup.find_all("a", href=True):
            text = _clean_text(a)
            href = a.get("href", "")
            if text or href:
                links.append({"text": text, "href": href})
        
        # Extract body text
        body_text = soup.get_text(" ", strip=True)
        
        return {
            "type": "html",
            "title": title,
            "headings": headings[:100],
            "links": links[:200],
            "text_preview": body_text[:5000],
        }
    except Exception as exc:
        return {"error": f"HTML parse error: {exc}"}


# ==================== MAIN DISPATCHER ==================== #

def dispatch_parse(file_path: str, filename: str) -> Dict[str, Any]:
    """
    Main dispatcher function that routes to appropriate parser based on file extension.
    
    Args:
        file_path: Full path to the file on disk
        filename: Original filename with extension
        
    Returns:
        Parsed data dictionary or error dict
    """
    ext = os.path.splitext(filename)[1].lower()
    
    # PDF files
    if ext == '.pdf':
        return parse_pdf(file_path)
    
    # CSV files
    if ext == '.csv':
        return parse_csv(file_path)
    
    # Excel files
    if ext in ('.xlsx', '.xls'):
        return parse_excel(file_path)
    
    # Nessus XML files
    if ext in ('.xml', '.nessus'):
        # Try XML parser first
        result = parse_nessus_xml(file_path)
        if "error" not in result:
            return result
        # Fallback to HTML parser if XML fails
        return parse_nessus_html(file_path)
    
    # HTML files
    if ext in ('.html', '.htm'):
        return parse_nessus_html(file_path)
    
    # Unsupported format
    return {"error": f"Unsupported file type: {ext}"}


# Alias for backward compatibility
parse_nessus = parse_nessus_xml