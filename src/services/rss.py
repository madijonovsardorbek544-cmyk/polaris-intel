from __future__ import annotations

import xml.etree.ElementTree as ET

from src.utils.text import strip_html


def parse_rss_or_atom(xml_text: str, fallback_source: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return entries

    for element in root.iter():
        tag = element.tag.lower()
        if not (tag.endswith("item") or tag.endswith("entry")):
            continue

        title = ""
        link = ""
        summary = ""

        for child in list(element):
            child_tag = child.tag.lower()
            if child_tag.endswith("title") and not title:
                title = strip_html(child.text or "")
            elif child_tag.endswith("description") and not summary:
                summary = strip_html(child.text or "")
            elif child_tag.endswith("summary") and not summary:
                summary = strip_html(child.text or "")
            elif child_tag.endswith("content") and not summary:
                summary = strip_html(child.text or "")
            elif child_tag.endswith("link") and not link:
                href = child.attrib.get("href", "").strip()
                link = href or (child.text or "").strip()

        if title:
            entries.append({"title": title, "link": link or fallback_source, "summary": summary})

    return entries
