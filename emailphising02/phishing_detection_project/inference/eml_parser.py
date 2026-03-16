import email
from email.message import Message
from email.policy import default
from typing import Optional, Tuple

from bs4 import BeautifulSoup


def _decode_payload(part: Message) -> str:
    # get_payload(decode=True) returns bytes (or None)
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except Exception:
        return payload.decode("utf-8", errors="replace")


def _extract_best_bodies(msg: Message) -> Tuple[str, str]:
    """
    Returns (plain_text, html_text)
    """
    plain_parts = []
    html_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            disp = (part.get_content_disposition() or "").lower()

            if disp == "attachment":
                continue

            if ctype == "text/plain":
                plain_parts.append(_decode_payload(part))
            elif ctype == "text/html":
                html_parts.append(_decode_payload(part))
    else:
        ctype = (msg.get_content_type() or "").lower()
        if ctype == "text/plain":
            plain_parts.append(_decode_payload(msg))
        elif ctype == "text/html":
            html_parts.append(_decode_payload(msg))

    plain_text = "\n".join(plain_parts).strip()
    html_text = "\n".join(html_parts).strip()
    return plain_text, html_text


def eml_to_text(eml_bytes: bytes) -> str:
    msg = email.message_from_bytes(eml_bytes, policy=default)
    subject = msg.get("subject", "") or ""
    from_ = msg.get("from", "") or ""
    to_ = msg.get("to", "") or ""
    date = msg.get("date", "") or ""

    plain, html = _extract_best_bodies(msg)
    text_parts = []
    if plain:
        text_parts.append(plain)
    if html:
        try:
            # Prefer lxml if available, otherwise html.parser
            features = "lxml" if "lxml" in str(BeautifulSoup) else "html.parser"
            soup = BeautifulSoup(html, features=features)
            text_from_html = soup.get_text(separator=" ", strip=True)
            text_parts.append(text_from_html)
        except Exception:
            # Fallback to original HTML if parsing fails
            text_parts.append(html)

    # The final 'plain' content is now a combination of plain text parts and
    # text extracted from HTML, if any.
    final_text_body = "\n\n".join([t for t in text_parts if t]).strip()

    headers = []
    if subject:
        headers.append(f"subject: {subject}")
    if from_:
        headers.append(f"from: {from_}")
    if to_:
        headers.append(f"to: {to_}")
    if date:
        headers.append(f"date: {date}")

    out = "\n".join(headers + ["", plain]).strip()
    return out


def load_eml_file(path: str) -> str:
    with open(path, "rb") as f:
        b = f.read()
    return eml_to_text(b)

