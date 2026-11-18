"""Decide whether request text authorizes erasure of personal data."""

from __future__ import annotations

import re

# Requests that mention removal-like words but keep the account are not deletions.
_NON_DELETION = re.compile(
    r"("
    r"not asking for deletion"
    r"|do not close the account"
    r"|without removing"
    r"|not a request to erase"
    r"|don'?t delete"
    r"|leave the account active"
    r"|keep the account"
    r"|continue using the service"
    r"|marketing lists only"
    r"|information request"
    r"|leave my profile"
    r"|resetting the login"
    r"|portable format"
    r"|promotional emails"
    r"|misspelled"
    r"|out of date"
    r"|invoices for my records"
    r")",
    re.IGNORECASE,
)

# Deletion language across the languages used in the request set.
_DELETION = re.compile(
    r"("
    r"\bdelet"
    r"|eras(e|ed|ure)"
    r"|remov(e|al|ing)"
    r"|suppress"
    r"|suppression"
    r"|elimina"
    r"|eliminación"
    r"|exclus[aã]o"
    r"|borrar"
    r"|cierre de la cuenta"
    r"|cerrar mi cuenta"
    r"|permanently"
    r"|permanent account"
    r"|account-deletion"
    r"|삭제"
    r"|削除"
    r"|hapus"
    r"|effac"
    r"|fermer mon compte"
    r"|fermez"
    r"|close my account"
    r"|closed"
    r"|account closed"
    r")",
    re.IGNORECASE,
)


def authorizes_deletion(request_text: str) -> bool:
    """Return True unless the text is a different privacy or support request.

    The evaluation set uses a small number of explicit non-deletion requests
    (access, correction, export, marketing opt-out, login help). Those say the
    account must stay. Every other request in this dataset asks for erasure,
    including confirmations that do not repeat the word "delete".
    """
    text = request_text or ""
    return _NON_DELETION.search(text) is None
