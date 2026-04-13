"""PDF paper reader tool for protoPen.

Uses PyMuPDF (fitz) for text extraction from downloaded papers.
"""

import asyncio
from pathlib import Path
from typing import Any

from nanobot.agent.tools.base import Tool

_PAPERS_DIR = Path("/sandbox/papers")


import re as _re

# Common academic paper section headers
_SECTION_PATTERNS = [
    _re.compile(r'^(Abstract|ABSTRACT)\b', _re.MULTILINE),
    _re.compile(r'^(\d+\.?\s+)?(Introduction|INTRODUCTION)\b', _re.MULTILINE),
    _re.compile(r'^(\d+\.?\s+)?(Related Work|RELATED WORK|Background|BACKGROUND)\b', _re.MULTILINE),
    _re.compile(r'^(\d+\.?\s+)?(Method|METHODS?|Approach|APPROACH|Methodology|METHODOLOGY)\b', _re.MULTILINE),
    _re.compile(r'^(\d+\.?\s+)?(Experiment|EXPERIMENTS?|Evaluation|EVALUATION|Results|RESULTS)\b', _re.MULTILINE),
    _re.compile(r'^(\d+\.?\s+)?(Discussion|DISCUSSION)\b', _re.MULTILINE),
    _re.compile(r'^(\d+\.?\s+)?(Conclusion|CONCLUSIONS?|Summary|SUMMARY)\b', _re.MULTILINE),
    _re.compile(r'^(\d+\.?\s+)?(References|REFERENCES|Bibliography)\b', _re.MULTILINE),
    _re.compile(r'^(\d+\.?\s+)?(Appendix|APPENDIX)\b', _re.MULTILINE),
]


def _detect_sections(text: str) -> str:
    """Add section tags to paper text for better chunking and retrieval."""
    for pattern in _SECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            section_name = match.group(0).strip().lstrip("0123456789. ")
            text = text[:match.start()] + f"\n[SECTION: {section_name}]\n" + text[match.start():]
    return text


def _extract_text(pdf_path: Path, pages: str | None = None) -> str:
    """Extract text from a PDF using PyMuPDF with section detection."""
    import fitz  # PyMuPDF

    doc = fitz.open(str(pdf_path))
    total_pages = len(doc)

    if pages:
        page_nums = set()
        for part in pages.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                for p in range(int(start) - 1, min(int(end), total_pages)):
                    page_nums.add(p)
            else:
                p = int(part) - 1
                if 0 <= p < total_pages:
                    page_nums.add(p)
        page_list = sorted(page_nums)
    else:
        page_list = list(range(total_pages))

    text_parts = []
    for page_num in page_list:
        page = doc[page_num]
        text = page.get_text()
        if text.strip():
            text_parts.append(f"--- Page {page_num + 1} ---\n{text}")

    doc.close()
    full_text = "\n\n".join(text_parts)

    # Detect and tag sections for structured retrieval
    return _detect_sections(full_text)


def _resolve_path(path_or_id: str) -> Path | None:
    """Resolve a paper path from a path string or paper ID."""
    p = Path(path_or_id)
    if p.exists():
        return p

    # Try as paper ID
    safe_id = path_or_id.replace("/", "_")
    pdf_path = _PAPERS_DIR / f"{safe_id}.pdf"
    if pdf_path.exists():
        return pdf_path

    # Try with .pdf extension
    if not path_or_id.endswith(".pdf"):
        pdf_path = _PAPERS_DIR / f"{safe_id}.pdf"
        if pdf_path.exists():
            return pdf_path

    return None


class PaperReaderTool(Tool):
    """Read and extract text from downloaded PDF papers."""

    @property
    def name(self) -> str:
        return "paper_reader"

    @property
    def description(self) -> str:
        return (
            "Read PDF papers that have been downloaded. Actions:\n"
            "- read: Extract text from a paper (by path or paper ID)\n"
            "- list: List downloaded papers\n"
            "Tip: Use the 'browser' tool or rabbit-hole MCP to fetch PDFs first."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["read", "list"],
                    "description": "Action to perform.",
                },
                "paper": {
                    "type": "string",
                    "description": "Path to PDF or paper ID (for 'read').",
                },
                "pages": {
                    "type": "string",
                    "description": "Page range to extract, e.g. '1-5' or '1,3,5' (default: all).",
                },
            },
            "required": ["action"],
        }

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs["action"]

        if action == "list":
            return self._list_papers()

        if action == "read":
            paper = kwargs.get("paper", "")
            if not paper:
                return "Error: 'paper' is required (file path or paper ID)."

            pdf_path = _resolve_path(paper)
            if pdf_path is None:
                return f"Error: Paper not found: {paper}. Download the PDF first (browser or rabbit-hole MCP)."

            try:
                text = await asyncio.to_thread(
                    _extract_text, pdf_path, kwargs.get("pages")
                )
            except ImportError:
                return "Error: PyMuPDF (fitz) is not installed."
            except Exception as e:
                return f"Error reading PDF: {e}"

            if not text.strip():
                return "Warning: No text extracted (may be a scanned/image-only PDF)."

            # Truncate if very long
            if len(text) > 15000:
                text = text[:15000] + "\n\n[... truncated. Use 'pages' parameter to read specific sections.]"

            return text

        return f"Error: Unknown action '{action}'."

    def _list_papers(self) -> str:
        if not _PAPERS_DIR.exists():
            return "No papers downloaded yet."

        pdfs = sorted(_PAPERS_DIR.glob("*.pdf"))
        if not pdfs:
            return "No papers downloaded yet."

        lines = [f"**Downloaded papers ({len(pdfs)}):**"]
        for pdf in pdfs:
            size_mb = pdf.stat().st_size / (1024 * 1024)
            lines.append(f"- `{pdf.stem}` ({size_mb:.1f} MB)")
        return "\n".join(lines)
