"""PDF Report Generator using fpdf2 with Arabic (RTL) support."""
import os
import re
import time
from fpdf import FPDF

REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORT_DIR, exist_ok=True)

# Arabic Unicode ranges (script characters only)
_ARABIC_RE = re.compile(r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]")


def _has_arabic(text: str) -> bool:
    """Check if text contains Arabic script characters."""
    return bool(_ARABIC_RE.search(text))


def _reshape_arabic(text: str) -> str:
    """Reshape and reorder Arabic text for correct visual rendering.

    Uses arabic_reshaper + python-bidi libraries when available.
    Falls back to simple reversal for basic RTL support.
    """
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
        return get_display(arabic_reshaper.reshape(text))
    except ImportError:
        # Fallback: reverse characters (imperfect but allows basic RTL flow)
        return text[::-1]


class AuditPDF(FPDF):
    """PDF report generator with Arabic (RTL) text support.

    Uses DejaVu Sans for Unicode/Arabic rendering with optional
    arabic_reshaper + python-bidi for proper character shaping.
    """

    def __init__(self):
        super().__init__()
        self.unicode_font = self._register_unicode_font()

    def _register_unicode_font(self) -> str:
        """Register a Unicode font that supports Arabic and return family name.

        Searches common OS paths and a local fonts/ directory.
        Falls back to 'Helvetica' if no suitable font is found.
        """
        search_dirs = [
            os.path.join(os.path.dirname(__file__), "fonts"),
            r"C:\Windows\Fonts",
            "/usr/share/fonts/truetype/dejavu",
            "/usr/share/fonts",
            "/System/Library/Fonts",
            os.path.expanduser("~/.fonts"),
        ]
        variants = [
            ("DejaVuSans.ttf", ""),
            ("DejaVuSans-Bold.ttf", "B"),
        ]
        registered = False
        for d in search_dirs:
            for fname, style in variants:
                path = os.path.join(d, fname)
                if os.path.isfile(path):
                    try:
                        self.add_font("DejaVu", style, path, uni=True)
                        registered = True
                    except Exception:
                        pass
        return "DejaVu" if registered else "Helvetica"

    def set_unicode_font(self, style: str = "", size: float = 10):
        """Set the current font to the Unicode font or nearest fallback."""
        try:
            self.set_font(self.unicode_font, style, size)
        except Exception:
            # Fallback chain
            for fallback in ("Helvetica", "Courier"):
                try:
                    self.set_font(fallback, style, size)
                    break
                except Exception:
                    continue

    def arabic_text(self, text: str) -> str:
        """Prepare Arabic text for PDF rendering (shaping + RTL reordering).

        Only applies transformation to text that contains Arabic characters.
        """
        if not text or not _has_arabic(text):
            return text
        return _reshape_arabic(text)

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(88, 166, 255)
        self.cell(0, 8, "Smart Contract Auditor", align="C", new_x="LMARGIN", new_y="NEXT")
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(140, 150, 160)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def section(self, title):
        self.set_unicode_font("B", 13)
        self.set_text_color(88, 166, 255)
        display = self.arabic_text(title) if _has_arabic(title) else title
        self.cell(0, 10, display, new_x="LMARGIN", new_y="NEXT")
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def add_arabic_section(self, title: str, body: str):
        """Add a content section with Arabic (RTL) text rendering."""
        self.section(title)
        self.set_unicode_font("", 9)
        self.set_text_color(200, 210, 220)
        self.multi_cell(0, 5, self.arabic_text(body))
        self.ln(3)

    def severity_box(self, severity):
        colors = {
            "CRITICAL": (218, 54, 51), "HIGH": (210, 153, 34),
            "MEDIUM": (88, 166, 255), "LOW": (140, 150, 160),
            "INFO": (35, 134, 54),
        }
        c = colors.get(severity.upper(), (200, 200, 200))
        self.set_fill_color(*c)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 8)
        w = self.get_string_width(severity.upper()) + 6
        self.cell(w, 6, severity.upper(), fill=True)
        self.ln(8)

    def code_block(self, text):
        self.set_font("Courier", "", 7)
        self.set_fill_color(13, 17, 23)
        self.set_text_color(200, 210, 220)
        self.multi_cell(0, 3.5, text[:2000], fill=True)
        self.ln(3)


def generate_pdf_report(report_text: str, label: str = "report") -> str:
    """Generate a PDF file from a textual report with Arabic support."""
    pdf = AuditPDF()
    pdf.alias_nb_pages()
    pdf.add_page()

    # Title
    pdf.set_unicode_font("B", 20)
    pdf.set_text_color(88, 166, 255)
    title_text = "Smart Contract Audit Report"
    if _has_arabic(report_text):
        title_text = pdf.arabic_text(title_text)
    pdf.cell(0, 15, title_text, align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Meta info
    pdf.set_unicode_font("", 9)
    pdf.set_text_color(140, 150, 160)
    pdf.cell(0, 6, f"Contract: {label}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Parse report text into sections
    lines = report_text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue

        is_arabic = _has_arabic(line)

        # Headings
        if line.startswith("#"):
            level = line.count("#")
            title = line.lstrip("#").strip()
            if level <= 2:
                pdf.section(title)
            else:
                pdf.set_unicode_font("B", 10)
                pdf.set_text_color(200, 210, 220)
                if is_arabic:
                    title = pdf.arabic_text(title)
                pdf.cell(0, 7, title, new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)
            i += 1
            continue

        # Severity markers
        if any(s in line.upper() for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if s in line.upper():
                    pdf.severity_box(s)
                    break
            pdf.set_unicode_font("", 9)
            pdf.set_text_color(200, 210, 220)
            if is_arabic:
                line = pdf.arabic_text(line)
            pdf.multi_cell(0, 5, line[:200])
            pdf.ln(2)
            i += 1
            continue

        # Code blocks
        if line.startswith("`"):
            code_lines = []
            while i < len(lines) and (lines[i].strip().startswith("`") or lines[i].strip()):
                code_lines.append(lines[i])
                i += 1
                if len(code_lines) > 20:
                    break
            pdf.code_block("\n".join(code_lines))
            continue

        # Normal text
        pdf.set_unicode_font("", 9)
        pdf.set_text_color(200, 210, 220)
        if is_arabic:
            line = pdf.arabic_text(line)
        pdf.multi_cell(0, 5, line[:300])
        pdf.ln(1)
        i += 1

    filename = f"{label}_{int(time.time())}.pdf"
    path = os.path.join(REPORT_DIR, filename)
    pdf.output(path)
    return path
