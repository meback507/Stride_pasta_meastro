import os
import io
import json
from typing import Dict, Any, Optional

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

try:
    import docx
except ImportError:
    docx = None

try:
    import openpyxl
except ImportError:
    openpyxl = None

try:
    import pptx
except ImportError:
    pptx = None


class DocumentService:
    """Extracts text and architecture metadata from uploaded project files."""

    @staticmethod
    def extract_text_from_file(file_path: str, file_type: str) -> str:
        if not os.path.exists(file_path):
            return ""

        file_ext = os.path.splitext(file_path)[1].lower().replace(".", "")
        effective_type = file_type.lower() or file_ext

        try:
            # 1. Plain text, markdown, csv, json
            if effective_type in ["txt", "md", "markdown", "csv", "json", "yaml", "yml"]:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()

            # 2. PDF via PyMuPDF
            elif effective_type == "pdf" and fitz:
                doc = fitz.open(file_path)
                text_chunks = []
                for page_num in range(len(doc)):
                    page = doc[page_num]
                    text = page.get_text()
                    if text.strip():
                        text_chunks.append(f"--- [Page {page_num + 1}] ---\n{text.strip()}")
                return "\n\n".join(text_chunks)

            # 3. DOCX via python-docx
            elif effective_type in ["docx", "doc"] and docx:
                doc = docx.Document(file_path)
                paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
                # Also extract tables
                tables_text = []
                for table in doc.tables:
                    for row in table.rows:
                        row_cells = [cell.text.strip() for cell in row.cells if cell.text.strip()]
                        if row_cells:
                            tables_text.append(" | ".join(row_cells))
                full_text = "\n".join(paragraphs)
                if tables_text:
                    full_text += "\n\n[Extracted Tables]:\n" + "\n".join(tables_text)
                return full_text

            # 4. XLSX via openpyxl
            elif effective_type in ["xlsx", "xls"] and openpyxl:
                wb = openpyxl.load_workbook(file_path, data_only=True)
                sheets_text = []
                for sheet in wb.sheetnames:
                    ws = wb[sheet]
                    sheet_rows = []
                    for row in ws.iter_rows(values_only=True):
                        non_empty = [str(val) for val in row if val is not None]
                        if non_empty:
                            sheet_rows.append(" | ".join(non_empty))
                    if sheet_rows:
                        sheets_text.append(f"--- [Sheet: {sheet}] ---\n" + "\n".join(sheet_rows[:200])) # limit 200 rows per sheet
                return "\n\n".join(sheets_text)

            # 5. PPTX via python-pptx
            elif effective_type in ["pptx", "ppt"] and pptx:
                prs = pptx.Presentation(file_path)
                slides_text = []
                for idx, slide in enumerate(prs.slides):
                    slide_elements = []
                    for shape in slide.shapes:
                        if hasattr(shape, "text") and shape.text.strip():
                            slide_elements.append(shape.text.strip())
                    if slide_elements:
                        slides_text.append(f"--- [Slide {idx + 1}] ---\n" + "\n".join(slide_elements))
                return "\n\n".join(slides_text)

            # 6. Images / Diagrams
            elif effective_type in ["png", "jpg", "jpeg", "svg"]:
                return f"[Image/Diagram Architecture Asset: {os.path.basename(file_path)}. Visual inspection / OCR attached]."

            else:
                # Fallback: try raw utf-8 read
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read(50000)

        except Exception as e:
            return f"[Error parsing document {os.path.basename(file_path)}: {str(e)}]"

    @staticmethod
    def sanitize_untrusted_context(raw_text: str, max_chars: int = 40000) -> str:
        """Sanitizes context from untrusted uploads to avoid prompt injection."""
        if not raw_text:
            return ""

        # Guard against meta-prompt injection delimiters
        sanitized = raw_text.replace("</untrusted_architecture_context>", "[REDACTED_DELIMITER]")
        
        # Truncate if exceeds token safe budget
        if len(sanitized) > max_chars:
            sanitized = sanitized[:max_chars] + f"\n... [Context truncated at {max_chars} characters for token safety] ..."
            
        return sanitized
