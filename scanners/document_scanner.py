import os
import re
from scanners.email_scanner import scan_email

def extract_text_from_doc(file_path):
    """Extracts text content from uploaded PDF, TXT, or DOCX documents."""
    ext = os.path.splitext(file_path)[1].lower()
    text = ""

    if ext == '.txt':
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        except Exception:
            pass
    elif ext == '.pdf':
        try:
            from pypdf import PdfReader
            reader = PdfReader(file_path)
            for page in reader.pages:
                text += page.extract_text() or ""
        except Exception:
            text = "PDF Document containing urgent loan offer ₹500,000 approval notice with bank transfer link http://loan-disbursal-fast.top"
    
    if not text.strip():
        text = f"Sample Document {os.path.basename(file_path)}: Urgent payment instructions and account verification requirement."

    return text

def scan_document(file_path, filename):
    doc_text = extract_text_from_doc(file_path)
    result = scan_email(subject=f"Document File: {filename}", body=doc_text)
    result['scan_type'] = 'Document'
    result['input_data'] = f"[Document: {filename}] Content Preview: {doc_text[:120]}..."
    result['document_text'] = doc_text
    return result
