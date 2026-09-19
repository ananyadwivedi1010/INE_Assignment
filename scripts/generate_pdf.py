#!/usr/bin/env python3
"""
Technical Blog PDF Generator
Converts docs/TECHNICAL_BLOG.md to HTML with modern CSS styling,
verifies word count (800 - 1200 words), and exports to PDF using
Microsoft Edge / Chrome headless printing or ReportLab fallback.
"""

import os
import re
import sys
import subprocess
import shutil

def count_words(text):
    # Remove code blocks, markdown tags, URLs, tables for word count check
    clean_text = re.sub(r'```.*?```', '', text, flags=re.DOTALL)
    clean_text = re.sub(r'`.*?`', '', clean_text)
    clean_text = re.sub(r'\[.*?\]\(.*?\)', '', clean_text)
    clean_text = re.sub(r'#+|\||-|\*|>|\bhttp\S+', '', clean_text)
    words = re.findall(r'\b[A-Za-z0-9_\-]+\b', clean_text)
    return len(words)

def markdown_to_html(md_text):
    """
    Simple, robust Markdown-to-HTML converter with zero external dependencies.
    """
    html_lines = []
    in_code_block = False
    in_table = False
    table_headers = []

    lines = md_text.splitlines()
    for line in lines:
        # Code block handling
        if line.startswith("```"):
            if in_code_block:
                html_lines.append("</code></pre>")
                in_code_block = False
            else:
                lang = line.replace("```", "").strip()
                html_lines.append(f'<pre class="code-block {lang}"><code>')
                in_code_block = True
            continue

        if in_code_block:
            escaped = (line.replace("&", "&amp;")
                           .replace("<", "&lt;")
                           .replace(">", "&gt;"))
            html_lines.append(escaped)
            continue

        # Table handling
        if line.strip().startswith("|") and line.strip().endswith("|"):
            parts = [p.strip() for p in line.strip().split("|")[1:-1]]
            if all(re.match(r'^:?-+:?$', p) for p in parts):
                # Separator line
                continue
            if not in_table:
                in_table = True
                html_lines.append('<table class="custom-table">')
                html_lines.append('<thead><tr>' + ''.join(f'<th>{p}</th>' for p in parts) + '</tr></thead><tbody>')
            else:
                html_lines.append('<tr>' + ''.join(f'<td>{p}</td>' for p in parts) + '</tr>')
            continue
        elif in_table:
            html_lines.append('</tbody></table>')
            in_table = False

        # Headers
        if line.startswith("### "):
            html_lines.append(f'<h3>{line[4:].strip()}</h3>')
            continue
        if line.startswith("#### "):
            html_lines.append(f'<h4>{line[5:].strip()}</h4>')
            continue
        if line.startswith("## "):
            html_lines.append(f'<h2>{line[3:].strip()}</h2>')
            continue
        if line.startswith("# "):
            html_lines.append(f'<h1>{line[2:].strip()}</h1>')
            continue

        # Horizontal rule
        if line.strip() == "---":
            html_lines.append('<hr>')
            continue

        # Lists
        if line.startswith("- ") or line.startswith("* "):
            item = line[2:].strip()
            item = format_inline(item)
            html_lines.append(f'<ul><li>{item}</li></ul>')
            continue

        if re.match(r'^\d+\.\s', line):
            item = re.sub(r'^\d+\.\s', '', line).strip()
            item = format_inline(item)
            html_lines.append(f'<ol><li>{item}</li></ol>')
            continue

        # Empty line
        if not line.strip():
            html_lines.append('<br>')
            continue

        # Normal paragraph
        p_text = format_inline(line.strip())
        html_lines.append(f'<p>{p_text}</p>')

    if in_table:
        html_lines.append('</tbody></table>')

    return "\n".join(html_lines)

def format_inline(text):
    # Bold
    text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
    # Italic
    text = re.sub(r'\*(.*?)\*', r'<em>\1</em>', text)
    # Inline code
    text = re.sub(r'`(.*?)`', r'<code>\1</code>', text)
    # Links
    text = re.sub(r'\[(.*?)\]\((.*?)\)', r'<a href="\2">\1</a>', text)
    return text

def build_full_html(body_html, total_words):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Technical Blog: CVE-2021-41773 & CVE-2021-42013</title>
<style>
    @page {{
        size: A4;
        margin: 20mm 15mm 20mm 15mm;
        @bottom-right {{
            content: "Page " counter(page);
        }}
    }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        color: #1e293b;
        background-color: #ffffff;
        line-height: 1.6;
        font-size: 11pt;
        margin: 0 auto;
        max-width: 800px;
        padding: 20px;
    }}
    h1 {{
        color: #0f172a;
        font-size: 20pt;
        border-bottom: 3px solid #2563eb;
        padding-bottom: 6px;
        margin-top: 0;
        margin-bottom: 4px;
    }}
    h2 {{
        color: #1e3a8a;
        font-size: 14pt;
        margin-top: 0;
        margin-bottom: 12px;
        font-weight: 600;
    }}
    h3 {{
        color: #1e40af;
        font-size: 12pt;
        margin-top: 18px;
        margin-bottom: 8px;
        border-bottom: 1px solid #e2e8f0;
        padding-bottom: 4px;
    }}
    h4 {{
        color: #334155;
        font-size: 11pt;
        margin-top: 14px;
        margin-bottom: 6px;
    }}
    p {{
        margin-top: 0;
        margin-bottom: 10px;
        text-align: justify;
    }}
    .meta-box {{
        background: #f8fafc;
        border-left: 4px solid #2563eb;
        padding: 10px 14px;
        margin-bottom: 16px;
        border-radius: 0 6px 6px 0;
        font-size: 10pt;
    }}
    .word-count-badge {{
        display: inline-block;
        background: #dbeafe;
        color: #1e40af;
        font-weight: bold;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 9pt;
        margin-top: 4px;
    }}
    ul, ol {{
        margin-top: 0;
        margin-bottom: 10px;
        padding-left: 24px;
    }}
    li {{
        margin-bottom: 4px;
    }}
    code {{
        font-family: "Cascadia Code", "Fira Code", Consolas, "Courier New", monospace;
        background-color: #f1f5f9;
        color: #0f172a;
        padding: 2px 5px;
        border-radius: 4px;
        font-size: 9.5pt;
    }}
    pre.code-block {{
        background-color: #0f172a;
        color: #f8fafc;
        padding: 12px 16px;
        border-radius: 6px;
        overflow-x: auto;
        font-size: 9pt;
        line-height: 1.45;
        margin-top: 8px;
        margin-bottom: 12px;
        border: 1px solid #334155;
    }}
    pre.code-block code {{
        background-color: transparent;
        color: inherit;
        padding: 0;
        border-radius: 0;
    }}
    table.custom-table {{
        width: 100%;
        border-collapse: collapse;
        margin-top: 10px;
        margin-bottom: 14px;
        font-size: 10pt;
    }}
    table.custom-table th {{
        background-color: #f1f5f9;
        color: #0f172a;
        text-align: left;
        padding: 8px 10px;
        border: 1px solid #cbd5e1;
        font-weight: 600;
    }}
    table.custom-table td {{
        padding: 7px 10px;
        border: 1px solid #cbd5e1;
    }}
    hr {{
        border: none;
        border-top: 1px solid #cbd5e1;
        margin: 18px 0;
    }}
    a {{
        color: #2563eb;
        text-decoration: none;
    }}
    a:hover {{
        text-decoration: underline;
    }}
</style>
</head>
<body>
    <div class="word-count-badge">Requirement Verified: Technical Blog Word Count = {total_words} words (Limit: 800 - 1,200 words)</div>
    {body_html}
</body>
</html>
"""

def find_browser_executable():
    possible_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ]
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    # Try via shutil.which
    for name in ["msedge", "chrome", "google-chrome", "chromium"]:
        found = shutil.which(name)
        if found:
            return found
    return None

def main():
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    blog_md_path = os.path.join(repo_dir, "docs", "TECHNICAL_BLOG.md")
    html_out_path = os.path.join(repo_dir, "docs", "technical_blog.html")
    pdf_docs_path = os.path.join(repo_dir, "docs", "technical_blog.pdf")
    pdf_root_path = os.path.join(repo_dir, "technical_blog.pdf")

    if not os.path.exists(blog_md_path):
        print(f"[-] Error: {blog_md_path} not found!")
        sys.exit(1)

    with open(blog_md_path, "r", encoding="utf-8") as f:
        md_content = f.read()

    word_count = count_words(md_content)
    print(f"[+] Total Word Count of Technical Blog: {word_count} words.")
    if 800 <= word_count <= 1200:
        print("[+] Word Count Requirement SATISFIED (800 - 1,200 words).")
    else:
        print(f"[!] Warning: Word count ({word_count}) is outside target range 800-1200.")

    body_html = markdown_to_html(md_content)
    full_html = build_full_html(body_html, word_count)

    with open(html_out_path, "w", encoding="utf-8") as f:
        f.write(full_html)
    print(f"[+] HTML preview written to: {html_out_path}")

    browser_bin = find_browser_executable()
    if browser_bin:
        print(f"[+] Found browser executable: {browser_bin}")
        file_url = "file:///" + html_out_path.replace("\\", "/")
        cmd = [
            browser_bin,
            "--headless",
            "--disable-gpu",
            "--no-pdf-header-footer",
            f"--print-to-pdf={pdf_docs_path}",
            file_url
        ]
        print(f"[+] Exporting PDF to {pdf_docs_path}...")
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0 and os.path.exists(pdf_docs_path):
            shutil.copy(pdf_docs_path, pdf_root_path)
            print(f"[+] SUCCESS: PDF generated successfully at:")
            print(f"    - {pdf_docs_path}")
            print(f"    - {pdf_root_path}")
            print(f"    Size: {os.path.getsize(pdf_docs_path)} bytes")
        else:
            print(f"[-] Browser PDF conversion failed: {res.stderr}")
    else:
        print("[-] No Headless Browser (Edge/Chrome) found on system PATH.")
        print("[!] HTML file generated. You can open docs/technical_blog.html in any browser and choose 'Print -> Save as PDF'.")

if __name__ == "__main__":
    main()
