import json
import os
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape  # pyre-ignore
from fpdf import FPDF  # pyre-ignore
from fpdf.enums import XPos, YPos  # pyre-ignore

from config import REPORT_DIR  # pyre-ignore

JSON_DIR = REPORT_DIR / 'json'
HTML_DIR = REPORT_DIR / 'html'
PDF_DIR  = REPORT_DIR / 'pdf'
for d in [JSON_DIR, HTML_DIR, PDF_DIR]:
    d.mkdir(parents=True, exist_ok=True)


class RedSimPDF(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 15)
        self.set_fill_color(220, 220, 220)
        self.cell(0, 10, 'RedSim Simulation Report', border=0, align='C', fill=True,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()} / {{nb}}', align='C')


def build_metadata(results):
    mitre = results.get('mitre_summary', [])
    recs = []
    if any('T1110' in t or 'T1078' in t for t in mitre):
        recs.append('Credential Access: Enforce MFA, monitor lockout frequency, isolate PAM.')
    if any('T1041' in t or 'T1567' in t for t in mitre):
        recs.append('Exfiltration: Deploy endpoint DLP, restrict arbitrary archiver invocations.')
    if any('T1059' in t or 'T1047' in t for t in mitre):
        recs.append('Execution: Constrain PowerShell via AMSI, enable constrained language mode.')
    if not recs:
        recs.append('Review SIEM alerts matching generated MITRE TTPs.')
    return {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'category': results.get('category', 'Threat Emulation'),
        'attacker_profile': results.get('attacker_profile', 'APT (Simulated)'),
        'complexity': results.get('complexity', 'Medium'),
        'defensive_value': 'High',
        'recommendations': ' | '.join(recs),
        'detection_summary': f"Executed {len(results.get('steps',[]))} anomalies, {len(mitre)} TTPs mapped."
    }


def generate_json_report(results, metadata, filepath, logger):
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump({'metadata': metadata, 'results': results}, f, indent=4)
    return filepath


def generate_html_report(results, metadata, filepath, logger):
    env = Environment(loader=FileSystemLoader(str(REPORT_DIR)),
                      autoescape=select_autoescape(['html', 'xml']))
    try:
        template = env.get_template('template.html')
    except Exception as e:
        logger.error(f'HTML template error: {e}'); return None
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(template.render(results=results, metadata=metadata))
    return filepath


def generate_pdf_report(results, metadata, filepath, logger):
    pdf = RedSimPDF()
    pdf.add_page()
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 8, f"Scenario: {results.get('scenario','Unknown')}",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font('helvetica', size=11)
    pdf.cell(0, 8, f"Generated: {metadata['timestamp']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 8, f"Status: {results.get('status','?').upper()}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 8, f"Profile: {metadata['attacker_profile']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 8, 'Execution Summary:', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font('helvetica', size=10)
    steps = results.get('steps', [])
    pdf.cell(0, 6, f"Total Steps: {len(steps)} ({results.get('successful_steps',0)} ok / {results.get('failed_steps',0)} fail)",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"Success Rate: {results.get('success_rate',0)}%", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"Risk Score: {results.get('risk_score',0)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)
    for i, step in enumerate(steps):
        pdf.set_font('helvetica', 'B', 10)
        pdf.cell(0, 6, f"[{i+1}] {step.get('module','?')} | MITRE: {step.get('mitre','?')}",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font('helvetica', size=10)
        pdf.multi_cell(0, 6, f"Status: {step.get('status','?').upper()} | {step.get('summary','')}",
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)
    pdf.ln(5)
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 8, 'Recommendations:', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font('helvetica', size=10)
    pdf.multi_cell(0, 6, metadata['recommendations'], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    try:
        pdf.output(str(filepath))
    except Exception as e:
        logger.error(f'PDF generation failed: {e}'); return None
    return filepath


def generate_report(results, report_formats, logger):
    logger.info('Initializing Report Engine...')
    name = results.get('scenario', 'unknown').replace(' ', '_').lower()
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    base = f'{name}_{ts}'
    meta = build_metadata(results)
    done = []
    for fmt in report_formats:
        if fmt.lower() == 'json':
            if generate_json_report(results, meta, JSON_DIR/f'{base}.json', logger): done.append('json')
        elif fmt.lower() == 'html':
            if generate_html_report(results, meta, HTML_DIR/f'{base}.html', logger): done.append('html')
        elif fmt.lower() == 'pdf':
            if generate_pdf_report(results, meta, PDF_DIR/f'{base}.pdf', logger): done.append('pdf')
    logger.info(f'Reports generated: {", ".join(done)}')
    return done
