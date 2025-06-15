import os
import json
import uuid
import io
from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app, send_file
from werkzeug.utils import secure_filename
from .forms import UploadForm, IPCheckForm, URLCheckForm

main_routes = Blueprint('main', __name__)

def get_report_path(report_id):
    return os.path.join(current_app.config['REPORT_FOLDER'], f"{report_id}.json")

@main_routes.route('/')
def home():
    return render_template('index.html')

def load_report(report_id):
    try:
        with open(get_report_path(report_id), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

@main_routes.route('/filechecker')
def filechecker():
    form = UploadForm()
    form.checker_name.data = "filechecker"
    report = None
    report_id = request.args.get('report_id')
    if report_id:
        report = load_report(report_id)
        if not report:
            flash("Could not load report from file.")
    return render_template('checkers/filechecker.html', form=form, report=report, report_id=report_id)

@main_routes.route('/pechecker')
def pechecker():
    form = UploadForm()
    form.checker_name.data = "pechecker"
    report = None
    report_id = request.args.get('report_id')
    if report_id:
        report = load_report(report_id)
        if not report:
            flash("Could not load report from file.")
    return render_template('checkers/pechecker.html', form=form, report=report, report_id=report_id)

@main_routes.route('/yarachecker')
def yarachecker():
    form = UploadForm()
    form.checker_name.data = "yarachecker"
    report = None
    report_id = request.args.get('report_id')
    if report_id:
        report = load_report(report_id)
        if not report:
            flash("Could not load report from file.")
    return render_template('checkers/yarachecker.html', form=form, report=report, report_id=report_id)

@main_routes.route('/getstrings')
def getstrings():
    form = UploadForm()
    form.checker_name.data = "getstrings"
    report = None
    report_id = request.args.get('report_id')
    if report_id:
        report = load_report(report_id)
        if not report:
            flash("Could not load report from file.")
    return render_template('checkers/getstrings.html', form=form, report=report, report_id=report_id)

@main_routes.route('/upload', methods=['GET', 'POST'])
def upload_file():
    UPLOAD_FOLDER = current_app.config['UPLOAD_FOLDER']
    REPORT_FOLDER = current_app.config['REPORT_FOLDER']
    form = UploadForm()
    if form.validate_on_submit():
        file = form.file.data
        if file:
            filename = secure_filename(file.filename)
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)

            report_id = str(uuid.uuid4())
            os.makedirs(REPORT_FOLDER, exist_ok=True)

            try:
                if form.checker_name.data == 'pechecker':
                    from app import PEChecker
                    report = PEChecker(file_path)
                    report['file_name'] = filename
                elif form.checker_name.data == 'filechecker':
                    from app import FileChecker
                    report = FileChecker(file_path)
                elif form.checker_name.data == 'yarachecker':
                    from app import YARA
                    report = YARA(file_path)
                    report['file_name'] = filename
                elif form.checker_name.data == 'getstrings':
                    from app import GetStrings
                    report = GetStrings(file_path)
                    report['file_name'] = filename
                    print(report)
                elif form.checker_name.data == 'dynamic':
                    from app import DynamicAnalysis
                    report = DynamicAnalysis(file_path)
                    report['file_name'] = filename
                else:
                    flash('Unknown checker type')
                    return redirect(url_for('main.home'))
                    
                # Save report to file
                with open(get_report_path(report_id), 'w', encoding='utf-8') as f:
                    json.dump(report, f)

                # Redirect to checker page with report ID
                return redirect(url_for(f'main.{form.checker_name.data}', report_id=report_id))

            except Exception as e:
                flash(f'Error checking file: {e}')
                return redirect(url_for('main.upload_file'))
        else:
            flash('File type not allowed')
            return redirect(request.url)

    # GET or failed POST, just render empty checker
    checker = form.checker_name.data or request.form.get("checker_name")
    return render_template(f'checkers/{checker}.html', form=form)

@main_routes.route('/ipchecker', methods=['GET', 'POST'])
def ipchecker():
    form = IPCheckForm()
    result = None
    report_id = request.args.get('report_id')
    if request.method == "POST" and form.validate_on_submit():
        ip = form.ip.data
        try:
            from app import IPChecker
            result = IPChecker(ip)
            if isinstance(result, str):
                result = json.loads(result)
            report_id = str(uuid.uuid4())
            with open(get_report_path(report_id), "w", encoding="utf-8") as f:
                json.dump(result, f)
            return redirect(url_for('main.ipchecker', report_id=report_id))
        except Exception:
            result = {"error": f"Could not check IP: {ip}"}
    elif report_id:
        result = load_report(report_id)
        if not result:
            flash("Could not load report from file.")
    return render_template('checkers/ipchecker.html', form=form, result=result, report_id=report_id)

@main_routes.route('/urlchecker', methods=['GET', 'POST'])
def urlchecker():
    form = URLCheckForm()
    result = None
    report_id = request.args.get('report_id')
    if request.method == "POST" and form.validate_on_submit():
        url = form.url.data
        try:
            from app import URLChecker
            result = URLChecker(url)
            if isinstance(result, str):
                result = json.loads(result)
            report_id = str(uuid.uuid4())
            with open(get_report_path(report_id), "w", encoding="utf-8") as f:
                json.dump(result, f)
            return redirect(url_for('main.urlchecker', report_id=report_id))
        except Exception:
            result = {"error": f"Could not check URL: {url}"}
    elif report_id:
        result = load_report(report_id)
        if not result:
            flash("Could not load report from file.")
    return render_template('checkers/urlchecker.html', form=form, result=result, report_id=report_id)

from xhtml2pdf import pisa  # Make sure xhtml2pdf is installed

def render_pdf(template_name, context):
    html = render_template(template_name, **context)
    pdf = io.BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=pdf)
    pdf.seek(0)
    return pdf if not pisa_status.err else None

@main_routes.route('/download_report/<checker>/<report_id>')
def download_report(checker, report_id):
    checker_map = {
        'filechecker': 'checkers/filechecker_pdf.html',
        'pechecker':   'checkers/pechecker_pdf.html',
        'yarachecker': 'checkers/yarachecker_pdf.html',
        'ipchecker':   'checkers/ipchecker_pdf.html',
        'urlchecker':  'checkers/urlchecker_pdf.html',
        'getstrings':  'checkers/getstrings_pdf.html',
    }
    if checker not in checker_map:
        flash('Invalid report type')
        return redirect(url_for('main.home'))

    report = load_report(report_id)
    if not report:
        flash('No report found with that ID')
        return redirect(url_for(f'main.{checker}'))

    # Prepare context for the PDF template
    context = {'report': report}
    pdf_template = checker_map[checker]
    pdf = render_pdf(pdf_template, context)
    if pdf:
        return send_file(
            pdf,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"{checker}_report_{report_id}.pdf"
        )
    else:
        flash('Failed to generate PDF')
        return redirect(url_for(f'main.{checker}', report_id=report_id))