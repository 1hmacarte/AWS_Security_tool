from datetime import datetime
from pathlib import Path
import webbrowser

from jinja2 import Environment, FileSystemLoader, select_autoescape


BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
OUTPUT_FILE = BASE_DIR.parent / "aws_security_dashboard.html"


def generate_html_template(results):
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = environment.get_template("aws_security_dashboard.html")
    return template.render(
        assessment_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        results=results,
    )


def save_report(html_content, output_path=OUTPUT_FILE):
    output_path = Path(output_path)
    output_path.write_text(html_content, encoding="utf-8")
    return output_path


def open_in_browser(html_file):
    webbrowser.open_new_tab(Path(html_file).resolve().as_uri())