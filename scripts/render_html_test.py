from sat.utils.html_renderer import render_html_report

out = render_html_report(
    final_report_json="reports/final_report_mock.json",
    template_path="reports/report_template.html",
    output_html="reports/report_mock.html",
)

print(f"OK: {out}")
