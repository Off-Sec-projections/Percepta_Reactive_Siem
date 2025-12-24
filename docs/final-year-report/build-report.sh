#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIAGRAM_DIR="$SCRIPT_DIR/diagrams"
GENERATED_DIR="$SCRIPT_DIR/generated"
OUTPUT_DIR="$SCRIPT_DIR/output"
REPORT_MD="$SCRIPT_DIR/percepta-final-year-project-report.md"
PRESENTATION_MD="$SCRIPT_DIR/percepta-defense-presentation-outline.md"
DEFAULT_TEMPLATE="/home/rajputana/Downloads/Template - 05 - Project Report final (v2) (1).doc"
TEMPLATE_DOC="${1:-$DEFAULT_TEMPLATE}"
DOWNLOADS_REPORT="/home/rajputana/Downloads/Percepta Final Year Project Report.docx"
DOWNLOADS_PRESENTATION="/home/rajputana/Downloads/Percepta Defense Presentation Outline.docx"
USE_TEMPLATE_REFERENCE="${PERCEPTA_USE_TEMPLATE_REFERENCE:-0}"

mkdir -p "$GENERATED_DIR" "$OUTPUT_DIR"

for dot_file in "$DIAGRAM_DIR"/*.dot; do
  base_name="$(basename "${dot_file%.dot}")"
  dot -Tpng -Gdpi=220 "$dot_file" -o "$GENERATED_DIR/$base_name.png"
done

reference_args=()
if [[ "$USE_TEMPLATE_REFERENCE" == "1" && -f "$TEMPLATE_DOC" ]]; then
  soffice --headless --convert-to docx --outdir "$GENERATED_DIR" "$TEMPLATE_DOC" >/dev/null 2>&1 || true
  template_docx="$GENERATED_DIR/$(basename "${TEMPLATE_DOC%.doc}").docx"
  if [[ -f "$template_docx" ]]; then
    reference_args=("--reference-doc=$template_docx")
  fi
fi

pushd "$SCRIPT_DIR" >/dev/null

pandoc \
  "$REPORT_MD" \
  --from=markdown+implicit_figures+pipe_tables \
  --toc \
  --toc-depth=2 \
  --number-sections \
  --standalone \
  "${reference_args[@]}" \
  -o "$OUTPUT_DIR/Percepta-Final-Year-Project-Report.docx"

pandoc \
  "$REPORT_MD" \
  --from=markdown+implicit_figures+pipe_tables \
  --toc \
  --toc-depth=2 \
  --number-sections \
  --standalone \
  -o "$OUTPUT_DIR/Percepta-Final-Year-Project-Report.html"

pandoc \
  "$PRESENTATION_MD" \
  --from=markdown+pipe_tables \
  --standalone \
  "${reference_args[@]}" \
  -o "$OUTPUT_DIR/Percepta-Defense-Presentation-Outline.docx"

popd >/dev/null

cp -f "$OUTPUT_DIR/Percepta-Final-Year-Project-Report.docx" "$DOWNLOADS_REPORT"
cp -f "$OUTPUT_DIR/Percepta-Defense-Presentation-Outline.docx" "$DOWNLOADS_PRESENTATION"

printf 'Report generated at: %s\n' "$OUTPUT_DIR/Percepta-Final-Year-Project-Report.docx"
printf 'Presentation outline generated at: %s\n' "$OUTPUT_DIR/Percepta-Defense-Presentation-Outline.docx"
printf 'Copied report to: %s\n' "$DOWNLOADS_REPORT"
printf 'Copied presentation outline to: %s\n' "$DOWNLOADS_PRESENTATION"