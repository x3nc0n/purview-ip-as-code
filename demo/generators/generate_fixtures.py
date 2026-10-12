#!/usr/bin/env python3
"""Generate fictional BCSI/PII fixtures and a manifest; no live data is read."""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[2]
CONTENT = ROOT / "demo" / "content" / "generated"
MANIFEST = ROOT / "demo" / "manifests" / "fixtures.json"
SSN = "123-45-6789"


def write_docx(destination: Path, body: str) -> None:
    paragraphs = "".join(
        f"<w:p><w:r><w:t xml:space=\"preserve\">{escape(line)}</w:t></w:r></w:p>"
        for line in body.splitlines()
    )
    document = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>{paragraphs}<w:sectPr/></w:body>
</w:document>"""
    content_types = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""
    relationships = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", relationships)
        archive.writestr("word/document.xml", document)


def write_pdf(destination: Path, body: str) -> None:
    lines = [re.sub(r"[^\x20-\x7e]", "?", line) for line in body.splitlines()]
    commands = ["BT", "/F1 10 Tf", "50 760 Td", "14 TL"]
    for index, line in enumerate(lines[:48]):
        escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        if index:
            commands.append("T*")
        commands.append(f"({escaped}) Tj")
    commands.append("ET")
    stream = "\n".join(commands).encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii") + obj + b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
    )
    destination.write_bytes(output)


def main() -> None:
    CONTENT.mkdir(parents=True, exist_ok=True)
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    fixtures: list[dict[str, object]] = []

    def add(
        fixture_id: str,
        body: str,
        expected_label: str,
        ssn_occurrences: int = 0,
        workload: str = "SharePoint",
        detector: str | None = None,
        formats: list[str] | None = None,
    ) -> None:
        text_name = f"{fixture_id}.txt"
        text_path = CONTENT / text_name
        text_path.write_text(body, encoding="utf-8", newline="\n")
        entry: dict[str, object] = {
            "id": fixture_id,
            "extractedTextPath": f"demo/content/generated/{text_name}",
            "expectedDetectionType": detector or ("us-ssn" if ssn_occurrences else None),
            "expectedConfidence": 85 if detector else None,
            "expectedSsnOccurrences": ssn_occurrences,
            "expectedLabel": expected_label,
            "workload": workload,
            "expectedProtection": {
                "status": "expected-only-not-observed",
                "preserveManualLabels": True,
            },
            "observedPurviewCount": None,
            "liveValidationStatus": "not-run",
            "syntheticOnly": True,
            "formats": formats or ["text"],
        }
        if formats and "docx" in formats:
            docx_name = f"{fixture_id}.docx"
            write_docx(CONTENT / docx_name, body)
            entry["docxPath"] = f"demo/content/generated/{docx_name}"
        if formats and "pdf" in formats:
            pdf_name = f"{fixture_id}.pdf"
            write_pdf(CONTENT / pdf_name, body)
            entry["pdfPath"] = f"demo/content/generated/{pdf_name}"
        fixtures.append(entry)

    add(
        "bcsi-explicit",
        "BCSI: INTERNAL DEMO DESIGNATION\n"
        "Handling: BES Cyber System Information\n"
        "Facility: Fictional Northwind-7 training station.\n"
        "This is synthetic, inert training content. No real system or facility is described.",
        "highly-confidential-bes",
        detector="bcsi-explicit-designation",
        formats=["text", "docx", "pdf"],
    )
    add(
        "bcsi-network",
        "Synthetic lab topology note.\n"
        "BES enclave firewall subnet 192.0.2.14 uses a documented deny rule for the test VLAN.\n"
        "Ingress and egress behavior is invented and is not operational guidance.",
        "highly-confidential-bes",
        detector="bcsi-network-security",
        formats=["text", "docx", "pdf"],
    )
    add(
        "bcsi-access",
        "Operator access procedure for fictional BES training station.\n"
        "A test badge and MFA are reviewed by a second fictional approver; access is audited.\n"
        "No credential, endpoint, or real procedure is included.",
        "highly-confidential-bes",
        detector="bcsi-access-procedures",
        formats=["text", "docx", "pdf"],
    )
    add(
        "control-public-standard",
        "A public training note quotes the phrase BES Cyber System Information from a public standard.\n"
        "No internal BCSI designation, system context, or operational details are present.",
        "none",
    )
    add("control-isolated-address", "An isolated documentation address is 192.0.2.44.", "none")
    add("control-generic-scada", "Generic SCADA concepts are discussed with no BES or security context.", "none")
    add(
        "control-generic-credential",
        "A fictional help desk example says username and password without any BES context.",
        "none",
    )
    add(
        "control-quoted-designation",
        "Quoted public text: \"BCSI: INTERNAL DEMO DESIGNATION\" is shown as a string parser example.\n"
        "This fixture tests a known limitation; regex logic cannot determine quotation, publication, or applicability.",
        "highly-confidential-bes",
        detector="bcsi-explicit-designation",
    )

    for count in (0, 1, 198, 199, 200, 201, 250):
        body = (
            "Synthetic identifier count demonstration. Repeated values are deliberate and do not represent unique people.\n"
            + "\n".join([SSN] * count)
            + ("\nInvalid negative-control value: 000-00-0000." if count == 0 else "")
        )
        label = "none" if count == 0 else (
            "confidential-internal" if count < 200 else "highly-confidential-internal"
        )
        add(
            f"pii-spo-{count}",
            body,
            label,
            ssn_occurrences=count,
            formats=["text", "docx", "pdf"] if count in (1, 200) else None,
        )

    add(
        "pii-exchange-200",
        "\n".join([SSN] * 200),
        "highly-confidential-recipients",
        ssn_occurrences=200,
        workload="Exchange",
    )
    add(
        "mixed-pii-199-bcsi",
        "BCSI: INTERNAL DEMO DESIGNATION\n"
        "Synthetic training item combines independent conditions.\n"
        + "\n".join([SSN] * 199),
        "highly-confidential-bes",
        ssn_occurrences=199,
        detector="bcsi-explicit-designation",
    )
    add(
        "mixed-pii-200-bcsi",
        "BCSI: INTERNAL DEMO DESIGNATION\n"
        "Synthetic training item combines independent conditions.\n"
        + "\n".join([SSN] * 200),
        "highly-confidential-bes",
        ssn_occurrences=200,
        detector="bcsi-explicit-designation",
    )

    manifest = {
        "generatorVersion": "1.0.0",
        "syntheticOnly": True,
        "identifierFixture": SSN,
        "identifierWarning": (
            "This conventional example is synthetic and is not associated with a person. "
            "A plausible SSN-format value cannot be guaranteed never to have been issued. "
            "Live detector results must be observed in the target tenant."
        ),
        "countSemantics": "Occurrences in one item; repeated values are not unique people.",
        "fixtures": fixtures,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Generated {len(fixtures)} synthetic fixtures in {CONTENT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
