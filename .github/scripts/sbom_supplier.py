"""Name cudeso.be as the supplier of a CycloneDX 1.4 XML SBOM, then validate it.

The NTIA minimum elements ask for the supplier, and neither cyclonedx-py nor
cyclonedx-cli's merge writes one. Used by release.yml on zsazsa's own SBOM and
on the deployment SBOM.

    python .github/scripts/sbom_supplier.py zsazsa-v1.0.8.cdx.xml
"""

import sys
import xml.etree.ElementTree as ET

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.xml import XmlValidator

NS = "{http://cyclonedx.org/schema/bom/1.4}"

path = sys.argv[1]
ET.register_namespace("", NS.strip("{}"))
tree = ET.parse(path)
metadata = tree.getroot().find(NS + "metadata")
supplier = ET.Element(NS + "supplier")
ET.SubElement(supplier, NS + "name").text = "cudeso.be"
# The schema fixes the order: the supplier comes after the component.
metadata.insert(list(metadata).index(metadata.find(NS + "component")) + 1, supplier)
ET.indent(tree, space="  ")
tree.write(path, xml_declaration=True, encoding="utf-8")

error = XmlValidator(SchemaVersion.V1_4).validate_str(open(path).read())
if error:
    sys.exit(f"{path} does not validate: {error}")
