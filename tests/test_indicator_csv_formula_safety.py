"""The CSV indicator export neutralises spreadsheet formula injection.

An attribute value from MISP can start with a character a spreadsheet
treats as a formula (= + - @) or a control character. indicator_csv_text has to
prefix those with a single quote so a consumer opening the file in Excel or
LibreOffice gets literal text, while leaving ordinary values untouched.

    python -m unittest tests.test_indicator_csv_formula_safety
"""

import csv
import io
import unittest

from webapp import misp_store


def _rows_of(csv_text):
    return list(csv.reader(io.StringIO(csv_text)))


class CsvFormulaSafety(unittest.TestCase):
    def test_formula_leading_values_are_quoted(self):
        for payload in ('=1+1', '+1', '-1', '@SUM(A1)', '=cmd|calc'):
            with self.subTest(value=payload):
                out = misp_store.indicator_csv_text([{"value": payload}])
                cell = _rows_of(out)[1][misp_store.INDICATOR_FEED_COLUMNS.index(("value", "Value"))]
                self.assertEqual(cell, "'" + payload)

    def test_control_character_leading_values_are_quoted(self):
        for payload in ('\tTAB', '\rCR', '\nLF'):
            with self.subTest(value=repr(payload)):
                cell = misp_store._csv_safe(payload)
                self.assertEqual(cell, "'" + payload)

    def test_ordinary_values_are_unchanged(self):
        for payload in ('1.2.3.4', 'evil.example', 'http://x/y', 'a-b-c'):
            with self.subTest(value=payload):
                self.assertEqual(misp_store._csv_safe(payload), payload)

    def test_empty_and_none_are_safe(self):
        self.assertEqual(misp_store._csv_safe(""), "")
        self.assertEqual(misp_store._csv_safe(None), "")

    def test_header_row_is_not_quoted(self):
        out = misp_store.indicator_csv_text([])
        header = _rows_of(out)[0]
        self.assertEqual(header, [h for _, h in misp_store.INDICATOR_FEED_COLUMNS])


if __name__ == "__main__":
    unittest.main()
