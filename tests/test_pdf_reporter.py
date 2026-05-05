"""Tests for PDF reporter (via mock to avoid reportlab dependency)."""

import sys
from unittest.mock import MagicMock, patch

import pytest

from core.report_generator import ScanResult


class TestPDFReporter:
    def test_import_error_when_reportlab_missing(self):
        """Verify PDF generation raises ImportError when reportlab not available."""
        with patch.dict(sys.modules, {"reportlab": None}):
            with pytest.raises(ImportError, match="reportlab"):
                from core.pdf_reporter import generate_pdf
                generate_pdf([])

    def test_pdf_with_reportlab_mocked(self, tmp_path):
        """Test PDF generation with mocked reportlab."""
        mock_doc = MagicMock()
        mock_para = MagicMock()
        mock_table = MagicMock()
        mock_spacer = MagicMock()

        mock_mod = MagicMock()
        mock_mod.lib.pagesizes.A4 = (595, 842)
        mock_mod.lib.units.inch = 72
        mock_mod.lib.colors.HexColor = MagicMock(return_value=MagicMock())
        mock_mod.lib.styles.getSampleStyleSheet.return_value = {
            "Title": MagicMock(),
            "Normal": MagicMock(),
            "Heading2": MagicMock(),
            "Italic": MagicMock(),
        }
        mock_mod.lib.styles.ParagraphStyle = MagicMock(return_value=MagicMock())
        mock_mod.platypus.SimpleDocTemplate = MagicMock(return_value=mock_doc)
        mock_mod.platypus.Paragraph = MagicMock(return_value=mock_para)
        mock_mod.platypus.Spacer = MagicMock(return_value=mock_spacer)
        mock_mod.platypus.Table = MagicMock(return_value=mock_table)
        mock_mod.platypus.TableStyle = MagicMock(return_value=MagicMock())

        with patch.dict(sys.modules, {"reportlab": mock_mod}):
            with patch.dict(sys.modules, {"reportlab.lib": mock_mod.lib}):
                with patch.dict(sys.modules, {"reportlab.lib.pagesizes": mock_mod.lib.pagesizes}):
                    with patch.dict(sys.modules, {"reportlab.lib.styles": mock_mod.lib.styles}):
                        with patch.dict(sys.modules, {"reportlab.lib.units": mock_mod.lib.units}):
                            with patch.dict(sys.modules, {"reportlab.lib.colors": mock_mod.lib.colors}):
                                with patch.dict(sys.modules, {"reportlab.platypus": mock_mod.platypus}):
                                    from core.pdf_reporter import generate_pdf

                                    results = [
                                        ScanResult(
                                            file_path="/test/a.exe",
                                            verdict="wannacry",
                                            ml_score=0.95,
                                            yara_matches=["WannaCry_Mutex"],
                                        ),
                                        ScanResult(
                                            file_path="/test/b.exe",
                                            verdict="benign",
                                            ml_score=0.1,
                                        ),
                                    ]

                                    output = tmp_path / "report.pdf"
                                    generate_pdf(results, output_path=output)
                                    mock_doc.build.assert_called_once()
