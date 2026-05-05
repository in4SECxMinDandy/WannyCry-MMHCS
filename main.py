#!/usr/bin/env python3
"""WannaCry Detector Lite — Main entry point.

Provides CLI and GUI launcher for the WannaCry detection tool.

Usage:
    python main.py --scan /path/to/target
    python main.py --gui
    python main.py --scan /path --report-format csv,json,pdf
"""

import argparse
import sys
from pathlib import Path

from core.config_manager import load_config
from core.logger_setup import enable_debug, get_logger, setup_logging
from core.report_generator import ReportGenerator
from core.scanner import Scanner

logger = get_logger(__name__)

BANNER = r"""
__        __   _   _   _   _   _    ___  ____  __   ____  ___  ___    ___  ___
 \ \    / /_\ | \ | | / \ | \ | |  / __\/  _ \/ _\ /  _ \/   \/   \  / _ \/  _\
  \ \/\/ //_ \|  \| || | \|  \| |  | (// | / \|| /  | | /| - || - | | / \|| | /
   \_/\_/|_||_|_|\__||_|_/|_|\__|  \___\|_/|_|\_|  |_|_\|_|_||_|_| |_|_|\|_|\_
                                                          ___  _  _____
                                                         /   \| ||_   _|
                                                         | - |\ || ||
                                                         |_|_||_| ||_|
"""

DISCLAIMER = """
DISCLAIMER: This tool is for ACADEMIC AND RESEARCH PURPOSES ONLY.
Only use on systems you own or have explicit permission to analyze.
The authors assume no liability for misuse or damage caused by this tool.
"""


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute scan command.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code (0 on success).
    """
    config_path = Path(args.config) if args.config else Path("data/config.json")
    try:
        config = load_config(config_path)
    except Exception as e:
        logger.error("Failed to load config: %s", e)
        return 1

    scanner = Scanner(config)
    results = scanner.scan_path(args.scan)

    if not results:
        logger.info("No results to report.")
        return 0

    report_gen = ReportGenerator(Path(config["report"]["output_dir"]))
    formats = args.report_format.split(",") if args.report_format else ["csv"]

    for fmt in formats:
        fmt = fmt.strip().lower()
        try:
            if fmt == "csv":
                path = report_gen.generate_csv(results)
                logger.info("CSV report: %s", path)
            elif fmt == "json":
                path = report_gen.generate_json(results)
                logger.info("JSON report: %s", path)
            elif fmt == "pdf":
                from core.pdf_reporter import generate_pdf

                path = generate_pdf(results)
                logger.info("PDF report: %s", path)
            else:
                logger.warning("Unknown report format: %s", fmt)
        except Exception as e:
            logger.error("Failed to generate %s report: %s", fmt, e)

    summary = report_gen.generate_summary(results)
    logger.info("Scan Summary: %s", summary)

    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    """Launch GUI application.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code.
    """
    try:
        from gui.app import launch_gui

        launch_gui()
        return 0
    except ImportError as e:
        logger.error("GUI dependencies not available: %s", e)
        logger.error("Install with: pip install customtkinter")
        return 1


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="WannaCry Detector Lite — Academic ransomware detection tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"{DISCLAIMER}\n"
        "Examples:\n"
        "  python main.py --scan /path/to/suspicious/files\n"
        "  python main.py --scan /path --report-format json,csv\n"
        "  python main.py --gui\n"
        "  python main.py --scan /path --verbose",
    )
    parser.add_argument(
        "--scan",
        type=str,
        default=None,
        help="Path to file or directory to scan",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch graphical user interface",
    )
    parser.add_argument(
        "--report-format",
        type=str,
        default="csv",
        help="Comma-separated report formats: csv,json,pdf (default: csv)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to custom config.json (default: data/config.json)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG logging",
    )
    args = parser.parse_args()

    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(level=getattr(sys.modules["logging"], log_level))
    if args.verbose:
        enable_debug()

    print(BANNER)
    print(DISCLAIMER)

    if args.scan:
        sys.exit(cmd_scan(args))
    elif args.gui:
        sys.exit(cmd_gui(args))
    else:
        logger.info("No action specified. Launching GUI by default...")
        sys.exit(cmd_gui(args))


if __name__ == "__main__":
    main()
