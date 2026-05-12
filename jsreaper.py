from __future__ import annotations
import sys
import os
import argparse
import logging
import json

from core.engine import Engine
from output.formatter import (
    print_banner, print_summary, print_secrets, print_security_issues,
    print_vuln_libs, print_endpoints, print_intel, print_extraction,
    format_json, format_csv, format_sarif,
)


def _setup_logging(verbose: bool, quiet: bool) -> logging.Logger:
    logger  = logging.getLogger("jsreaper")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(handler)
    if quiet:
        logger.setLevel(logging.ERROR)
    elif verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    return logger


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jsreaper",
        description="JS Secret & Security Scanner — 10x Elite Edition",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    p.add_argument("url",                help="Target URL to scan")
    p.add_argument("--version", action="version", version="%(prog)s 2.0.0")

    crawl = p.add_argument_group("Crawling")
    crawl.add_argument("--depth",             type=int,   default=2,   help="Page crawl depth")
    crawl.add_argument("--threads",           type=int,   default=10,  help="Parallel fetch threads")
    crawl.add_argument("--timeout",           type=int,   default=15,  help="Request timeout (s)")
    crawl.add_argument("--delay",             type=float, default=0.0, help="Delay between requests (s)")
    crawl.add_argument("--jitter",            type=float, default=0.3, help="Random jitter added to delay")
    crawl.add_argument("--max-js",            type=int,   default=500, help="Max JS files to scan")
    crawl.add_argument("--scope",             nargs="+",               help="Domains to scope crawl to")
    crawl.add_argument("--extra-urls",        nargs="+",               help="Extra JS URLs to scan")
    crawl.add_argument("--nested-scan",       action="store_true",     help="Recursively scan base64/JSON blobs for secrets")

    waf = p.add_argument_group("WAF Bypass")
    waf.add_argument("--waf-bypass",          action="store_true",     help="Enable full WAF bypass mode")
    waf.add_argument("--rotate-ua",           action="store_true",     help="Rotate User-Agent per request")
    waf.add_argument("--spoof-ip",            action="store_true",     help="Add IP spoofing headers")
    waf.add_argument("--cf-bypass",           action="store_true",     help="Add Cloudflare bypass headers")
    waf.add_argument("--user-agent",          metavar="UA",            help="Use a fixed User-Agent")
    waf.add_argument("--proxy",               metavar="URL",           help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    waf.add_argument("--no-ssl-verify",       action="store_true",     help="Disable SSL verification")
    waf.add_argument("--headers",             nargs="+", metavar="H",  help="Extra headers: 'Name: Value'")
    waf.add_argument("--cookies",             metavar="STR",           help="Cookie string: 'k1=v1; k2=v2'")
    waf.add_argument("--backoff-delay",       type=float, default=2.0, help="Base backoff delay on 429/403")
    waf.add_argument("--max-retries",         type=int,   default=6,   help="Max retry attempts on rate limit")

    scan = p.add_argument_group("Scanning")
    scan.add_argument("--secrets-only",       action="store_true",     help="Only output secrets")
    scan.add_argument("--endpoints-only",     action="store_true",     help="Only output endpoints")
    scan.add_argument("--no-security",        action="store_true",     help="Skip security checks")
    scan.add_argument("--no-vuln-libs",       action="store_true",     help="Skip vulnerable library detection")
    scan.add_argument("--no-intel",           action="store_true",     help="Skip intelligence gathering")
    scan.add_argument("--no-extraction",      action="store_true",     help="Skip deep extraction")
    scan.add_argument("--intel",              action="store_true",     help="Enable intelligence gathering (OSINT)")
    scan.add_argument("--probe",              action="store_true",     help="Actively probe discovered endpoints")
    scan.add_argument("--deobfuscate",        action="store_true",     help="Attempt to deobfuscate JS before scan")
    scan.add_argument("--entropy",            action="store_true",     help="Enable entropy-based detection")
    scan.add_argument("--entropy-threshold",  type=float, default=4.0, help="Minimum Shannon entropy to flag")
    scan.add_argument("--min-secret-len",     type=int,   default=16,  help="Minimum secret length")
    scan.add_argument("--patterns",           metavar="FILE",          help="Extra patterns JSON file")
    scan.add_argument("--disable-pattern",    nargs="+",               help="Disable named patterns")
    scan.add_argument("--severity",           choices=["critical","high","medium","low"],
                                                                       help="Minimum severity to report")
    scan.add_argument("--min-confidence",     type=int,   default=0,   help="Min confidence score (0-100)")
    scan.add_argument("--no-unique",          action="store_true",     help="Do not deduplicate findings")

    output = p.add_argument_group("Output")
    output.add_argument("--output-format", choices=["text","json","csv","sarif"], default="text",
                                                                       help="Output format")
    output.add_argument("--output",           metavar="FILE",          help="Write output to file")
    output.add_argument("--no-color",         action="store_true",     help="Disable colored output")
    output.add_argument("--show-context",     action="store_true",     help="Show surrounding code context")
    output.add_argument("--context-lines",    type=int,   default=3,   help="Lines of context to show")
    output.add_argument("--no-banner",        action="store_true",     help="Suppress banner")
    output.add_argument("--quiet",   "-q",    action="store_true",     help="Quiet mode (stderr only)")
    output.add_argument("--verbose", "-v",    action="store_true",     help="Verbose debug logging")

    return p


def _write_output(content: str, path: str | None):
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    else:
        print(content)


def main():
    parser = _build_parser()
    args   = parser.parse_args()
    logger = _setup_logging(args.verbose, args.quiet)

    no_color = args.no_color or not sys.stdout.isatty()

    if args.output_format == "text" and not args.no_banner and not args.quiet:
        print_banner(args.url, no_color=no_color)

    try:
        engine  = Engine(args, logger)
        results = engine.run()
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    if args.output_format == "json":
        _write_output(format_json(results), args.output)

    elif args.output_format == "csv":
        _write_output(format_csv(results), args.output)

    elif args.output_format == "sarif":
        _write_output(json.dumps(format_sarif(results), indent=2), args.output)

    else:
        print_summary(results, no_color=no_color)
        if not args.endpoints_only:
            print_secrets(results.get("secrets", []), no_color=no_color,
                          show_context=args.show_context)
        if not args.secrets_only:
            if not args.no_security:
                print_security_issues(results.get("security_issues", []), no_color=no_color)
            if not args.no_vuln_libs:
                print_vuln_libs(results.get("vuln_libs", []), no_color=no_color)
            print_endpoints(results.get("endpoints", {}), no_color=no_color)
        if not args.no_intel:
            print_intel(results.get("intel", {}), no_color=no_color)
        if not args.no_extraction:
            print_extraction(results.get("extraction", {}), no_color=no_color)

    if args.output and args.output_format != "text":
        logger.info(f"Results saved to {args.output}")

    critical = sum(1 for f in results.get("secrets", []) if f.get("severity") == "critical")
    sys.exit(2 if critical > 0 else 0)


if __name__ == "__main__":
    main()
