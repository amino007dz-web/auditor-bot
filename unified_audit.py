#!/usr/bin/env python3
"""
Unified Audit CLI — static analysis for any smart contract project
Support: Solidity, Chialisp, Move/Sui
"""
import os
import sys
import argparse
from analyzers import get_analyzer, detect_language, list_languages
from cli_display import console, banner, markdown_report, severity_text


def main():
    parser = argparse.ArgumentParser(
        description="Unified Smart Contract Static Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  unified_audit --dir solidity_project
  unified_audit --dir chia_project --lang chialisp
  unified_audit --file contract.move
  unified_audit --list-languages
        """
    )
    parser.add_argument("--dir", help="project directory to analyze")
    parser.add_argument("--file", help="single file to analyze")
    parser.add_argument("--lang", choices=list_languages(), help="force language (optional)")
    parser.add_argument("--list-languages", action="store_true", help="list supported languages")
    parser.add_argument("--output", help="save report to file")

    args = parser.parse_args()

    if args.list_languages:
        console.print("[bold]Supported languages:[/]")
        for lang in list_languages():
            console.print(f"  • [cyan]{lang}[/]")
        return

    if not args.dir and not args.file:
        parser.print_help()
        console.print("\n[yellow]Use --file or --dir[/]")
        return

    if args.file and args.dir:
        console.print("[red]Choose --file or --dir only[/]")
        return

    path = args.dir or args.file
    if not os.path.exists(path):
        console.print(f"[red]Path not found:[/] {path}")
        return

    lang = args.lang or detect_language(path)
    if not lang:
        console.print("[red]Could not detect language.[/] Use --lang:")
        for l in list_languages():
            console.print(f"  unified_audit --lang [cyan]{l}[/] --dir <path>")
        return

    analyzer = get_analyzer(lang)
    if not analyzer:
        console.print(f"[red]No analyzer for language:[/] {lang}")
        return

    banner(f"{lang.upper()} Static Analysis")
    console.print(f"  [bold]Language:[/]  {lang}")
    console.print(f"  [bold]Path:[/]      {path}")
    console.print(f"  [bold]Analyzer:[/]  {analyzer.name}")
    console.print()

    if args.file:
        code = analyzer.load_file(path)
        if not code:
            console.print("[red]Failed to read file[/]")
            return
        analyzer._files = {os.path.basename(path): code}
        results = analyzer.analyze_all()
    else:
        results = analyzer.analyze_all(path)

    report = analyzer.generate_report(results)
    markdown_report(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        console.print(f"[green]Report saved:[/] {args.output}")


if __name__ == "__main__":
    main()
