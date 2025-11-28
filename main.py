import argparse
import sys
import json
import os
from scanner import CodeScanner
from agent import SecurityAgent
from report_generator import generate_report
from rich.console import Console
from rich.table import Table
from dotenv import load_dotenv

# Load env vars (API keys)
load_dotenv()

console = Console()

def main():
    parser = argparse.ArgumentParser(description="AI-Powered JS/TS Security Auditor")
    parser.add_argument("target", help="Directory to scan")
    parser.add_argument("--json", help="Output results to JSON file", action="store_true")
    parser.add_argument("--no-cache", help="Disable AI caching", action="store_true")
    args = parser.parse_args()

    # 1. Validation
    if not os.environ.get("OPENAI_API_KEY"):
        console.print("[bold red]Error:[/bold red] OPENAI_API_KEY not found in environment.")
        console.print("Please set it via 'export OPENAI_API_KEY=...' or a .env file")
        sys.exit(1)
    
    if not os.path.isdir(args.target):
        console.print(f"[bold red]Error:[/bold red] Directory '{args.target}' does not exist.")
        sys.exit(1)

    # 2. Scanning Phase (Deterministic)
    console.rule("[bold blue]Phase 1: Pattern Scanning")
    scanner = CodeScanner(args.target)
    candidates = scanner.scan()
    
    if not candidates:
        console.print("[green]No suspicious patterns found via Regex.[/green]")
        sys.exit(0)
        
    console.print(f"[yellow]Found {len(candidates)} potential hotspots. Passing to AI Agent...[/yellow]")

    # 3. Analysis Phase (Probabilistic)
    console.rule("[bold blue]Phase 2: AI Verification")
    # Initialize Agent with Caching
    agent = SecurityAgent(use_cache=not args.no_cache)
    confirmed_findings = agent.analyze_candidates(candidates)

    # 4. Reporting
    console.rule("[bold blue]Phase 3: Final Report")
    
    if not confirmed_findings:
        console.print("[bold green]Good news! The AI determined all candidates were false positives.[/bold green]")
    else:
        # Display Table in Terminal
        table = Table(title="Confirmed Vulnerabilities")
        table.add_column("Type", style="red")
        table.add_column("Location", style="cyan")
        table.add_column("Severity", style="yellow")
        table.add_column("Fix", style="green")

        for finding in confirmed_findings:
            loc = f"{os.path.basename(finding['file'])}:{finding['line']}"
            table.add_row(
                finding['vuln_name'], 
                loc, 
                finding.get('severity', 'Medium'),
                finding['fix_suggestion'][:50] + "..." # Truncate for display
            )

        console.print(table)
        
        # Generate Markdown Report
        report_path = generate_report(confirmed_findings, args.target)
        console.print(f"\n[bold]Detailed report generated: [green]{report_path}[/green][/bold]")
        
        # Optional JSON dump
        if args.json:
            with open("security_report.json", "w") as f:
                json.dump(confirmed_findings, f, indent=2)
            console.print(f"[dim]JSON data saved to security_report.json[/dim]")

if __name__ == "__main__":
    main()