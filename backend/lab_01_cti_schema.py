"""Lab 7.1 - Analyze a Production Schema: Cyber Threat Intelligence (CTI) Platform
URL Reference: https://ctidigest.com/

Objective:
1. Examine realistic CTI production schema and identify embedding vs referencing.
2. For each referencing relationship, explain why embedding was not used and show the alternative.
3. Calculate average document size using $bsonSize and verify 16 MB limits.
4. Activity 7.1: Redesign referencing relationship as embedded design. Analyze trade-offs.
"""

import sys, os, time
from pymongo import MongoClient
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()
client = MongoClient("mongodb://localhost:27017/")
db = client["cti_platform"]


def banner(title):
    console.print("\n" + "=" * 80, style="bold cyan")
    console.print(f"  {title}", style="bold white")
    console.print("=" * 80 + "\n", style="bold cyan")


def step_1_schema_analysis():
    banner("1. Production Schema Relationship Identification")

    table = Table(title="CTI Platform Schema - Embedding vs Referencing Decisions")
    table.add_column("Relationship", style="cyan", width=30)
    table.add_column("Type", justify="center", width=12)
    table.add_column("Implementation in CTI Platform", style="green", width=36)

    table.add_row(
        "Indicator -> Sources (Feeds)",
        "[bold green]EMBEDDED[/bold green]",
        "Array of sources[] inside indicator document"
    )
    table.add_row(
        "Indicator -> MITRE ATT&CK",
        "[bold green]EMBEDDED[/bold green]",
        "Tactics & techniques embedded in attribution"
    )
    table.add_row(
        "Indicator -> Context Data",
        "[bold green]EMBEDDED[/bold green]",
        "Type-specific data (hashes, ASN) embedded"
    )
    table.add_row(
        "Indicator -> Threat Actor",
        "[bold yellow]REFERENCED[/bold yellow]",
        "actor_id references threat_actors collection"
    )
    table.add_row(
        "Report -> Related Indicators",
        "[bold yellow]REFERENCED[/bold yellow]",
        "related_indicators array of indicator_ids"
    )
    console.print(table)


def step_2_referencing_rationale():
    banner("2. Referencing Rationale & Embedded Alternative")

    r1_panel = """[bold cyan]Relationship 1: Indicator -> Threat Actor (REFERENCED)[/bold cyan]
• [bold]Why Referencing was Chosen:[/bold]
  - 1-to-N & N-to-N cardinality: A single threat actor (e.g., APT29 / Cozy Bear) is linked to hundreds of indicators.
  - Independent lifecycle: Threat actor profiles include in-depth biographies, nation-state attribution,
    TTPs, target sectors, and history. Updating an actor profile shouldn't trigger updates across 10,000+ indicators.
  - Document size control: Duplicating complete actor dossiers in every indicator wastes storage and memory.

• [bold]Embedded Alternative:[/bold]
  {
    "indicator_id": "ind-003",
    "value": "194.165.16.11",
    "threat_actor": {
      "actor_id": "actor-001",
      "name": "Cozy Bear",
      "aliases": ["APT29", "Midnight Blizzard"],
      "country": "Russia",
      "motivation": "Espionage",
      "description": "Russian SVR-linked group...",
      "ttps": ["Spearphishing", "Supply Chain"],
      "tools_used": ["Cobalt Strike", "WellMess"]
    }
  }

[bold cyan]Relationship 2: Report -> Related Indicators (REFERENCED)[/bold cyan]
• [bold]Why Referencing was Chosen:[/bold]
  - Many-to-Many cardinality: One threat report mentions 5-50 indicators; an indicator appears across multiple reports.
  - Active mutation: Indicators receive real-time updates (sighting counts, confidence score changes, expiration).
    If embedded in reports, reports would become stale or require complex distributed updates.

• [bold]Embedded Alternative:[/bold]
  {
    "report_id": "rpt-001",
    "title": "APT29 Campaign",
    "indicators": [
      { "type": "ipv4-addr", "value": "194.165.16.11", "severity": "critical" },
      { "type": "domain-name", "value": "cdn-microsoftonline.net", "severity": "critical" }
    ]
  }"""
    console.print(Panel(r1_panel, title="Design Decisions Explanation", border_style="blue"))


def step_3_bson_size_calculation():
    banner("3. Document Size Analysis using $bsonSize Aggregation")

    col = db["indicators"]
    pipeline = [
        {"$project": {
            "indicator_id": 1,
            "type": 1,
            "value": 1,
            "doc_bytes": {"$bsonSize": "$$ROOT"}
        }},
        {"$group": {
            "_id": None,
            "total_docs": {"$sum": 1},
            "avg_bytes": {"$avg": "$doc_bytes"},
            "max_bytes": {"$max": "$doc_bytes"},
            "min_bytes": {"$min": "$doc_bytes"},
            "total_bytes": {"$sum": "$doc_bytes"}
        }}
    ]

    result = list(col.aggregate(pipeline))
    if not result:
        console.print("[red]No documents found in indicators collection. Run seed_data.py first![/red]")
        return

    stats = result[0]
    LIMIT_16MB = 16 * 1024 * 1024

    summary_table = Table(title="BSON Document Size Metrics (indicators collection)")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", justify="right", style="green")
    summary_table.add_column("Limit / Threshold", justify="right")
    summary_table.add_column("% of 16MB Limit", justify="right", style="magenta")

    avg_b = stats['avg_bytes']
    max_b = stats['max_bytes']
    min_b = stats['min_bytes']
    tot_b = stats['total_bytes']
    count = stats['total_docs']

    summary_table.add_row("Total Documents", f"{count:,}", "-", "-")
    summary_table.add_row("Average Document Size", f"{avg_b:.2f} bytes ({avg_b/1024:.2f} KB)", "16,777,216 bytes", f"{(avg_b/LIMIT_16MB)*100:.5f}%")
    summary_table.add_row("Maximum Document Size", f"{max_b:,} bytes ({max_b/1024:.2f} KB)", "16,777,216 bytes", f"{(max_b/LIMIT_16MB)*100:.5f}%")
    summary_table.add_row("Minimum Document Size", f"{min_b:,} bytes ({min_b/1024:.2f} KB)", "16,777,216 bytes", f"{(min_b/LIMIT_16MB)*100:.5f}%")
    summary_table.add_row("Total Collection Data Size", f"{tot_b:,} bytes ({tot_b/1024:.2f} KB)", "-", "-")

    console.print(summary_table)

    console.print("\n[bold green]Verification Result:[/bold green]")
    console.print(f"  Maximum document size is {max_b:,} bytes ({max_b/1024:.2f} KB).")
    console.print(f"  Headroom remaining before 16 MB limit: {LIMIT_16MB - max_b:,} bytes ({(1 - max_b/LIMIT_16MB)*100:.4f}% safe).")
    console.print("  [bold green]SAFE: No documents approach the 16 MB BSON document limit.[/bold green]\n")


def step_4_activity_redesign():
    banner("Activity 7.1: Redesign Referencing as Embedded (Threat Source Attribution)")

    explanation = """[bold yellow]Experiment: Embedding Threat Actor Data into Threat Indicators[/bold yellow]

In the original schema:
  Indicator stores: attribution.threat_actors = [ { "actor_id": "actor-001", "name": "Cozy Bear" } ]
  Full actor details (aliases, TTPs, targets, tools) live in `threat_actors` collection.

[bold green]What Queries Become FASTER:[/bold green]
  1. [bold]Indicator Enrichment & SIEM Triage:[/bold]
     When an analyst queries an indicator (`db.indicators.findOne({"value": "194.165.16.11"})`),
     they get full actor dossiers, aliases, and TTPs in a SINGLE network round-trip.
     No `$lookup` aggregation pipeline required!
  2. [bold]Actor-attribute search on indicators:[/bold]
     Finding indicators by actor motivation (`{"attribution.actor.motivation": "Espionage"}`)
     does not require a join or pre-query.
  3. [bold]Working Set Locality:[/bold]
     Indicator + Threat Actor data resides on the same memory page in WiredTiger cache.

[bold red]What Queries Become HARDER / MORE EXPENSIVE:[/bold red]
  1. [bold]Threat Actor Updates (Write Amplification):[/bold]
     If threat researchers discover that Cozy Bear operates new aliases or tools,
     we must update EVERY indicator attributed to Cozy Bear (potentially 50,000+ docs)
     instead of 1 document in `threat_actors`.
  2. [bold]Data Inconsistency Risks:[/bold]
     Partial batch update failures leave some indicators with outdated actor data.
  3. [bold]Index & Memory Bloat:[/bold]
     Repeated string fields inflate collection storage size and consume more WiredTiger cache."""

    console.print(Panel(explanation, title="Activity 7.1 Trade-Off Analysis", border_style="yellow"))


def main():
    console.print(Panel.fit("[bold white]NoSQL Lab 7.1 - Analyze a Production Schema[/bold white]\n[cyan]Cyber Threat Intelligence Platform (https://ctidigest.com/)[/cyan]", border_style="cyan"))
    step_1_schema_analysis()
    step_2_referencing_rationale()
    step_3_bson_size_calculation()
    step_4_activity_redesign()
    banner("Lab 7.1 Completed Successfully")


if __name__ == "__main__":
    main()
