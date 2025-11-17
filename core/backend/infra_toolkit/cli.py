"""
CLI Entry Point for Infrastructure Toolkit

Provides a unified command-line interface for all infrastructure tools.
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, Type

from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from .base_tool import BaseTool
from .tools.cloudflare import CloudflareTool
from .tools.pterodactyl import PterodactylTool


# Tool registry
AVAILABLE_TOOLS: Dict[str, Type[BaseTool]] = {
    "cloudflare": CloudflareTool,
    "pterodactyl": PterodactylTool,
}


console = Console()


def setup_logging(verbose: bool = False):
    """
    Configure logging with rich output.

    Args:
        verbose: Enable verbose logging (DEBUG level)
    """
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)]
    )


def list_tools():
    """List all available tools."""
    console.print("\n[bold cyan]Available Infrastructure Tools:[/bold cyan]\n")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Tool", style="cyan")
    table.add_column("Description", style="white")

    for tool_name, tool_class in AVAILABLE_TOOLS.items():
        # Get description from docstring
        doc = tool_class.__doc__ or "No description available"
        first_line = doc.strip().split('\n')[0]
        table.add_row(tool_name, first_line)

    console.print(table)
    console.print(f"\nUsage: infra-toolkit <tool> [options]\n")


def create_parser() -> argparse.ArgumentParser:
    """
    Create argument parser with all tools.

    Returns:
        Configured ArgumentParser
    """
    parser = argparse.ArgumentParser(
        description="Infrastructure Toolkit - Standardized CLI for infrastructure management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List available tools
  infra-toolkit --list

  # Cloudflare: List hostnames
  infra-toolkit cloudflare list

  # Cloudflare: Add hostname (dry-run)
  infra-toolkit cloudflare add prowlarr 192.168.1.11 9696 --dry-run

  # Cloudflare: Add hostname (execute)
  infra-toolkit cloudflare add prowlarr 192.168.1.11 9696

  # Cloudflare: Validate configuration
  infra-toolkit cloudflare validate

  # Cloudflare: Health check
  infra-toolkit cloudflare health-check

  # Cloudflare: List backups
  infra-toolkit cloudflare backups

  # Cloudflare: Restore from backup
  infra-toolkit cloudflare restore /path/to/backup.json
"""
    )

    # Global options
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available tools"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="infrastructure-toolkit 1.0.0"
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    # Tool subcommands
    subparsers = parser.add_subparsers(dest="tool", help="Infrastructure tool to use")

    # Register each tool
    for tool_name, tool_class in AVAILABLE_TOOLS.items():
        tool_parser = subparsers.add_parser(
            tool_name,
            help=f"{tool_name.capitalize()} management"
        )

        # Let the tool configure its own parser
        tool_class.configure_parser(tool_parser)

    return parser


def execute_tool(args) -> int:
    """
    Execute selected tool with provided arguments.

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    tool_name = args.tool

    if tool_name not in AVAILABLE_TOOLS:
        console.print(f"[bold red]Error:[/bold red] Unknown tool: {tool_name}")
        console.print("\nRun 'infra-toolkit --list' to see available tools")
        return 1

    tool_class = AVAILABLE_TOOLS[tool_name]

    try:
        # Extract common options
        dry_run = getattr(args, "dry_run", False)
        verbose = getattr(args, "verbose", False)
        no_verify = getattr(args, "no_verify", False)

        # Initialize tool with appropriate parameters
        console.print(f"[bold cyan]Initializing {tool_name} tool...[/bold cyan]")

        if tool_name == "cloudflare":
            domain = getattr(args, "domain", "haymoed")
            tool = tool_class(
                domain=domain,
                dry_run=dry_run,
                verbose=verbose,
                no_verify=no_verify
            )
        elif tool_name == "pterodactyl":
            tool = tool_class(
                dry_run=dry_run,
                verbose=verbose,
                no_verify=no_verify
            )
        else:
            # Generic initialization for future tools
            tool = tool_class(
                dry_run=dry_run,
                verbose=verbose,
                no_verify=no_verify
            )

        # Execute subcommand
        subcommand = getattr(args, "subcommand", None)

        if not subcommand:
            console.print(f"[bold red]Error:[/bold red] No subcommand specified")
            return 1

        # Route to appropriate handler
        if subcommand == "list":
            hostnames = tool.list_hostnames()

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Hostname", style="cyan")
            table.add_column("Service", style="green")

            for entry in hostnames:
                table.add_row(entry["hostname"], entry["service"])

            console.print(f"\n[bold]Tunnel Hostnames ({len(hostnames)} total):[/bold]\n")
            console.print(table)
            console.print()

        elif subcommand == "add":
            service = args.service
            ip = args.ip
            port = args.port
            protocol = getattr(args, "protocol", "http")

            if dry_run:
                console.print(f"[bold yellow]DRY RUN MODE[/bold yellow] - No changes will be made\n")

            hostname = f"{service}.{domain}.com"
            service_url = f"{protocol}://{ip}:{port}"

            console.print(f"Adding hostname: [cyan]{hostname}[/cyan]")
            console.print(f"Service URL: [green]{service_url}[/green]\n")

            if not dry_run:
                success = tool.add_hostname(service, ip, port, protocol)

                if success:
                    console.print(f"\n[bold green]✓ Success![/bold green] Hostname added: {hostname}")
                else:
                    console.print(f"\n[bold red]✗ Failed[/bold red] to add hostname")
                    return 1
            else:
                console.print("[yellow]Dry-run complete - no changes made[/yellow]")

        elif subcommand == "validate":
            console.print("[bold cyan]Validating tunnel configuration...[/bold cyan]\n")

            is_valid, errors = tool.validate_tunnel_config()

            if is_valid:
                console.print("[bold green]✓ Configuration valid![/bold green]")

                # Show hostname count
                config = tool.get_tunnel_config()
                ingress = config.get("config", {}).get("ingress", [])
                hostname_count = len([r for r in ingress if "hostname" in r])
                console.print(f"  Hostnames: {hostname_count}")
            else:
                console.print("[bold red]✗ Configuration invalid![/bold red]\n")
                for error in errors:
                    console.print(f"  • {error}")
                return 1

        elif subcommand == "health-check":
            console.print("[bold cyan]Running health check...[/bold cyan]\n")

            result = tool.health_check()

            status = result["status"]
            checks = result["checks"]

            # Display results
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Check", style="cyan")
            table.add_column("Status", style="white")

            for check_name, check_result in checks.items():
                if isinstance(check_result, bool):
                    status_str = "[green]✓ PASS[/green]" if check_result else "[red]✗ FAIL[/red]"
                    table.add_row(check_name, status_str)

            console.print(table)

            if status == "healthy":
                console.print(f"\n[bold green]✓ All checks passed[/bold green]")
            else:
                console.print(f"\n[bold red]✗ Health check failed[/bold red]")
                if "error" in checks:
                    console.print(f"  Error: {checks['error']}")
                if "tunnel_error" in checks:
                    console.print(f"  Tunnel error: {checks['tunnel_error']}")
                return 1

        elif subcommand == "backups":
            backups = tool.backup_manager.list_backups()

            if not backups:
                console.print("[yellow]No backups found[/yellow]")
                return 0

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Filename", style="cyan")
            table.add_column("Created", style="green")
            table.add_column("Size", style="yellow")

            for backup in backups:
                size_kb = backup["size"] / 1024
                table.add_row(
                    backup["filename"],
                    backup["created"].strftime("%Y-%m-%d %H:%M:%S"),
                    f"{size_kb:.1f} KB"
                )

            console.print(f"\n[bold]Available Backups ({len(backups)} total):[/bold]\n")
            console.print(table)
            console.print()

        elif subcommand == "restore":
            backup_file = Path(args.backup_file)

            if not backup_file.exists():
                console.print(f"[bold red]Error:[/bold red] Backup file not found: {backup_file}")
                return 1

            console.print(f"[bold yellow]Restoring from backup:[/bold yellow] {backup_file.name}\n")

            if dry_run:
                console.print("[bold yellow]DRY RUN MODE[/bold yellow] - No changes will be made\n")
                console.print("[yellow]Dry-run complete - no changes made[/yellow]")
            else:
                success = tool.rollback_from_backup(backup_file)

                if success:
                    console.print(f"\n[bold green]✓ Restore successful![/bold green]")
                else:
                    console.print(f"\n[bold red]✗ Restore failed[/bold red]")
                    return 1

        # Pterodactyl-specific commands
        elif subcommand == "nodes":
            nodes = tool.list_nodes()

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("ID", style="cyan")
            table.add_column("Name", style="cyan")
            table.add_column("FQDN", style="green")
            table.add_column("Status", style="white")
            table.add_column("Memory", style="yellow")

            for node in nodes:
                # Status indicator
                if node.get("is_expected"):
                    if node.get("warning"):
                        status = "[yellow]⚠ WARNING[/yellow]"
                    else:
                        status = "[green]✓ OK[/green]"
                else:
                    status = "[dim]Unknown[/dim]"

                memory_gb = node.get("memory", 0) / 1024
                table.add_row(
                    str(node.get("id")),
                    node.get("name", "N/A"),
                    node.get("fqdn", "N/A"),
                    status,
                    f"{memory_gb:.1f} GB"
                )

            console.print(f"\n[bold]Pterodactyl Wings ({len(nodes)} total):[/bold]\n")
            console.print(table)

            # Show warnings if any
            for node in nodes:
                if node.get("warning"):
                    console.print(f"\n[yellow]⚠ {node.get('fqdn')}:[/yellow] {node.get('warning')}")

            console.print()

        elif subcommand == "node-status":
            node_id = args.node_id
            status = tool.get_node_status(node_id)

            console.print(f"\n[bold cyan]Node Status:[/bold cyan] {status.get('name')}\n")

            table = Table(show_header=False)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")

            table.add_row("FQDN", status.get("fqdn", "N/A"))
            table.add_row("Maintenance Mode", "Yes" if status.get("is_maintenance") else "No")
            table.add_row("Allocated Memory", f"{status.get('allocated_memory', 0) / 1024:.1f} GB")
            table.add_row("Allocated Disk", f"{status.get('allocated_disk', 0) / 1024:.1f} GB")
            table.add_row("Memory Overallocation", f"{status.get('memory_overallocate', 0)}%")
            table.add_row("Disk Overallocation", f"{status.get('disk_overallocate', 0)}%")

            console.print(table)
            console.print()

        elif subcommand == "diagnose":
            console.print("[bold cyan]Diagnosing tunnel configuration...[/bold cyan]\n")

            diagnosis = tool.diagnose_tunnel_config()

            if diagnosis["status"] == "healthy":
                console.print("[bold green]✓ No issues detected![/bold green]\n")
            elif diagnosis["status"] == "issues_found":
                console.print("[bold yellow]⚠ Issues detected![/bold yellow]\n")

                for issue in diagnosis["issues"]:
                    console.print(f"[yellow]Node:[/yellow] {issue['node']}")
                    console.print(f"  [red]Issue:[/red] {issue['issue']}")
                    console.print(f"  Current: {issue['current']}")
                    console.print(f"  Expected: {issue['expected']}")
                    console.print(f"  [yellow]Impact:[/yellow] {issue['impact']}")
                    console.print(f"  [cyan]Fix:[/cyan] {issue['fix']}\n")

            if diagnosis["recommendations"]:
                console.print("[bold]Recommendations:[/bold]")
                for rec in diagnosis["recommendations"]:
                    console.print(f"  • {rec}")
                console.print()

        elif subcommand == "servers":
            node_id = getattr(args, "node", None)

            if node_id:
                console.print(f"[bold cyan]Servers on node {node_id}:[/bold cyan]\n")
            else:
                console.print("[bold cyan]All game servers:[/bold cyan]\n")

            servers = tool.list_servers(node_id=node_id)

            if not servers:
                console.print("[yellow]No servers found[/yellow]")
                return 0

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("ID", style="cyan")
            table.add_column("Name", style="white")
            table.add_column("Node", style="green")
            table.add_column("Status", style="yellow")
            table.add_column("Memory", style="blue")

            for server in servers:
                status_str = server.get("status", "unknown")
                if server.get("is_suspended"):
                    status_str = "[red]suspended[/red]"

                memory_mb = server.get("limits", {}).get("memory", 0)

                table.add_row(
                    str(server.get("id")),
                    server.get("name", "N/A")[:30],  # Truncate long names
                    str(server.get("node")),
                    status_str,
                    f"{memory_mb} MB"
                )

            console.print(table)
            console.print()

        else:
            console.print(f"[bold red]Error:[/bold red] Unknown subcommand: {subcommand}")
            return 1

        return 0

    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        return 130

    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        if args.verbose:
            console.print_exception()
        return 1


def main():
    """Main entry point for CLI."""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    setup_logging(verbose=getattr(args, "verbose", False))

    # Handle --list
    if args.list:
        list_tools()
        return 0

    # Check if tool specified
    if not args.tool:
        parser.print_help()
        console.print("\n[yellow]Tip:[/yellow] Run 'infra-toolkit --list' to see available tools")
        return 1

    # Execute tool
    exit_code = execute_tool(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
