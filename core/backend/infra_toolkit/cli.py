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
from .tools.performance import PerformanceTool
from .tools.network import NetworkTool
from .tools.docker import DockerTool
from .tools.nas import NASTool
from .tools.proxmox import ProxmoxTool
from .tools.homeassistant import HomeAssistantTool
from .tools.ups import UPSTool
from .tools.uptime_kuma import UptimeKumaTool
from .tools.protonmail import ProtonMailTool


# Tool registry
AVAILABLE_TOOLS: Dict[str, Type[BaseTool]] = {
    "cloudflare": CloudflareTool,
    "docker": DockerTool,
    "homeassistant": HomeAssistantTool,
    "nas": NASTool,
    "network": NetworkTool,
    "performance": PerformanceTool,
    "proxmox": ProxmoxTool,
    "pterodactyl": PterodactylTool,
    "ups": UPSTool,
    "uptime-kuma": UptimeKumaTool,
    "protonmail": ProtonMailTool,
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
        elif tool_name == "performance":
            server = getattr(args, "server", None)
            all_servers = getattr(args, "all_servers", False)
            tool = tool_class(
                server=server,
                all_servers=all_servers,
                dry_run=dry_run,
                verbose=verbose,
                no_verify=no_verify
            )
        elif tool_name == "network":
            tool = tool_class(
                dry_run=dry_run,
                verbose=verbose,
                no_verify=no_verify
            )
        elif tool_name == "docker":
            server = getattr(args, "server", None)
            all_servers = getattr(args, "all_servers", False)
            tool = tool_class(
                server=server,
                all_servers=all_servers,
                dry_run=dry_run,
                verbose=verbose,
                no_verify=no_verify
            )
        elif tool_name == "nas":
            tool = tool_class()
        elif tool_name == "proxmox":
            host = getattr(args, "host", "pve3")
            tool = tool_class(
                host=host,
                dry_run=dry_run,
                verbose=verbose,
                no_verify=no_verify
            )
        elif tool_name == "homeassistant":
            tool = tool_class(
                dry_run=dry_run,
                verbose=verbose,
                no_verify=no_verify
            )
        elif tool_name == "ups":
            tool = tool_class(
                dry_run=dry_run,
                verbose=verbose,
                no_verify=no_verify
            )
        elif tool_name == "uptime-kuma":
            # Load config for uptime-kuma
            config = _load_tool_config()
            tool = tool_class(
                config=config,
                dry_run=dry_run,
                verbose=verbose,
                no_verify=no_verify
            )
        elif tool_name == "protonmail":
            config = _load_tool_config()
            tool = tool_class(
                config=config,
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

        # Route to appropriate handler based on tool
        if tool_name == "cloudflare":
            return _handle_cloudflare(tool, subcommand, args, dry_run, domain)
        elif tool_name == "pterodactyl":
            return _handle_pterodactyl(tool, subcommand, args)
        elif tool_name == "performance":
            return _handle_performance(tool, subcommand, args)
        elif tool_name == "network":
            return _handle_network(tool, subcommand, args)
        elif tool_name == "docker":
            return _handle_docker(tool, subcommand, args, dry_run)
        elif tool_name == "nas":
            return _handle_nas(tool, subcommand, args, dry_run)
        elif tool_name == "proxmox":
            return _handle_proxmox(tool, subcommand, args, dry_run)
        elif tool_name == "homeassistant":
            return _handle_homeassistant(tool, subcommand, args, dry_run)
        elif tool_name == "ups":
            return _handle_ups(tool, subcommand, args)
        elif tool_name == "uptime-kuma":
            return _handle_uptime_kuma(tool, subcommand, args)
        elif tool_name == "protonmail":
            return _handle_protonmail(tool, subcommand, args)
        else:
            console.print(f"[bold red]Error:[/bold red] No handler for tool: {tool_name}")
            return 1

    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        return 130

    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        if verbose:
            console.print_exception()
        return 1


def _handle_cloudflare(tool, subcommand: str, args, dry_run: bool, domain: str) -> int:
    """Handle Cloudflare tool subcommands."""
    try:
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
            explicit_hostname = getattr(args, "hostname", None)

            if dry_run:
                console.print(f"[bold yellow]DRY RUN MODE[/bold yellow] - No changes will be made\n")

            hostname = explicit_hostname or f"{service}.{tool.domain_fqdn}"
            service_url = f"{protocol}://{ip}:{port}"

            console.print(f"Adding hostname: [cyan]{hostname}[/cyan]")
            console.print(f"Service URL: [green]{service_url}[/green]\n")

            if not dry_run:
                success = tool.add_hostname(service, ip, port, protocol, hostname=explicit_hostname)

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

        elif subcommand == "remove":
            hostname = args.hostname
            console.print(f"Removing hostname: [cyan]{hostname}[/cyan]\n")
            if dry_run:
                console.print("[bold yellow]DRY RUN MODE[/bold yellow] - No changes will be made\n")
                console.print("[yellow]Dry-run complete - no changes made[/yellow]")
            else:
                success = tool.remove_hostname(hostname)
                if success:
                    console.print(f"\n[bold green]✓ Success![/bold green] Hostname removed: {hostname}")
                else:
                    console.print(f"\n[bold red]✗ Failed[/bold red] to remove hostname")
                    return 1

        elif subcommand == "dns-list":
            record_type = getattr(args, "record_type", None)
            records = tool.list_dns_records(record_type=record_type)

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("ID", style="dim", max_width=16)
            table.add_column("Type", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Content", style="white", max_width=50)
            table.add_column("Proxied", style="yellow")

            for rec in records:
                table.add_row(
                    rec["id"][:16], rec["type"], rec["name"],
                    rec["content"][:50], str(rec.get("proxied", False))
                )

            console.print(f"\n[bold]DNS Records ({len(records)} total):[/bold]\n")
            console.print(table)
            console.print()

        elif subcommand == "dns-add":
            proxied = not getattr(args, "no_proxy", False)
            result = tool.add_dns_record(args.record_type, args.name, args.content, proxied=proxied)
            if result.get("already_exists"):
                console.print(f"[yellow]DNS record already exists: {args.name}[/yellow]")
            else:
                console.print(f"[bold green]✓ DNS record created:[/bold green] {args.record_type} {args.name} → {args.content}")

        elif subcommand == "dns-remove":
            tool.remove_dns_record(args.record_id)
            console.print(f"[bold green]✓ DNS record deleted[/bold green]")

        elif subcommand == "access-list":
            apps = tool.list_access_apps()

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("ID", style="dim", max_width=20)
            table.add_column("Name", style="cyan")
            table.add_column("Domain", style="green")
            table.add_column("Type", style="white")

            for app in apps:
                table.add_row(app["id"][:20], app["name"], app.get("domain", ""), app.get("type", ""))

            console.print(f"\n[bold]Access Applications ({len(apps)} total):[/bold]\n")
            console.print(table)
            console.print()

        elif subcommand == "access-create-app":
            result = tool.create_access_app(
                args.name, args.app_domain,
                session_duration=getattr(args, "session_duration", "24h")
            )
            console.print(f"[bold green]✓ Access app created:[/bold green] {result['name']} (ID: {result['id']})")

        elif subcommand == "access-add-policy":
            result = tool.add_access_policy(
                args.app_id, args.policy_name,
                decision=getattr(args, "decision", "allow"),
                emails=args.emails
            )
            console.print(f"[bold green]✓ Policy added:[/bold green] {result['name']}")

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


def _handle_pterodactyl(tool, subcommand: str, args) -> int:
    """Handle Pterodactyl tool subcommands."""
    try:
        if subcommand == "nodes":
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


def _handle_performance(tool, subcommand: str, args) -> int:
    """Handle Performance tool subcommands."""
    try:
        if subcommand == "dashboard":
            console.print("[bold cyan]Server Performance Dashboard[/bold cyan]\n")

            metrics = tool.get_all_servers_metrics()

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Server", style="cyan")
            table.add_column("Status", style="white")
            table.add_column("CPU Load (1m)", style="yellow")
            table.add_column("Memory", style="blue")
            table.add_column("Disk", style="green")

            for server_metrics in metrics:
                server = server_metrics.get("server", "N/A")
                reachable = server_metrics.get("reachable", False)

                if not reachable:
                    status = "[red]✗ UNREACHABLE[/red]"
                    table.add_row(server, status, "—", "—", "—")
                    continue

                # Status based on health
                status_val = server_metrics.get("status", "unknown")
                if status_val == "healthy":
                    status = "[green]✓ HEALTHY[/green]"
                elif status_val == "warning":
                    status = "[yellow]⚠ WARNING[/yellow]"
                elif status_val == "critical":
                    status = "[red]✗ CRITICAL[/red]"
                else:
                    status = "[dim]UNKNOWN[/dim]"

                # CPU Load
                cpu_load = server_metrics.get("cpu_load", {})
                cpu_1min = cpu_load.get("1min", 0)
                cpu_str = f"{cpu_1min:.2f}"

                # Memory
                memory = server_metrics.get("memory", {})
                mem_used_pct = memory.get("used_percent", 0)
                mem_str = f"{mem_used_pct:.1f}%"

                # Disk
                disk = server_metrics.get("disk", {})
                disk_used_pct = disk.get("used_percent", 0)
                disk_str = f"{disk_used_pct:.1f}%"

                table.add_row(server, status, cpu_str, mem_str, disk_str)

            console.print(table)
            console.print()

        elif subcommand == "metrics":
            server = args.server
            console.print(f"[bold cyan]Detailed Metrics for {server}[/bold cyan]\n")

            metrics = tool.get_server_metrics(server)

            if not metrics.get("reachable"):
                console.print(f"[bold red]✗ Server unreachable:[/bold red] {server}")
                return 1

            # Build table
            table = Table(show_header=False)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="white")

            # CPU Load
            if "cpu_load" in metrics:
                cpu = metrics["cpu_load"]
                table.add_row("CPU Load (1min)", f"{cpu.get('1min', 0):.2f}")
                table.add_row("CPU Load (5min)", f"{cpu.get('5min', 0):.2f}")
                table.add_row("CPU Load (15min)", f"{cpu.get('15min', 0):.2f}")

            # Memory
            if "memory" in metrics:
                mem = metrics["memory"]
                table.add_row("Memory Total", f"{mem.get('total_gb', 0):.1f} GB")
                table.add_row("Memory Used", f"{mem.get('used_gb', 0):.1f} GB")
                table.add_row("Memory Used %", f"{mem.get('used_percent', 0):.1f}%")

            # Disk
            if "disk" in metrics:
                disk = metrics["disk"]
                table.add_row("Disk Total", f"{disk.get('total_gb', 0):.1f} GB")
                table.add_row("Disk Used", f"{disk.get('used_gb', 0):.1f} GB")
                table.add_row("Disk Used %", f"{disk.get('used_percent', 0):.1f}%")

            # Uptime
            if "uptime" in metrics:
                table.add_row("Uptime", metrics["uptime"])

            console.print(table)
            console.print()

        elif subcommand == "summary":
            console.print("[bold cyan]Performance Summary[/bold cyan]\n")

            metrics = tool.get_all_servers_metrics()

            total = len(metrics)
            reachable = sum(1 for m in metrics if m.get("reachable"))
            unreachable = total - reachable

            healthy = sum(1 for m in metrics if m.get("status") == "healthy")
            warning = sum(1 for m in metrics if m.get("status") == "warning")
            critical = sum(1 for m in metrics if m.get("status") == "critical")

            table = Table(show_header=False)
            table.add_column("Metric", style="cyan")
            table.add_column("Count", style="white")

            table.add_row("Total Servers", str(total))
            table.add_row("Reachable", f"[green]{reachable}[/green]")
            table.add_row("Unreachable", f"[red]{unreachable}[/red]" if unreachable > 0 else "0")
            table.add_row("", "")
            table.add_row("Healthy", f"[green]{healthy}[/green]")
            table.add_row("Warning", f"[yellow]{warning}[/yellow]" if warning > 0 else "0")
            table.add_row("Critical", f"[red]{critical}[/red]" if critical > 0 else "0")

            console.print(table)
            console.print()

        elif subcommand == "export":
            import json
            metrics = tool.get_all_servers_metrics()

            # Format for export
            export_format = getattr(args, "format", "json")

            if export_format == "json":
                output = json.dumps({"servers": metrics}, indent=2)
                console.print(output)
            elif export_format == "csv":
                console.print("Server,Status,Reachable,CPU(1m),Memory%,Disk%")
                for m in metrics:
                    server = m.get("server", "N/A")
                    status = m.get("status", "unknown")
                    reachable = m.get("reachable", False)
                    cpu = m.get("cpu_load", {}).get("1min", 0)
                    mem = m.get("memory", {}).get("used_percent", 0)
                    disk = m.get("disk", {}).get("used_percent", 0)
                    console.print(f"{server},{status},{reachable},{cpu:.2f},{mem:.1f},{disk:.1f}")

        elif subcommand == "health-check":
            console.print("[bold cyan]Performance Monitoring Health Check[/bold cyan]\n")

            # Test node_exporter connectivity
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Server", style="cyan")
            table.add_column("node_exporter", style="white")
            table.add_column("SSH", style="white")

            for server_name in tool.server_list.keys():
                # Try node_exporter
                ne_status = "[green]✓[/green]"
                try:
                    data = tool._query_prometheus_exporter(server_name, 9100)
                    if not data:
                        ne_status = "[red]✗[/red]"
                except:
                    ne_status = "[red]✗[/red]"

                # Try SSH
                ssh_status = "[green]✓[/green]"
                try:
                    result = tool._execute_ssh_command(server_name, "echo test")
                    if result.returncode != 0:
                        ssh_status = "[red]✗[/red]"
                except:
                    ssh_status = "[red]✗[/red]"

                table.add_row(server_name, ne_status, ssh_status)

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


def _handle_network(tool, subcommand: str, args) -> int:
    """Handle Network tool subcommands."""
    try:
        if subcommand == "health":
            console.print("[bold cyan]Network Health Status[/bold cyan]\n")

            health = tool.get_system_health()

            table = Table(show_header=False)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="white")

            table.add_row("CPU %", f"{health.get('cpu', 0):.1f}%")
            table.add_row("Memory %", f"{health.get('mem', 0):.1f}%")
            table.add_row("Uptime", health.get("uptime", "N/A"))

            console.print(table)
            console.print()

        elif subcommand == "networks":
            console.print("[bold cyan]Network Configurations[/bold cyan]\n")

            networks = tool.get_networks()

            if not networks:
                console.print("[yellow]No networks found[/yellow]")
                return 0

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Name", style="cyan")
            table.add_column("Subnet", style="green")
            table.add_column("VLAN", style="yellow")
            table.add_column("Domain", style="white")

            for net in networks:
                table.add_row(
                    net.get("name", "N/A"),
                    net.get("ip_subnet", "N/A"),
                    str(net.get("vlan", "N/A")),
                    net.get("domain_name", "N/A")
                )

            console.print(table)
            console.print()

        elif subcommand == "wifi":
            console.print("[bold cyan]WiFi Networks[/bold cyan]\n")

            wlans = tool.get_wifi_networks()

            if not wlans:
                console.print("[yellow]No WiFi networks found[/yellow]")
                return 0

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Name", style="cyan")
            table.add_column("Enabled", style="white")
            table.add_column("2.4GHz Rate", style="green")
            table.add_column("5GHz Rate", style="green")

            for wlan in wlans:
                enabled = "[green]Yes[/green]" if wlan.get("enabled") else "[red]No[/red]"
                ng_rate = wlan.get("minrate_ng_data_rate_kbps", 0) / 1000
                na_rate = wlan.get("minrate_na_data_rate_kbps", 0) / 1000

                table.add_row(
                    wlan.get("name", "N/A"),
                    enabled,
                    f"{ng_rate:.0f} Mbps" if ng_rate > 0 else "N/A",
                    f"{na_rate:.0f} Mbps" if na_rate > 0 else "N/A"
                )

            console.print(table)
            console.print()

        elif subcommand == "devices":
            console.print("[bold cyan]Network Devices[/bold cyan]\n")

            devices = tool.get_network_devices()

            if not devices:
                console.print("[yellow]No devices found[/yellow]")
                return 0

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Name", style="cyan")
            table.add_column("Type", style="white")
            table.add_column("Model", style="green")
            table.add_column("IP", style="yellow")
            table.add_column("State", style="white")

            for device in devices:
                state = device.get("state", 0)
                state_str = "[green]Connected[/green]" if state == 1 else "[red]Disconnected[/red]"

                table.add_row(
                    device.get("name", "N/A"),
                    device.get("type", "N/A"),
                    device.get("model", "N/A"),
                    device.get("ip", "N/A"),
                    state_str
                )

            console.print(table)
            console.print()

        elif subcommand == "clients":
            console.print("[bold cyan]Active Clients[/bold cyan]\n")

            clients = tool.get_active_clients()

            if not clients:
                console.print("[yellow]No active clients found[/yellow]")
                return 0

            # Sort options
            sort_by = getattr(args, "sort", "name")
            reverse = getattr(args, "reverse", False)
            top_n = getattr(args, "top", None)

            if sort_by == "name":
                clients.sort(key=lambda c: c.get("hostname", ""), reverse=reverse)
            elif sort_by == "ip":
                clients.sort(key=lambda c: c.get("ip", ""), reverse=reverse)
            elif sort_by == "rx":
                clients.sort(key=lambda c: c.get("rx_bytes", 0), reverse=True if not reverse else False)
            elif sort_by == "tx":
                clients.sort(key=lambda c: c.get("tx_bytes", 0), reverse=True if not reverse else False)

            if top_n:
                clients = clients[:top_n]

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Hostname", style="cyan")
            table.add_column("IP", style="green")
            table.add_column("MAC", style="white")
            table.add_column("RX", style="blue")
            table.add_column("TX", style="yellow")

            for client in clients:
                rx_mb = client.get("rx_bytes", 0) / (1024 * 1024)
                tx_mb = client.get("tx_bytes", 0) / (1024 * 1024)

                table.add_row(
                    client.get("hostname", "N/A"),
                    client.get("ip", "N/A"),
                    client.get("mac", "N/A"),
                    f"{rx_mb:.1f} MB",
                    f"{tx_mb:.1f} MB"
                )

            console.print(table)
            console.print()

        elif subcommand == "health-check":
            console.print("[bold cyan]Network Tool Health Check[/bold cyan]\n")

            # Test authentication
            if tool._authenticate():
                console.print("[green]✓ API authentication successful[/green]")
            else:
                console.print("[red]✗ API authentication failed[/red]")
                return 1

            # Test basic connectivity
            try:
                health = tool.get_system_health()
                console.print("[green]✓ API connectivity working[/green]")
            except Exception as e:
                console.print(f"[red]✗ API connectivity failed: {e}[/red]")
                return 1

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


def _handle_docker(tool, subcommand: str, args, dry_run: bool) -> int:
    """Handle Docker tool subcommands."""
    try:
        if subcommand == "list":
            if tool.all_servers:
                console.print("[bold cyan]Docker Containers (All Servers)[/bold cyan]\n")

                all_containers = tool.get_all_servers_containers()

                for server, containers in all_containers.items():
                    console.print(f"\n[bold]{server}:[/bold]")

                    if not containers:
                        console.print("  [dim]No containers running[/dim]")
                        continue

                    table = Table(show_header=True, header_style="bold magenta")
                    table.add_column("Name", style="cyan")
                    table.add_column("Image", style="green")
                    table.add_column("Status", style="white")
                    table.add_column("State", style="yellow")

                    for container in containers:
                        # Handle both dict and string formats
                        if isinstance(container, dict):
                            name = container.get("Name", container.get("name", "N/A"))
                            image = container.get("Image", container.get("image", "N/A"))
                            status = container.get("Status", container.get("status", "N/A"))
                            state = container.get("State", container.get("state", "unknown"))
                        else:
                            name = image = status = "N/A"
                            state = "unknown"

                        state_color = "[green]" if state == "running" else "[red]"
                        state_str = f"{state_color}{state}[/{state_color.strip('[')}]"

                        table.add_row(name, image, status, state_str)

                    console.print(table)

                console.print()

            else:
                server = tool.server
                console.print(f"[bold cyan]Docker Containers on {server}[/bold cyan]\n")

                containers = tool.get_running_services()

                if not containers:
                    console.print("[yellow]No containers running[/yellow]")
                    return 0

                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Name", style="cyan")
                table.add_column("Image", style="green")
                table.add_column("Status", style="white")
                table.add_column("State", style="yellow")

                for container in containers:
                    # Handle both dict and string formats
                    if isinstance(container, dict):
                        name = container.get("Name", container.get("name", "N/A"))
                        image = container.get("Image", container.get("image", "N/A"))
                        status = container.get("Status", container.get("status", "N/A"))
                        state = container.get("State", container.get("state", "unknown"))
                    else:
                        name = image = status = "N/A"
                        state = "unknown"

                    state_color = "[green]" if state == "running" else "[red]"
                    state_str = f"{state_color}{state}[/{state_color.strip('[')}]"

                    table.add_row(name, image, status, state_str)

                console.print(table)
                console.print()

        elif subcommand == "health-check":
            console.print("[bold cyan]Docker Health Check[/bold cyan]\n")

            health = tool.docker_health_check()

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Check", style="cyan")
            table.add_column("Status", style="white")

            status = health.get("status", "unknown")
            status_str = "[green]✓ HEALTHY[/green]" if status == "healthy" else "[red]✗ UNHEALTHY[/red]"

            table.add_row("Docker Status", status_str)
            table.add_row("Docker Installed", "[green]Yes[/green]" if health.get("docker_installed") else "[red]No[/red]")
            table.add_row("Docker Running", "[green]Yes[/green]" if health.get("docker_running") else "[red]No[/red]")

            if "containers" in health:
                table.add_row("Containers Running", str(health["containers"].get("running", 0)))
                table.add_row("Containers Total", str(health["containers"].get("total", 0)))

            console.print(table)
            console.print()

            if status != "healthy" and "error" in health:
                console.print(f"[red]Error: {health['error']}[/red]\n")
                return 1

        elif subcommand == "logs":
            container = args.container
            tail = getattr(args, "tail", 100)

            console.print(f"[bold cyan]Logs for {container} (last {tail} lines)[/bold cyan]\n")

            logs = tool.get_container_logs(container, tail=tail)

            console.print(logs)

        elif subcommand == "inventory":
            console.print("[bold cyan]Generating Docker Container Inventory...[/bold cyan]\n")
            success = tool.inventory()
            if not success:
                return 1

        elif subcommand == "login":
            registry_name = getattr(args, "registry", None)
            success = tool.login_registry(registry_name)
            if not success:
                return 1

        # Pass through other Docker-specific commands to the tool
        elif subcommand in ["validate", "backups", "rollback", "deploy", "restart", "sync"]:
            # These are existing DockerTool methods - call the tool method directly
            method_name = subcommand.replace("-", "_")
            if hasattr(tool, method_name):
                result = getattr(tool, method_name)()
                console.print(result)
            else:
                console.print(f"[bold red]Error:[/bold red] Method {method_name} not implemented")
                return 1

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


def _handle_nas(tool, subcommand: str, args, dry_run: bool) -> int:
    """Handle NAS tool subcommands."""
    try:
        if subcommand == "list":
            console.print("[bold cyan]NAS Systems[/bold cyan]\n")

            systems = tool.get_all_nas_metrics()

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Name", style="cyan")
            table.add_column("Type", style="white")
            table.add_column("IP", style="green")
            table.add_column("Status", style="white")
            table.add_column("Purpose", style="yellow")

            for system in systems:
                status = system.get("status", "unknown")
                if status == "healthy":
                    status_str = "[green]✓ HEALTHY[/green]"
                elif status == "degraded":
                    status_str = "[yellow]⚠ DEGRADED[/yellow]"
                elif status == "unreachable":
                    status_str = "[red]✗ UNREACHABLE[/red]"
                else:
                    status_str = "[dim]UNKNOWN[/dim]"

                table.add_row(
                    system.get("name", "N/A"),
                    system.get("type", "N/A").upper(),
                    system.get("ip", "N/A"),
                    status_str,
                    system.get("purpose", "N/A")
                )

            console.print(table)

            # Show issues if any
            for system in systems:
                if system.get("issues"):
                    console.print(f"\n[yellow]⚠ {system.get('name')}:[/yellow] {system.get('issues')}")

            console.print()

        elif subcommand == "metrics":
            system_id = args.system
            console.print(f"[bold cyan]NAS Metrics: {system_id}[/bold cyan]\n")

            all_systems = tool.get_all_nas_metrics()
            system = next((s for s in all_systems if s.get("system_id") == system_id), None)

            if not system:
                console.print(f"[bold red]Error:[/bold red] NAS system not found: {system_id}")
                return 1

            if not system.get("reachable"):
                console.print(f"[bold red]✗ System unreachable:[/bold red] {system.get('name')}")
                return 1

            table = Table(show_header=False)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="white")

            # Common metrics
            table.add_row("Name", system.get("name", "N/A"))
            table.add_row("Type", system.get("type", "N/A").upper())
            table.add_row("IP Address", system.get("ip", "N/A"))
            table.add_row("Purpose", system.get("purpose", "N/A"))
            table.add_row("Status", system.get("status", "unknown").upper())

            # Storage
            if "storage" in system:
                storage = system["storage"]
                table.add_row("", "")  # Spacer
                table.add_row("[bold]Storage[/bold]", "")
                table.add_row("Total", storage.get("total", "N/A"))
                table.add_row("Used", storage.get("used", "N/A"))
                table.add_row("Available", storage.get("available", "N/A"))
                table.add_row("Used %", f"{storage.get('used_percent', 0)}%")

            # Memory
            if "memory" in system:
                memory = system["memory"]
                table.add_row("", "")  # Spacer
                table.add_row("[bold]Memory[/bold]", "")
                if "total" in memory:
                    table.add_row("Total", memory.get("total", "N/A"))
                    table.add_row("Used", memory.get("used", "N/A"))
                elif "total_gb" in memory:
                    table.add_row("Total", f"{memory.get('total_gb', 0):.1f} GB")

            # Uptime & Load
            if "uptime" in system:
                table.add_row("", "")  # Spacer
                table.add_row("[bold]System[/bold]", "")
                table.add_row("Uptime", system["uptime"])

            if "load" in system:
                load = system["load"]
                table.add_row("Load (1m)", f"{load.get('1min', 0):.2f}")
                table.add_row("Load (5m)", f"{load.get('5min', 0):.2f}")
                table.add_row("Load (15m)", f"{load.get('15min', 0):.2f}")

            # Type-specific metrics
            if system.get("type") == "unraid" and "array" in system:
                array = system["array"]
                table.add_row("", "")  # Spacer
                table.add_row("[bold]Array Status[/bold]", "")
                for key, value in array.items():
                    table.add_row(key, value)

            if system.get("type") == "truenas" and "pools" in system:
                pools = system["pools"]
                table.add_row("", "")  # Spacer
                table.add_row("[bold]ZFS Pools[/bold]", "")
                for pool in pools:
                    health_color = "[green]" if pool["health"] == "ONLINE" else "[yellow]"
                    table.add_row(
                        f"  {pool['name']}",
                        f"{pool['size']} ({pool['cap']} used) - {health_color}{pool['health']}[/{health_color.strip('[')}]"
                    )

            console.print(table)
            console.print()

        elif subcommand == "health-check":
            console.print("[bold cyan]NAS Health Check[/bold cyan]\n")

            health = tool.health_check()

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("System", style="cyan")
            table.add_column("Reachable", style="white")
            table.add_column("Status", style="white")

            for system_id, check in health["checks"].items():
                reachable_str = "[green]✓[/green]" if check["reachable"] else "[red]✗[/red]"

                status = check["status"]
                if status == "healthy":
                    status_str = "[green]HEALTHY[/green]"
                elif status == "degraded":
                    status_str = "[yellow]DEGRADED[/yellow]"
                else:
                    status_str = "[red]UNREACHABLE[/red]"

                table.add_row(system_id, reachable_str, status_str)

            console.print(table)
            console.print(f"\n{health['message']}\n")

            if health["status"] != "healthy":
                return 1

        else:
            console.print(f"[bold red]Error:[/bold red] Unknown subcommand: {subcommand}")
            return 1

        return 0

    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        return 130

    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        if getattr(args, "verbose", False):
            console.print_exception()
        return 1


def _handle_proxmox(tool, subcommand: str, args, dry_run: bool) -> int:
    """Handle Proxmox tool subcommands."""
    try:
        if subcommand == "health-check":
            console.print("[bold cyan]Proxmox Tool Health Check[/bold cyan]\n")

            health = tool.health_check()

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Check", style="cyan")
            table.add_column("Status", style="white")

            for check_name, check_value in health["checks"].items():
                if isinstance(check_value, bool):
                    status_str = "[green]✓ PASS[/green]" if check_value else "[red]✗ FAIL[/red]"
                else:
                    status_str = str(check_value)
                table.add_row(check_name, status_str)

            console.print(table)

            status = health["status"]
            if status == "healthy":
                console.print(f"\n[bold green]✓ All checks passed[/bold green]")
            else:
                console.print(f"\n[bold red]✗ Health check failed[/bold red]")
                return 1

        elif subcommand == "usb-status":
            vm_id = args.vm_id
            console.print(f"[bold cyan]USB Status for VM {vm_id}[/bold cyan]\n")

            health = tool.check_usb_health(vm_id)

            # Summary
            status = health["status"]
            if status == "healthy":
                console.print(f"[bold green]✓ All {health['total_devices']} USB devices healthy[/bold green]\n")
            else:
                console.print(f"[bold yellow]⚠ {health['unhealthy_devices']} unhealthy device(s)[/bold yellow]\n")

            # Device table
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Device ID", style="cyan")
            table.add_column("Product", style="white")
            table.add_column("Speed", style="green")
            table.add_column("Port", style="yellow")
            table.add_column("Status", style="white")

            for device in health["devices"]:
                is_healthy = device.get("is_healthy", True)
                status_str = "[green]✓ OK[/green]" if is_healthy else "[red]✗ UNHEALTHY[/red]"

                table.add_row(
                    device.get("device_id", "N/A"),
                    device.get("product_name", "N/A"),
                    device.get("speed", "N/A"),
                    str(device.get("port", "N/A")),
                    status_str
                )

            console.print(table)

            # Show issues if any
            if health["issues"]:
                console.print("\n[bold yellow]Issues:[/bold yellow]")
                for issue in health["issues"]:
                    console.print(f"  • {issue['device_id']}: {issue['issue']}")
                console.print(f"\n[cyan]Run 'infra-toolkit proxmox usb-auto-fix {vm_id}' to attempt auto-repair[/cyan]")

            console.print()

        elif subcommand == "usb-reset":
            vm_id = args.vm_id
            device_id = args.device_id

            if dry_run:
                console.print(f"[bold yellow]DRY RUN MODE[/bold yellow] - No changes will be made\n")

            console.print(f"[bold cyan]Resetting USB device {device_id} on VM {vm_id}[/bold cyan]\n")

            success = tool.reset_usb_device(vm_id, device_id)

            if success:
                console.print(f"\n[bold green]✓ USB device {device_id} reset successfully[/bold green]")

                # Show new status
                console.print("\n[bold cyan]New USB Status:[/bold cyan]")
                health = tool.check_usb_health(vm_id)
                for device in health["devices"]:
                    if device["device_id"] == device_id:
                        is_healthy = device.get("is_healthy", True)
                        status_str = "[green]✓ OK[/green]" if is_healthy else "[red]✗ UNHEALTHY[/red]"
                        console.print(f"  {device_id}: {device['product_name']} @ {device['speed']} - {status_str}")
            else:
                console.print(f"\n[bold red]✗ Failed to reset USB device[/bold red]")
                return 1

        elif subcommand == "usb-auto-fix":
            vm_id = args.vm_id

            if dry_run:
                console.print(f"[bold yellow]DRY RUN MODE[/bold yellow] - No changes will be made\n")

            console.print(f"[bold cyan]Auto-fixing USB devices on VM {vm_id}[/bold cyan]\n")

            result = tool.auto_fix_usb(vm_id)

            status = result["status"]

            if status == "no_action_needed":
                console.print(f"[bold green]✓ {result['message']}[/bold green]")
                console.print(f"  Devices checked: {result['devices_checked']}")
            elif status == "fixed":
                console.print(f"[bold green]✓ All devices fixed![/bold green]")
                console.print(f"  Fixed: {', '.join(result['fixed_devices'])}")
            elif status == "partial":
                console.print(f"[bold yellow]⚠ Partial fix[/bold yellow]")
                console.print(f"  Fixed: {', '.join(result['fixed_devices'])}")
                console.print(f"  Failed: {', '.join(result['failed_devices'])}")
                return 1

            # Show final status
            if "new_health" in result:
                console.print("\n[bold cyan]Final USB Status:[/bold cyan]")
                for device in result["new_health"]["devices"]:
                    is_healthy = device.get("is_healthy", True)
                    status_str = "[green]✓[/green]" if is_healthy else "[red]✗[/red]"
                    console.print(f"  {status_str} {device['device_id']}: {device['product_name']} @ {device['speed']}")

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
        if getattr(args, "verbose", False):
            console.print_exception()
        return 1


def _handle_homeassistant(tool, subcommand: str, args, dry_run: bool) -> int:
    """Handle Home Assistant tool subcommands."""
    try:
        if subcommand == "status":
            console.print("[bold cyan]Home Assistant Status[/bold cyan]\n")

            # Get VM status
            vm_status = tool.get_vm_status()

            # VM Info Table
            table = Table(show_header=False)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")

            table.add_row("VM ID", str(tool.HA_CONFIG.vm_id))
            table.add_row("VM Name", tool.HA_CONFIG.vm_name)
            table.add_row("Proxmox Host", f"{tool.HA_CONFIG.proxmox_host} ({tool.HA_CONFIG.proxmox_ip})")

            vm_state = vm_status.get("status", "unknown")
            if vm_state == "running":
                state_str = "[green]running[/green]"
            elif vm_state == "stopped":
                state_str = "[red]stopped[/red]"
            else:
                state_str = f"[yellow]{vm_state}[/yellow]"
            table.add_row("VM Status", state_str)

            if vm_status.get("uptime"):
                uptime_str = vm_status["uptime"]
                if vm_status.get("long_uptime_warning"):
                    uptime_str = f"[yellow]{uptime_str} (consider restart)[/yellow]"
                table.add_row("Uptime", uptime_str)

            table.add_row("", "")
            table.add_row("[bold]Network[/bold]", "")
            table.add_row("HA IP", tool.HA_CONFIG.ha_ip)
            table.add_row("HA Port", str(tool.HA_CONFIG.ha_port))
            table.add_row("VLAN", f"{tool.HA_CONFIG.vlan} ({tool.HA_CONFIG.network_name})")
            table.add_row("External URL", f"https://{tool.HA_CONFIG.cloudflare_hostname}")

            console.print(table)

            # Service check
            service = tool.check_service_health()
            console.print(f"\n[bold]Service Status:[/bold] ", end="")
            if service["status"] == "healthy":
                console.print("[green]✓ HEALTHY[/green]")
            elif service["status"] == "degraded":
                console.print("[yellow]⚠ DEGRADED[/yellow]")
            else:
                console.print("[red]✗ UNHEALTHY[/red]")

            console.print()

        elif subcommand == "health-check":
            console.print("[bold cyan]Home Assistant Health Check[/bold cyan]\n")

            health = tool.health_check()

            # Summary
            status = health["status"]
            if status == "healthy":
                console.print(f"[bold green]✓ {health['message']}[/bold green]\n")
            elif status == "degraded":
                console.print(f"[bold yellow]⚠ {health['message']}[/bold yellow]\n")
            else:
                console.print(f"[bold red]✗ {health['message']}[/bold red]\n")

            # Checks table
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Check", style="cyan")
            table.add_column("Status", style="white")

            for check_name, check_result in health["checks"].items():
                status_str = "[green]✓ PASS[/green]" if check_result else "[red]✗ FAIL[/red]"
                # Make check name more readable
                display_name = check_name.replace("_", " ").title()
                table.add_row(display_name, status_str)

            console.print(table)

            # VM details
            vm = health.get("vm", {})
            if vm.get("long_uptime_warning"):
                console.print(f"\n[yellow]⚠ Long uptime warning:[/yellow] VM has been running for {vm.get('uptime', 'unknown')}")
                console.print("  Consider restarting to prevent resource exhaustion")

            # Return non-zero if unhealthy
            if status == "unhealthy":
                return 1

            console.print()

        elif subcommand == "start":
            if dry_run:
                console.print(f"[bold yellow]DRY RUN MODE[/bold yellow] - No changes will be made\n")

            console.print(f"[bold cyan]Starting Home Assistant VM...[/bold cyan]\n")

            result = tool.start_vm()

            if result["status"] == "success":
                console.print(f"[bold green]✓ {result['message']}[/bold green]")
            elif result["status"] == "dry_run":
                console.print(f"[yellow]{result['message']}[/yellow]")
            else:
                console.print(f"[bold red]✗ {result['message']}[/bold red]")
                return 1

        elif subcommand == "stop":
            force = getattr(args, "force", False)

            if dry_run:
                console.print(f"[bold yellow]DRY RUN MODE[/bold yellow] - No changes will be made\n")

            if force:
                console.print(f"[bold cyan]Force stopping Home Assistant VM...[/bold cyan]\n")
            else:
                console.print(f"[bold cyan]Stopping Home Assistant VM (graceful)...[/bold cyan]\n")

            result = tool.stop_vm(force=force)

            if result["status"] == "success":
                console.print(f"[bold green]✓ {result['message']}[/bold green]")
            elif result["status"] == "dry_run":
                console.print(f"[yellow]{result['message']}[/yellow]")
            else:
                console.print(f"[bold red]✗ {result['message']}[/bold red]")
                return 1

        elif subcommand == "restart":
            force = getattr(args, "force", False)
            no_wait = getattr(args, "no_wait", False)

            if dry_run:
                console.print(f"[bold yellow]DRY RUN MODE[/bold yellow] - No changes will be made\n")

            console.print(f"[bold cyan]Restarting Home Assistant VM...[/bold cyan]\n")

            result = tool.restart_vm(force=force, wait_for_service=not no_wait)

            if result["status"] == "success":
                console.print(f"[bold green]✓ {result['message']}[/bold green]")
                if "elapsed_seconds" in result:
                    console.print(f"  Elapsed time: {result['elapsed_seconds']}s")
            elif result["status"] == "partial":
                console.print(f"[bold yellow]⚠ {result['message']}[/bold yellow]")
                if "elapsed_seconds" in result:
                    console.print(f"  Elapsed time: {result['elapsed_seconds']}s")
                console.print("  Service may still be starting up - check again in a few minutes")
            elif result["status"] == "dry_run":
                console.print(f"[yellow]{result['message']}[/yellow]")
            else:
                console.print(f"[bold red]✗ {result['message']}[/bold red]")
                return 1

        elif subcommand == "tunnel-status":
            console.print("[bold cyan]Cloudflare Tunnel Status[/bold cyan]\n")

            tunnel = tool.check_cloudflare_tunnel()

            # Summary
            status = tunnel["status"]
            if status == "healthy":
                console.print(f"[bold green]✓ Tunnel healthy[/bold green]\n")
            elif status == "degraded":
                console.print(f"[bold yellow]⚠ Tunnel degraded[/bold yellow]\n")
            else:
                console.print(f"[bold red]✗ Tunnel unhealthy[/bold red]\n")

            # Details table
            table = Table(show_header=False)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")

            table.add_row("External URL", f"https://{tunnel['hostname']}")
            table.add_row("Tunnel Host", tunnel["tunnel_host"])
            table.add_row("Tunnel Container", tunnel["tunnel_container"])

            checks = tunnel["checks"]
            ext_status = "[green]✓ Accessible[/green]" if checks["external_accessible"] else "[red]✗ Not accessible[/red]"
            table.add_row("External Access", ext_status)

            if checks.get("external_status_code"):
                table.add_row("HTTP Status", str(checks["external_status_code"]))

            container_status = "[green]✓ Running[/green]" if checks["tunnel_container_running"] else "[red]✗ Not running[/red]"
            table.add_row("Container Status", container_status)

            console.print(table)

            if not checks["external_accessible"]:
                console.print(f"\n[yellow]Hint:[/yellow] Check tunnel logs with:")
                console.print(f"  ssh root@{tool.CLOUDFLARE_TUNNEL['host_ip']} \"docker logs --tail 50 {tunnel['tunnel_container']}\"")

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
        if getattr(args, "verbose", False):
            console.print_exception()
        return 1


def _handle_ups(tool, subcommand: str, args) -> int:
    """Handle UPS tool subcommands."""
    try:
        if subcommand == "status":
            console.print("[bold cyan]UPS Status[/bold cyan]\n")

            data = tool.status()

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Metric", style="cyan")
            table.add_column("Smart-UPS (Servers)", style="white")
            table.add_column("BE600M1 (Network)", style="white")

            smart = data["smart_ups"]
            be600 = data["be600m1"]

            # Online status
            smart_online = "[green]ONLINE[/green]" if smart["online"] else "[red]OFFLINE[/red]"
            be600_online = "[green]ONLINE[/green]" if be600["online"] else "[red]OFFLINE[/red]"
            table.add_row("Status", smart_online, be600_online)

            # Battery
            smart_batt = f"{smart['battery_pct']:.1f}%" if smart["battery_pct"] is not None else "N/A"
            be600_batt = f"{be600['battery_pct']:.1f}%" if be600["battery_pct"] is not None else "N/A"
            table.add_row("Battery", smart_batt, be600_batt)

            # Runtime
            def fmt_runtime(s):
                if s is None:
                    return "N/A"
                mins = int(s) // 60
                secs = int(s) % 60
                return f"{mins}m {secs}s"

            table.add_row("Runtime", fmt_runtime(smart["runtime_s"]), fmt_runtime(be600["runtime_s"]))

            # Load
            smart_load = f"{smart['load_pct']:.1f}%" if smart["load_pct"] is not None else "N/A"
            be600_load = f"{be600['load_pct']:.1f}%" if be600["load_pct"] is not None else "N/A"
            table.add_row("Load", smart_load, be600_load)

            # Input voltage
            smart_inv = f"{smart['input_v']:.1f}V" if smart["input_v"] is not None else "N/A"
            be600_inv = f"{be600['input_v']:.1f}V" if be600["input_v"] is not None else "N/A"
            table.add_row("Input Voltage", smart_inv, be600_inv)

            # Smart-UPS only metrics
            smart_outv = f"{smart['output_v']:.1f}V" if smart["output_v"] is not None else "N/A"
            table.add_row("Output Voltage", smart_outv, "---")

            smart_temp = f"{smart['temp_c']:.1f}C" if smart["temp_c"] is not None else "N/A"
            table.add_row("Battery Temp", smart_temp, "---")

            smart_eff = f"{smart['efficiency_pct']:.1f}%" if smart["efficiency_pct"] is not None else "N/A"
            table.add_row("Efficiency", smart_eff, "---")

            smart_energy = f"{smart['energy_kwh']:.3f} kWh" if smart["energy_kwh"] is not None else "N/A"
            table.add_row("Energy (total)", smart_energy, "---")

            console.print(table)
            console.print()

        elif subcommand == "history":
            duration = getattr(args, "duration", "1h")
            console.print(f"[bold cyan]UPS History ({duration})[/bold cyan]\n")

            data = tool.history(duration)

            for ups_name, label in [("smart_ups", "Smart-UPS (Servers)"), ("be600m1", "BE600M1 (Network)")]:
                ups_hist = data.get(ups_name, {})
                if not ups_hist:
                    console.print(f"[yellow]{label}: No data available[/yellow]\n")
                    continue

                console.print(f"[bold]{label}[/bold]")
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Metric", style="cyan")
                table.add_column("Min", style="green")
                table.add_column("Max", style="red")
                table.add_column("Avg", style="yellow")
                table.add_column("Samples", style="dim")

                for metric_name, stats in ups_hist.items():
                    table.add_row(
                        metric_name,
                        str(stats["min"]),
                        str(stats["max"]),
                        str(stats["avg"]),
                        str(stats["samples"]),
                    )

                console.print(table)
                console.print()

        elif subcommand == "energy":
            console.print("[bold cyan]Energy Consumption (Smart-UPS)[/bold cyan]\n")

            data = tool.energy()

            table = Table(show_header=False)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="white")

            daily = f"{data['daily_kwh']:.3f} kWh" if data["daily_kwh"] is not None else "N/A"
            weekly = f"{data['weekly_kwh']:.3f} kWh" if data["weekly_kwh"] is not None else "N/A"
            watts = f"{data['current_watts']:.1f} W" if data["current_watts"] is not None else "N/A"

            table.add_row("Current Draw", watts)
            table.add_row("Last 24h", daily)
            table.add_row("Last 7d", weekly)

            console.print(table)
            console.print()

        elif subcommand == "health-check":
            console.print("[bold cyan]UPS Health Check (Prometheus)[/bold cyan]\n")

            result = tool.health_check()

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Check", style="cyan")
            table.add_column("Status", style="white")

            for check_name, check_result in result["checks"].items():
                if isinstance(check_result, bool):
                    status_str = "[green]PASS[/green]" if check_result else "[red]FAIL[/red]"
                    table.add_row(check_name, status_str)

            console.print(table)

            if result["status"] == "healthy":
                console.print(f"\n[bold green]Prometheus reachable at {tool.prom_url}[/bold green]")
            else:
                console.print(f"\n[bold red]Cannot reach Prometheus[/bold red]")
                console.print(f"  {result['message']}")
                return 1

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
        if getattr(args, "verbose", False):
            console.print_exception()
        return 1


def _handle_protonmail(tool, subcommand: str, args) -> int:
    """Handle ProtonMail tool subcommands."""
    try:
        if subcommand == "test":
            smtp_only = getattr(args, "smtp", False)
            imap_only = getattr(args, "imap", False)
            send_test = getattr(args, "send_test", False)
            skip_container = getattr(args, "no_container_check", False)
            test_both = not smtp_only and not imap_only

            console.print("[bold cyan]ProtonMail Bridge Connectivity Test[/bold cyan]\n")
            console.print(f"  Host: {tool.host}")
            console.print(f"  SMTP Port: {tool.smtp_port}")
            console.print(f"  IMAP Port: {tool.imap_port}")
            console.print(f"  Username: {tool.username}\n")

            all_passed = True

            # Container check
            if not skip_container:
                console.print("[cyan]Checking Docker container...[/cyan]")
                ok, msg = tool.check_container()
                if ok:
                    console.print(f"  [green]PASS[/green] {msg}")
                else:
                    console.print(f"  [red]FAIL[/red] {msg}")
                    console.print("[red]Fix container issues before testing protocols.[/red]")
                    return 1
                console.print()

            # SMTP
            if smtp_only or test_both:
                console.print("[cyan]Testing SMTP...[/cyan]")
                ok, msg = tool.test_smtp(send_test=send_test)
                if ok:
                    console.print(f"  [green]PASS[/green] {msg}")
                else:
                    console.print(f"  [red]FAIL[/red] {msg}")
                    all_passed = False
                console.print()

            # IMAP
            if imap_only or test_both:
                console.print("[cyan]Testing IMAP...[/cyan]")
                ok, msg = tool.test_imap()
                if ok:
                    console.print(f"  [green]PASS[/green] {msg}")
                else:
                    console.print(f"  [red]FAIL[/red] {msg}")
                    all_passed = False
                console.print()

            if all_passed:
                console.print("[bold green]All tests passed[/bold green]")
            else:
                console.print("[bold red]Some tests failed[/bold red]")
                return 1

        elif subcommand == "health-check":
            console.print("[bold cyan]ProtonMail Bridge Health Check[/bold cyan]\n")

            result = tool.health_check()

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Check", style="cyan")
            table.add_column("Status", style="white")
            table.add_column("Details", style="white")

            for check_name, check_data in result["checks"].items():
                status_str = (
                    "[green]PASS[/green]"
                    if check_data["status"]
                    else "[red]FAIL[/red]"
                )
                table.add_row(check_name, status_str, check_data["message"])

            console.print(table)

            if result["status"] == "healthy":
                console.print(f"\n[bold green]{result['message']}[/bold green]")
            else:
                console.print(f"\n[bold red]{result['message']}[/bold red]")
                return 1

        else:
            console.print(f"[bold red]Error:[/bold red] Unknown subcommand: {subcommand}")
            return 1

        return 0

    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        return 130

    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        if getattr(args, "verbose", False):
            console.print_exception()
        return 1


def _load_tool_config() -> dict:
    """Load configuration from config.yaml for tools that need it."""
    import yaml
    config_paths = [
        Path("/app/config.yaml"),
        Path("/mnt/tank/faststorage/general/repo/ai-config/config.yaml"),
        Path.home() / ".config" / "infrastructure-toolkit" / "config.yaml",
    ]
    for config_path in config_paths:
        if config_path.exists():
            with open(config_path, "r") as f:
                return yaml.safe_load(f) or {}
    return {}


def _handle_uptime_kuma(tool, subcommand: str, args) -> int:
    """Handle Uptime Kuma tool subcommands."""
    try:
        if subcommand == "export":
            console.print("[bold cyan]Exporting Uptime Kuma monitors...[/bold cyan]\n")
            success = tool.export_monitors()
            if success:
                console.print(f"\n[bold green]Export complete[/bold green]")
            else:
                console.print(f"\n[bold red]Export failed[/bold red]")
                return 1

        elif subcommand == "backup":
            console.print("[bold cyan]Backing up Uptime Kuma database...[/bold cyan]\n")
            success = tool.backup()
            if success:
                console.print(f"\n[bold green]Backup complete[/bold green]")
            else:
                console.print(f"\n[bold red]Backup failed[/bold red]")
                return 1

        elif subcommand == "health-check":
            console.print("[bold cyan]Uptime Kuma Health Check[/bold cyan]\n")

            result = tool.health_check()

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Check", style="cyan")
            table.add_column("Status", style="white")

            for check_name, check_result in result["checks"].items():
                if isinstance(check_result, bool):
                    status_str = "[green]PASS[/green]" if check_result else "[red]FAIL[/red]"
                    table.add_row(check_name, status_str)

            console.print(table)

            if result["status"] == "healthy":
                console.print(f"\n[bold green]{result['message']}[/bold green]")
            else:
                console.print(f"\n[bold red]{result['message']}[/bold red]")
                return 1

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
        if getattr(args, "verbose", False):
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
