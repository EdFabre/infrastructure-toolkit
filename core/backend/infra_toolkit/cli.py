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


# Tool registry
AVAILABLE_TOOLS: Dict[str, Type[BaseTool]] = {
    "cloudflare": CloudflareTool,
    "docker": DockerTool,
    "network": NetworkTool,
    "performance": PerformanceTool,
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
