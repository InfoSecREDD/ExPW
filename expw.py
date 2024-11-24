import nmap
import openai
import argparse
import os
import sys
import subprocess
import re
from dotenv import load_dotenv
import tempfile
import shutil
import json
import sysconfig
import ast
from rich import print
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.tree import Tree
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text
from rich.progress import track
from rich.status import Status
from rich.align import Align
from datetime import datetime

# Load environment variables from .env file
load_dotenv()

# Initialize OpenAI client
from openai import OpenAI
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

if not client:
    print("[bold red]Error:[/bold red] OpenAI API key not set. Please set the [bold]OPENAI_API_KEY[/bold] variable in your .env file.")
    sys.exit(1)

# Initialize Nmap object
nm = nmap.PortScanner()

# Cache for exploit results
exploit_cache = {}

def display_banner():
    banner_text = """
 ▗▄▄▄▖▄   ▄ ▄ ▗▄▄▖▄ ▗▖ ▗▖▄ 
▐▌    ▀▄▀    ▐▌ ▐▌ ▐▌ ▐▌  
▐▛▀▀▘▄▀ ▀▄   ▐▛▀▘  ▐▌ ▐▌  
▐▙▄▄▖        ▐▌    ▐▙█▟▌  
             
    """
    console = Console()
    
    # Create a Text object with center justification
    banner_text_obj = Text(banner_text, style="bold cyan", justify="center")

    # Wrap the Text object in an Align object to center it within the panel
    aligned_banner = Align.center(banner_text_obj)
    
    banner = Panel(
        aligned_banner,
        title="(Ex)ploitDB (P)oC (W)riter",
        subtitle="Developed by [bold red]InfoSecREDD[/bold red]  -  Version 1.0",
        border_style="bright_cyan",
        padding=(1, 2) 
    )
    console.print(banner)

def port_scan(target_ip, port_list, protocol):
    ports = ",".join(map(str, port_list))
    try:
        # Include service version detection with -sV and enable aggressive version detection
        arguments = f'-sS -sV --version-all -p{ports} -T4 --open'
        if protocol == 'udp':
            arguments += ' -sU'
        console = Console()
        with console.status(f"[bold green]Scanning {target_ip}...[/bold green]"):
            nm.scan(target_ip, arguments=arguments)
        open_ports = []
        if target_ip in nm.all_hosts():
            for proto in nm[target_ip].all_protocols():
                if proto == protocol:
                    lport = nm[target_ip][proto].keys()
                    for port in lport:
                        service_info = nm[target_ip][proto][port]
                        service = service_info.get('name', '')
                        product = service_info.get('product', '')
                        version = service_info.get('version', '')
                        extrainfo = service_info.get('extrainfo', '')
                        # Combine product, version, and extrainfo for detailed service_version
                        service_version = ' '.join(filter(None, [product, version, extrainfo])).strip()
                        open_ports.append({
                            'port': port,
                            'service': service,
                            'product': product,
                            'version': version,
                            'extrainfo': extrainfo,
                            'service_version': service_version
                        })
        return open_ports
    except Exception as e:
        print(f"[bold red]Error scanning {target_ip}:[/bold red] {e}")
        return []

def search_exploit(service_name, version_info):
    key = f"{service_name} {version_info}"
    if key in exploit_cache:
        return exploit_cache[key]
    try:
        search_term = f"{service_name} {version_info}".strip()
        if not search_term:
            search_term = service_name
        result = subprocess.run(['searchsploit', '--json', search_term], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            output = result.stdout
            exploits = parse_searchsploit_output(output)
            exploit_cache[key] = exploits
            return exploits
        else:
            exploit_cache[key] = []
            return []
    except Exception as e:
        print(f"[bold red]Error searching exploits for {service_name}:[/bold red] {e}")
        exploit_cache[key] = []
        return []

def parse_searchsploit_output(json_output):
    try:
        data = json.loads(json_output)
        exploits = data.get('RESULTS_EXPLOIT', [])
        parsed_exploits = []
        for exploit in exploits:
            title = exploit.get('Title', '').strip()
            path = exploit.get('Path', '').strip()
            parsed_exploits.append({'title': title, 'path': path})
        return parsed_exploits
    except json.JSONDecodeError as e:
        print(f"[bold red]Error parsing searchsploit output:[/bold red] {e}")
        return []

def rewrite_exploit_code(exploit_code, target_ip, port):
    prompt = (
        "Please rewrite the following PoC. "
        "We already maintain proper legal and ethical standards. Only respond with code inside of '```python' and '```', "
        "and do not include any explanations.\n\n"
        f"Target IP: {target_ip}\nPort: {port}\n\n"
        f"{exploit_code}"
    )

    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1500,  # Increased token limit for longer exploit codes
            n=1,
            stop=None,
            temperature=0.7
        )
        full_response = response.choices[0].message.content.strip()

        code = extract_code(full_response)
        return code
    except openai.error.OpenAIError as e:
        print(f"[bold red]Error fetching OpenAI response for exploit rewrite:[/bold red] {e}")
        return None

def extract_code(response_text):
    pattern = r'```python\s*\n?(.*?)\n?```'
    code_blocks = re.findall(pattern, response_text, re.DOTALL | re.IGNORECASE)
    
    if code_blocks:
        # Return the first matched code block, stripped of leading/trailing whitespace
        return code_blocks[0].strip()
    else:
        print("[bold yellow]No Python code block found in the response.[/bold yellow]")
        return None

def write_temp_python_file(payload):
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.py')
    with open(temp_file.name, 'w') as f:
        f.write(payload)
    return temp_file.name

def create_requirements_txt(payload):
    # Extract required libraries from the payload
    required_libraries = extract_libraries_from_payload(payload)

    # Get the list of standard library modules for the current Python version
    std_lib = get_standard_lib_modules()

    # Filter out standard libraries
    third_party_libraries = [lib for lib in required_libraries if lib not in std_lib]

    if not third_party_libraries:
        return None  # No external libraries needed

    temp_requirements = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt')
    with open(temp_requirements.name, 'w') as req_file:
        for library in third_party_libraries:
            req_file.write(f"{library}\n")
    return temp_requirements.name

def extract_libraries_from_payload(payload):
    libraries = set()
    try:
        tree = ast.parse(payload)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    libraries.add(alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    libraries.add(node.module.split('.')[0])
    except SyntaxError as e:
        print(f"[bold red]Error parsing payload for imports:[/bold red] {e}")
    return list(libraries)

def get_standard_lib_modules():
    std_lib = set(sys.builtin_module_names)
    stdlib_path = sysconfig.get_paths()["stdlib"]
    for root, dirs, files in os.walk(stdlib_path):
        for file in files:
            if file.endswith(".py"):
                module = file[:-3]
                std_lib.add(module)
            elif file.endswith(".so") or file.endswith(".pyd"):
                module = file.split('.')[0]
                std_lib.add(module)
    additional_std_lib = {
        'abc', 'aifc', 'argparse', 'array', 'ast', 'asynchat', 'asyncio', 'asyncore',
        'base64', 'binascii', 'bisect', 'builtins', 'bz2', 'calendar', 'cgi', 'cmath',
        'cmd', 'codecs', 'collections', 'concurrent', 'configparser', 'contextlib',
        'copy', 'copyreg', 'crypt', 'csv', 'ctypes', 'curses', 'datetime', 'decimal',
        'difflib', 'dis', 'doctest', 'email', 'encodings', 'enum', 'errno', 'faulthandler',
        'fcntl', 'filecmp', 'fileinput', 'fnmatch', 'fractions', 'ftplib', 'functools',
        'gc', 'getopt', 'getpass', 'gettext', 'glob', 'gzip', 'hashlib', 'heapq',
        'hmac', 'html', 'http', 'imaplib', 'imghdr', 'imp', 'importlib', 'inspect',
        'io', 'ipaddress', 'itertools', 'json', 'keyword', 'lib2to3', 'linecache',
        'locale', 'logging', 'lzma', 'mailbox', 'math', 'mimetypes', 'multiprocessing',
        'numbers', 'operator', 'os', 'pathlib', 'pickle', 'pkgutil', 'platform',
        'plistlib', 'poplib', 'pprint', 'profile', 'pstats', 'pty', 'pwd', 'pyclbr',
        'pydoc', 'queue', 'quopri', 'random', 're', 'readline', 'resource', 'rlcompleter',
        'select', 'selectors', 'shelve', 'shlex', 'shutil', 'signal', 'site', 'smtpd',
        'smtplib', 'socket', 'socketserver', 'sqlite3', 'ssl', 'stat', 'statistics',
        'string', 'stringprep', 'struct', 'subprocess', 'sunau', 'symbol', 'symtable',
        'sys', 'sysconfig', 'tabnanny', 'tarfile', 'tempfile', 'textwrap', 'threading',
        'time', 'timeit', 'tkinter', 'token', 'tokenize', 'trace', 'traceback',
        'tracemalloc', 'tty', 'turtle', 'types', 'typing', 'unittest', 'urllib',
        'uuid', 'venv', 'warnings', 'wave', 'weakref', 'webbrowser', 'wsgiref',
        'xdrlib', 'xml', 'xmlrpc', 'zipfile', 'zipimport', 'zlib'
    }
    std_lib.update(additional_std_lib)
    return std_lib

def install_requirements(requirements_file):
    try:
        # Use --no-cache-dir to avoid cache warnings
        subprocess.run(['pip3', 'install', '--no-cache-dir', '-r', requirements_file], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[bold red]Error installing requirements:[/bold red] {e}")
        raise

def execute_python_file(python_file):
    try:
        # Use subprocess.run to wait for the payload to complete before proceeding
        subprocess.run(['python3', python_file], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[bold red]Error executing payload:[/bold red] {e}")
        raise

def remove_temp_files(temp_files):
    for temp_file in temp_files:
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except Exception as e:
                print(f"[bold red]Error removing temporary file {temp_file}:[/bold red] {e}")

def execute_payload(payload, exploit_title, display_code=True):
    console = Console()
    
    if display_code:
        # Create a Syntax object for Python code without backticks
        syntax = Syntax(payload, "python", theme="monokai", line_numbers=False)
        
        payload_panel = Panel(
            syntax,
            title=f"💻 Payload for '{exploit_title}'",
            subtitle="[italic]Generated by OpenAI[/italic]",
            border_style="green",
            padding=(1, 2)  # Correct: Integer padding
        )
        
        console.print(payload_panel)
    
    # Create temp Python file for the payload
    temp_python_file = write_temp_python_file(payload)
    
    # Generate requirements.txt
    temp_requirements_file = create_requirements_txt(payload)
    
    try:
        if temp_requirements_file:
            # Install required libraries
            console.print("[bold green]Installing required libraries...[/bold green]")
            install_requirements(temp_requirements_file)
        else:
            console.print("[bold green]No external libraries to install.[/bold green]")

        # Execute the payload and wait for it to complete
        console.print(f"[bold cyan]Executing payload from {temp_python_file}...[/bold cyan]\n")
        execute_python_file(temp_python_file)
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Error during payload execution:[/bold red] {e}")
    finally:
        if not display_code:
            save_response = Confirm.ask("Do you want to save the generated payload?")
            if save_response:
                # Write the payload to 'pocs' directory with base filename <=10 characters
                pocs_dir = os.path.join(os.getcwd(), "pocs")
                os.makedirs(pocs_dir, exist_ok=True)

                # Sanitize exploit title for filename and limit base name to 10 characters
                sanitized_title = re.sub(r'[^A-Za-z0-9_\- ]', '', exploit_title).replace(" ", "_")[:10]
                timestamp = datetime.now().strftime("%m%d%y")  # MMDDYY format
                filename = f"{sanitized_title}_{timestamp}.py"
                file_path = os.path.join(pocs_dir, filename)

                try:
                    with open(file_path, 'w') as f:
                        f.write(payload)
                    console.print(f"[bold green]Payload saved to {file_path}.[/bold green]\n")
                except Exception as e:
                    console.print(f"[bold red]Error saving payload to file:[/bold red] {e}\n")
        
        # Clean up temp files after execution
        console.print("[bold green]Cleaning up temporary files...[/bold green]")
        remove_temp_files([temp_python_file, temp_requirements_file])
        console.print("[bold green]Cleanup complete.[/bold green]\n")

def format_ports(port_list):
    if not port_list:
        return ""
    
    sorted_ports = sorted(port_list)
    ranges = []
    start = end = sorted_ports[0]
    
    for port in sorted_ports[1:]:
        if port == end + 1:
            end = port
        else:
            if start == end:
                ranges.append(f"{start}")
            else:
                ranges.append(f"{start}-{end}")
            start = end = port
    
    if start == end:
        ranges.append(f"{start}")
    else:
        ranges.append(f"{start}-{end}")
    
    return ', '.join(ranges)

def main(target_ip, ports, protocol, skipports):
    display_banner()
    console = Console()

    port_list = []
    for port_entry in ports:
        if '-' in port_entry:
            try:
                start_port, end_port = map(int, port_entry.split('-'))
                if start_port < 0 or end_port > 65535 or start_port > end_port:
                    console.print(f"[bold yellow]Invalid port range:[/bold yellow] {port_entry}. Ports must be between 0 and 65535.")
                    continue
                port_list.extend(range(start_port, end_port + 1))
            except ValueError:
                console.print(f"[bold yellow]Invalid port range format:[/bold yellow] {port_entry}. Skipping.")
        else:
            try:
                single_port = int(port_entry)
                if single_port < 0 or single_port > 65535:
                    console.print(f"[bold yellow]Invalid port number:[/bold yellow] {single_port}. Ports must be between 0 and 65535.")
                    continue
                port_list.append(single_port)
            except ValueError:
                console.print(f"[bold yellow]Invalid port number:[/bold yellow] {port_entry}. Skipping.")

    # Remove duplicates and sort
    port_list = sorted(list(set(port_list)))

    # Process skipports
    if skipports:
        skip_port_list = []
        for skip_entry in skipports:
            if '-' in skip_entry:
                try:
                    skip_start, skip_end = map(int, skip_entry.split('-'))
                    if skip_start < 0 or skip_end > 65535 or skip_start > skip_end:
                        console.print(f"[bold yellow]Invalid skip port range:[/bold yellow] {skip_entry}. Ports must be between 0 and 65535.")
                        continue
                    skip_port_list.extend(range(skip_start, skip_end + 1))
                except ValueError:
                    console.print(f"[bold yellow]Invalid skip port range format:[/bold yellow] {skip_entry}. Skipping.")
            else:
                try:
                    skip_port = int(skip_entry)
                    if skip_port < 0 or skip_port > 65535:
                        console.print(f"[bold yellow]Invalid skip port number:[/bold yellow] {skip_port}. Ports must be between 0 and 65535.")
                        continue
                    skip_port_list.append(skip_port)
                except ValueError:
                    console.print(f"[bold yellow]Invalid skip port number:[/bold yellow] {skip_entry}. Skipping.")

        # Remove duplicates and sort
        skip_port_list = sorted(list(set(skip_port_list)))

        # Exclude skipports from port_list
        original_port_count = len(port_list)
        port_list = [port for port in port_list if port not in skip_port_list]
        skipped_count = original_port_count - len(port_list)
        console.print(f"[bold yellow]Skipped {skipped_count} port(s) as per --skipports option.[/bold yellow]\n")

    if not port_list:
        console.print("[bold red]No valid ports to scan after applying skip ports. Exiting.[/bold red]")
        return

    # Display the list of ports to be scanned
    formatted_ports = format_ports(port_list)
    console.print(f"[bold white] -> Port(s) to be scanned: [bold yellow]{formatted_ports}[/bold yellow]\n")

    console.print(f"[bold blue]Scanning [bold white]{len(port_list)}[/bold white] port(s) on [bold yellow]{target_ip}[/bold yellow] using {protocol.upper()} protocol...[/bold blue]\n")
    open_ports = port_scan(target_ip, port_list, protocol)

    if not open_ports:
        console.print(f"[bold yellow]No open {protocol.upper()} ports found on {target_ip} in the specified range.[/bold yellow]\n")
        return

    for port_info in open_ports:
        port = port_info['port']
        service = port_info['service']
        service_version = port_info['service_version'] if port_info['service_version'] else "Unknown Service"

        # Search for exploits before deciding to print port information
        exploits = search_exploit(service, service_version)
        if exploits:
            # Display Processing Message only if exploits are found
            processing_text = Text(f"Searching ExploitDB - Port {port} ({service}/{service_version})", style="bold green")
            processing_panel = Panel(
                processing_text,
                title="🔍 [bold white]Processing Port[/bold white]",
                border_style="green",
                padding=(1, 1)
            )
            console.print(processing_panel)

            scan_tree = Tree(f":desktop_computer:  [bold green]Scan Results for [bold yellow]{target_ip}[/bold yellow][/bold green]")
            port_branch = scan_tree.add(f":key: [bold cyan]Port {port}[/bold cyan] ([italic]{service_version}[/italic])")
            exploits_branch = port_branch.add(f":mag_right: [bold]Exploits Found[/bold]")

            for idx, exploit in enumerate(exploits, start=1):
                exploits_branch.add(f"[{idx}] {exploit['title']}")

            console.print(scan_tree)

            for exploit in exploits:
                user_input = Confirm.ask(f"\nDo you want to generate a payload for '[italic]{exploit['title']}[/italic]'?")

                if user_input:
                    exploit_path = exploit['path']
                    try:
                        with open(exploit_path, 'r', encoding='utf-8', errors='ignore') as file:
                            exploit_code = file.read()
                        console.print(f"[bold green]Successfully read exploit code from {exploit_path}.[/bold green]")
                    except Exception as e:
                        console.print(f"[bold red]Error reading exploit file at {exploit_path}:[/bold red] {e}")
                        continue  # Skip to the next exploit

                    rewritten_payload = rewrite_exploit_code(exploit_code, target_ip, port)
                    if rewritten_payload:
                        console.print(f"\n[bold blue]Generated payload for exploit '{exploit['title']}':[/bold blue]")
                        payload_panel = Panel(
                            Syntax(rewritten_payload, "python", theme="monokai", line_numbers=False),
                            title=f"💻 Payload for '{exploit['title']}'",
                            subtitle="[italic]Generated by OpenAI[/italic]",
                            border_style="green",
                            padding=(1, 2)  # Correct: Integer padding
                        )
                        console.print(payload_panel)

                        warning_message = "⚠️  WARNING!!: The generated code MAY require further modifications to function as intended. Please review and adjust as necessary."
                        warning_panel = Panel(
                            warning_message,
                            title="WARNING!",
                            subtitle="",
                            border_style="red",
                            style="bold red",
                            expand=False,
                            padding=(1, 2)  # Correct: Integer padding
                        )
                        console.print(warning_panel)

                        action = Prompt.ask(
                            "Choose an action - [bold][W][/bold]rite, [bold][R][/bold]un, [bold][C][/bold]ancel",
                            default="R"
                        ).strip().upper()

                        if action not in ["W", "R", "C"]:
                            console.print("[bold yellow]Invalid input. Defaulting to 'Run'.[/bold yellow]\n")
                            action = "R"

                        if action == "W":
                            # Write the payload to 'pocs' directory with base filename <=10 characters
                            pocs_dir = os.path.join(os.getcwd(), "pocs")
                            os.makedirs(pocs_dir, exist_ok=True)

                            # Sanitize exploit title for filename and limit base name to 10 characters
                            sanitized_title = re.sub(r'[^A-Za-z0-9_\- ]', '', exploit['title']).replace(" ", "_")[:10]
                            timestamp = datetime.now().strftime("%m%d%y")  # MMDDYY format
                            filename = f"{sanitized_title}_{timestamp}.py"
                            file_path = os.path.join(pocs_dir, filename)

                            try:
                                with open(file_path, 'w') as f:
                                    f.write(rewritten_payload)
                                console.print(f"[bold green]Payload written to {file_path}.[/bold green]\n")
                            except Exception as e:
                                console.print(f"[bold red]Error writing payload to file:[/bold red] {e}\n")

                        elif action == "R":
                            execute_payload(rewritten_payload, exploit['title'], display_code=False)

                        elif action == "C":
                            console.print("[bold yellow]Action canceled by the user.[/bold yellow]\n")
                    else:
                        console.print("[bold red]Failed to generate payload.[/bold red]\n")
                else:
                    console.print(f"[bold yellow]Skipped exploit '{exploit['title']}'.[/bold yellow]\n")
        else:
            continue  # Move to the next port without printing

    console.print("[bold green]Script Complete.[/bold green]")

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="Port scan, search exploits, and generate payloads.")
        parser.add_argument('target_ip', help="Target IP address to scan.")
        parser.add_argument('--ports', '-p', type=str, nargs='+', default=['1-1024'], help="Port range(s) or single port(s) to scan (e.g., 80, 443, 1-65535).")
        parser.add_argument('--protocol', choices=['tcp', 'udp'], default='tcp', help="Protocol to scan (default: tcp).")
        parser.add_argument('--skipports', '-s', type=str, nargs='+', default=[], help="Port(s) or port range(s) to skip (e.g., 81, 88-89).")

        args = parser.parse_args()

        main(args.target_ip, args.ports, args.protocol, args.skipports)
    except KeyboardInterrupt:
        console = Console()
        console.print("\n[bold yellow]Script interrupted by user. Exiting gracefully...[/bold yellow]")
        sys.exit(0)
