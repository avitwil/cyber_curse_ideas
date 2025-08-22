#!/usr/bin/env python3
import os, sys, argparse, shutil, re, subprocess, venv, tempfile
from pathlib import Path
from colorama import Fore, init
import pyfiglet
import tarfile

init(autoreset=True)

DEBIAN_PACKAGE_MAP = {
    "requests": "python3-requests",
    "bs4": "python3-bs4",
    "beautifulsoup4": "python3-bs4",
    "PIL": "python3-pil",
    "Pillow": "python3-pil",
    "numpy": "python3-numpy",
    "pandas": "python3-pandas",
    "matplotlib": "python3-matplotlib",
    "scipy": "python3-scipy",
    "flask": "python3-flask",
    "django": "python3-django",
    "pyyaml": "python3-yaml",
    "cryptography": "python3-cryptography",
    "colorama": "python3-colorama",
    "pyfiglet": "python3-pyfiglet",
    "pytest": "python3-pytest",
    "sqlalchemy": "python3-sqlalchemy",
    "lxml": "python3-lxml",
    "tqdm": "python3-tqdm"
}

BUILTIN_MODULES = {
    "sys","os","shutil","subprocess","argparse","pathlib",
    "re","tarfile","time","math","json","logging","glob","io"
}

def print_logo():
    print(Fore.BLUE + pyfiglet.figlet_format("Twil-Industries", font="slant"))
    print(Fore.CYAN + "================= Presents to you =================\n")
    print(Fore.RED + pyfiglet.figlet_format(" Py2Deb v2", font="slant"))
    print(Fore.GREEN + "================= Avi Twil (c) =================\n")

def help_menu():
    print(Fore.YELLOW + "USAGE: " + Fore.CYAN +
          "py2deb <python_file> -cn <creator_name> -email <creator_email> --command <command_name> [options]\n")
    print(Fore.MAGENTA + "Options:")
    print(Fore.YELLOW + "  <python_file>         " + Fore.WHITE + "Python file to package (required)")
    print(Fore.YELLOW + "  -cn <creator_name>    " + Fore.WHITE + "Name of the package creator (required)")
    print(Fore.YELLOW + "  -email <creator_email>" + Fore.WHITE + "Email of the creator (required)")
    print(Fore.YELLOW + "  --command <name>      " + Fore.WHITE + "Command name for the installed executable (required)")
    print(Fore.YELLOW + "  --sudo                " + Fore.WHITE + "Add 'sudo' to package dependencies")
    print(Fore.YELLOW + "  --setup               " + Fore.WHITE + "Create a setup script alongside the DEB")
    print(Fore.YELLOW + "  --tar-gz              " + Fore.WHITE + "Create a tar.gz archive containing DEB and setup script")
    print(Fore.YELLOW + "  --bin                 " + Fore.WHITE + "Compile standalone binary with dependencies included")
    print(Fore.YELLOW + "  -man, --man_page <file>" + Fore.WHITE + "Add man page for the command")
    print(Fore.YELLOW + "  -h, --help            " + Fore.WHITE + "Show this help message and exit\n")

def parse_python_dependencies(py_file):
    deps = set()
    with open(py_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            m1 = re.match(r"import\s+([a-zA-Z0-9_]+)", line)
            m2 = re.match(r"from\s+([a-zA-Z0-9_]+)\s+import", line)
            for m in (m1, m2):
                if m:
                    mod = m.group(1)
                    if mod not in BUILTIN_MODULES:
                        deps.add(mod)
    return sorted(deps)

def create_deb_structure(app_name):
    build_dir = Path(f"{app_name}_deb_build")
    if build_dir.exists():
        shutil.rmtree(build_dir)
    (build_dir / "DEBIAN").mkdir(parents=True)
    (build_dir / "usr/local/bin").mkdir(parents=True)
    return build_dir

def write_control_file(build_dir, app_name, author, email, sudo_required, deps):
    all_deps = []
    if sudo_required:
        all_deps.append("sudo")
    for dep in deps:
        all_deps.append(DEBIAN_PACKAGE_MAP.get(dep, f"python3-{dep}"))
    control_text = f"""Package: {app_name}
Version: 1.0
Section: base
Priority: optional
Architecture: all
Maintainer: {author} <{email}>
Description: Auto generated DEB package
"""
    if all_deps:
        control_text += "Depends: " + ", ".join(all_deps) + "\n"
    (build_dir / "DEBIAN/control").write_text(control_text)

def copy_python_file(build_dir, py_file, app_name):
    target_path = build_dir / "usr/local/bin" / app_name
    shutil.copy(py_file, target_path)
    target_path.chmod(0o755)
    return target_path

def copy_man_page(build_dir, man_file, app_name):
    man_dir = build_dir / "usr/share/man/man1"
    man_dir.mkdir(parents=True, exist_ok=True)
    target_path = man_dir / f"{app_name}.1"
    shutil.copy(man_file, target_path)
    subprocess.run(["gzip", "-f", str(target_path)], check=True)
    print(f"Man page installed: {target_path}.gz")

def create_tar_gz(deb_file, setup_script):
    tar_name = f"{deb_file.stem}.tar.gz"
    with tarfile.open(tar_name,"w:gz") as tar:
        tar.add(deb_file)
        if setup_script:
            tar.add(setup_script)
    print(f"Created tar.gz: {tar_name}")

def explain_tool():
    print(Fore.CYAN + "\n===== About Py2Deb =====\n")
    print(Fore.YELLOW + "Py2Deb is a utility to automatically create Debian (.deb) packages from Python scripts.\n")
    print(Fore.GREEN + "Purpose:")
    print(Fore.WHITE + "- Package any Python script as a .deb file.")
    print(Fore.WHITE + "- Automatically detect Python dependencies and map them to Debian packages.")
    print(Fore.WHITE + "- Optionally create a setup installation script and a tar.gz archive.\n")
    print(Fore.GREEN + "Key options:")
    print(Fore.WHITE + "-cn <creator_name>     Specify the creator of the package")
    print(Fore.WHITE + "-email <creator_email> Specify creator email")
    print(Fore.WHITE + "--command <name>      Name of the executable command after installation")
    print(Fore.WHITE + "--sudo                 Add sudo as a package dependency")
    print(Fore.WHITE + "--setup                Generate an install.sh setup script")
    print(Fore.WHITE + "--tar-gz               Create a tar.gz containing DEB and setup script")
    print(Fore.WHITE + "--bin                  Compile standalone binary with dependencies included")
    print(Fore.WHITE + "-man, --man_page <file>  Add man page for the command\n")
    print(Fore.MAGENTA + "Created by " + Fore.YELLOW + "Avi Twil " + Fore.MAGENTA + "from " + Fore.CYAN + "Twil Industries\n")

def build_in_virtualenv(py_file, app_name, deps):
    """Build standalone binary in a temporary virtual environment."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)
        venv_dir = temp_dir_path / "py2deb_venv"

        print(f"Creating temporary virtual environment at: {venv_dir}")
        venv.create(venv_dir, with_pip=True)

        python_bin = venv_dir / "bin" / "python"
        pip_bin = venv_dir / "bin" / "pip"

        # Install Nuitka and dependencies
        print("Installing Nuitka and required dependencies in virtualenv...")
        subprocess.run([python_bin, "-m", "pip", "install", "--upgrade", "pip"], check=True)
        subprocess.run([pip_bin, "install", "nuitka"] + deps, check=True)

        # Prepare Nuitka command
        output_dir = Path(f"build_nuitka/{app_name}.dist")
        output_dir.mkdir(parents=True, exist_ok=True)

        nuitka_cmd = [
            str(python_bin), "-m", "nuitka",
            "--standalone",
            f"--output-dir={output_dir}",
            str(py_file)
        ]

        print("Compiling script to standalone binary using Nuitka inside virtualenv...")
        subprocess.run(nuitka_cmd, check=True)
        print(f"Standalone folder created at: {output_dir}")
        return output_dir

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("file", nargs="?")
    parser.add_argument("-cn", "--creator_name", help="Creator name")
    parser.add_argument("-email", "--creator_email", help="Creator email")
    parser.add_argument("--command", help="Command name for executable")
    parser.add_argument("--sudo", action="store_true", help="Add sudo dependency")
    parser.add_argument("--setup", action="store_true", help="Create setup script")
    parser.add_argument("--tar-gz", action="store_true", help="Create tar.gz archive")
    parser.add_argument("--bin", action="store_true", help="Compile standalone binary")
    parser.add_argument("-man", "--man_page", help="Path to man page file")
    parser.add_argument("-h", "--help", action="store_true", help="Show help menu")
    args = parser.parse_args()

    if len(sys.argv)==1 or args.help:
        print_logo()
        help_menu()
        sys.exit(1)

    print_logo()
    py_file = Path(args.file)
    if not args.file or not py_file.exists():
        print(Fore.RED + "Error: missing or invalid Python file to package\n")
        help_menu()
        sys.exit(1)

    if not args.command:
        print(Fore.RED + "Error: you must insert command name using " +
              Fore.CYAN + "--command <name>\n")
        help_menu()
        sys.exit(1)

    if not args.creator_name:
        args.creator_name = "Unknown Creator"
        print(Fore.YELLOW + f"Warning: no creator name provided, using default: {Fore.CYAN}{args.creator_name}")

    if not args.creator_email:
        args.creator_email = "unknown@example.com"
        print(Fore.YELLOW + f"Warning: no creator email provided, using default: {Fore.CYAN}{args.creator_email}")

    deps = parse_python_dependencies(py_file)
    print(f"Detected dependencies: {deps}")

    # Handle standalone compilation
    if args.bin:
        try:
            build_in_virtualenv(py_file, args.command, deps)
        except subprocess.CalledProcessError:
            print(Fore.RED + "Error compiling standalone binary with Nuitka.")
            sys.exit(1)

    # Create DEB package
    build_dir = create_deb_structure(args.command)
    write_control_file(build_dir, args.command, args.creator_name, args.creator_email, args.sudo, deps)
    copy_python_file(build_dir, py_file, args.command)
    if args.man_page:
        copy_man_page(build_dir, args.man_page, args.command)

    deb_file = Path(f"{args.command}.deb")
    try:
        subprocess.run(["dpkg-deb", "--build", str(build_dir), str(deb_file)], check=True)
    except subprocess.CalledProcessError:
        print(Fore.RED + "Error building DEB package.")
        sys.exit(1)
    print(Fore.GREEN + f"DEB package created: {deb_file}")

    # Setup script
    setup_script = None
    if args.setup:
        setup_script = Path("install.sh")
        setup_script.write_text(f"""#!/bin/bash
sudo dpkg -i {deb_file.name}
""")
        setup_script.chmod(0o755)
        print(Fore.GREEN + "Setup script created: install.sh")

    # Optional tar.gz
    if args.tar_gz:
        create_tar_gz(deb_file, setup_script)

    explain_tool()

if __name__ == "__main__":
    main()
