========================================
           Snmap - Super Nmap Scanner
========================================

Version: 1.0
Author: Avi Twil
Organization: Twil-Industries

Overview:
---------
Snmap is a standalone Nmap wrapper built with Python and Nuitka, bundled into a single executable for Kali Linux / Debian systems.
It includes a built-in Python interpreter and the Nmap binary, so it can run without installing Python or Nmap separately.
A MAN page is included for full usage instructions.

Installation:
-------------
1. Extract the release archive:
   tar -xzvf snmap_release.tar.gz
   cd snmap_release

2. Run the setup script (optional) or install the DEB manually:
   sudo ./setup.sh
   # or:
   sudo dpkg -i snmap_package.deb

3. Verify installation:
   Snmap -h
   man Snmap

Usage:
------
# Scan a single IP with default SYN scan
Snmap -t 192.168.1.10

# Scan a file with multiple IPs
Snmap -f ips.txt

# Scan a subnet with aggressive scanning
Snmap -ts 192.168.1.0/24 -flags -A --open

For full options, use the MAN page:
   man Snmap

Features:
---------
- Standalone executable (no external Python required)
- Includes Nmap binary inside the package
- Supports saving results in JSON
- Displays OS guesses, ports, services, and scripts
- Built-in colorful console output

Notes:
------
- Requires a 64-bit Debian-based system (Kali Linux recommended)
- MAN page is installed automatically with the DEB package

License:
--------
Provided by Avi Twil, Twil-Industries. All rights reserved.
