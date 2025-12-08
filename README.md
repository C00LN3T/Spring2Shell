# React4Shell
ULTIMATE REACT4SHELL EXPLOITATION FRAMEWORK CVE-2025-55182 &amp; CVE-2025-66478 Ready

=============================================================

usage: cracker.py [-h] {scan,exploit,direct,cve-scan,menu} ...

Ultimate React4Shell Scanner with CVE-2025-55182 & CVE-2025-66478 Exploitation

positional arguments:
  {scan,exploit,direct,cve-scan,menu}
                        Operation mode
    scan                Scan targets for vulnerabilities
    exploit             Load and exploit from existing report
    direct              Direct exploitation of a target
    cve-scan            Mass CVE scanning
    menu                Start interactive menu

options:
  -h, --help            show this help message and exit

Examples:
  cracker.py scan targets.txt results        # Scan targets and save reports
  cracker.py exploit report.json            # Load and exploit from report
  cracker.py menu                           # Start interactive menu
  cracker.py direct http://target.com       # Direct exploitation (tests ALL endpoints)
  cracker.py direct http://target.com -e /api/graphql  # Specific endpoint
  cracker.py direct http://target.com -a -c "id"       # Aggressive mode with command
  cracker.py direct http://target.com --test-all       # Test all endpoints without prompt
  cracker.py direct http://target.com --cve-scan       # CVE-specific scan only
        
