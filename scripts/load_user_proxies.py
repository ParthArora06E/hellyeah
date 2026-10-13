import csv
import json
import os

raw_csv = """ip,anonymityLevel,asn,country,isp,latency,org,port,protocols,speed,upTime,upTimeSuccessCount,upTimeTryCount,updated_at,responseTime
"103.43.17.157","elite","AS132883","CN","Hong Kong San Ai Net Int'l Limited","206","Jiangsu Sanai network science and technology co, LTD","11111","https","705","98","415","422","2026-10-12T19:08:10.029Z","139"
"122.52.202.231","transparent","AS9299","PH","Philippine Long Distance Telephone Co.","229","Philippine Long Distance Telephone Company","8080","http","458","100","10","10","2026-10-12T19:39:18.925Z","146"
"80.82.54.243","elite","AS21017","RU","CenterTelecom Voronezh ISP","53","OJSC Rostelecom Voronezh branch Network Operation Center","1080","socks5","303","100","166","166","2026-10-12T19:02:27.424Z","148"
"139.135.63.218","elite","AS9541","PK","Cyber Internet Services (Private) Limited","129","Cyber Internet Services (Private) Limited","8080","http","830","94","74","79","2026-10-12T19:27:14.268Z","148"
"203.205.49.2","elite","AS45903","VN","CMC Telecom Infrastructure Company","202","CMC Telecom Infrastructure Company","10086","http","5001","100","10","10","2026-10-12T19:09:08.896Z","149"
"153.51.241.42","transparent","AS28435","MX","Javier Tamayo Garcia","156","Tamayo Telecom, S.A. de C.V","999","http","700","100","7","7","2026-10-12T19:12:43.285Z","150"
"72.195.114.184","elite","AS22773","US","Cox Communications Inc.","155","Cox Communications","4145","socks4","5000","80","8","10","2026-10-12T19:38:39.637Z","151"
"89.43.132.81","transparent","AS216472","SY","High Speed For Internet Services L.L.C","89","N/A","8085","http","273","72","493","688","2026-10-12T19:23:22.410Z","152"
"49.149.196.26","transparent","AS9299","PH","Philippine Long Distance Telephone Co.","273","Philippine Long Distance Telephone Company","8081","http","1177","61","419","691","2026-10-12T19:38:45.736Z","154"
"169.58.135.161","elite","AS51167","FR","Contabo GmbH","30","Contabo GmbH","3128","https","204","42","150","359","2026-10-12T19:18:01.245Z","154"
"190.7.138.78","transparent","AS13489","CO","EPM Telecomunicaciones S.A. E.S.P.","171","N/A","8080","https","762","100","201","202","2026-10-12T19:38:18.182Z","154"
"158.160.159.18","elite","AS200350","RU","Yandex.Cloud LLC","52","Yandex.Cloud LLC","1080","socks4","4611","100","400","400","2026-10-12T19:29:24.159Z","155"
"174.138.163.54","elite","AS20454","US","Secured Servers LLC","143","Secured Servers LLC","38795","http","1104","100","315","315","2026-10-12T19:38:16.724Z","155"
"94.156.250.185","elite","AS136258","GB","BrainStorm Network, Inc","17","Oneprovider.com","1080","socks5","4680","100","132","132","2026-10-12T19:12:50.994Z","155"
"119.93.172.191","transparent","AS9299","PH","Philippine Long Distance Telephone Co.","274","Philippine Long Distance Telephone Company","8081","http","977","98","65","66","2026-10-12T19:38:11.921Z","155"
"174.138.163.53","elite","AS20454","US","Secured Servers LLC","144","Secured Servers LLC","37984","http","1500","100","310","310","2026-10-12T19:38:47.781Z","156"
"178.128.165.127","elite","AS14061","GB","DigitalOcean, LLC","23","Digitalocean","10000","socks4","643","82","75","91","2026-10-12T19:25:50.924Z","156"
"45.207.211.153","elite","AS401701","HK","Vapeline Technology","246","N/A","3128","https","678","84","468","560","2026-10-12T19:18:27.912Z","158"
"185.147.69.48","elite","AS203028","PL","Prymas Inwestycje Spolka Z Ograniczona Odpowiedzialnoscia Spolka Komandytowa","32","Prymas","1080","socks4","1192","99","552","555","2026-10-12T19:19:49.900Z","158"
"124.40.250.74","transparent","AS45305","ID","PT Lintas Data Prima","179","N/A","3128","http","743","100","79","79","2026-10-12T19:22:33.658Z","158"
"67.203.23.88","elite","AS17252","US","Colocation America Corporation","150","T3 Web Hosting","8081","http","1014","100","203","204","2026-10-12T19:38:33.061Z","161"
"139.135.182.132","transparent","AS17639","PH","ComClark Network & Technology Corp","267","Converge ICT Network","8081","http","1063","98","85","87","2026-10-12T19:14:48.607Z","162"
"104.248.81.109","transparent","AS14061","NL","DigitalOcean, LLC","12","DigitalOcean, LLC","3128","https","354","100","111","111","2026-10-12T19:35:44.102Z","164"
"68.183.130.198","elite","AS14061","US","DigitalOcean, LLC","119","DigitalOcean, LLC","10000","https","887","78","72","92","2026-10-12T19:38:35.846Z","172"
"27.75.150.5","elite","AS7552","VN","Newass2011xDSLHN","176","N/A","1080","socks4","877","98","675","690","2026-10-12T19:28:29.365Z","174"
"93.86.242.213","transparent","AS8400","RS","TELEKOM-SRBIJA","34","N/A","3128","https","1090","100","111","111","2026-10-12T19:39:33.232Z","174"
"23.94.25.101","elite","AS36352","US","HostPapa","155","RackNerd LLC","40001","socks5","764","100","108","108","2026-10-12T19:14:27.497Z","177"
"72.56.64.208","elite","AS210976","NL","Timeweb, LLP","15","Timeweb, LLP","1080","socks5","163","88","670","765","2026-10-12T19:37:53.060Z","185"
"51.75.206.209","elite","AS16276","FR","OVH SAS","16","OVH","80","http","66","100","119","119","2026-10-12T19:38:24.159Z","185"
"154.12.231.32","elite","AS40021","US","Contabo Inc","104","Contabo Inc","80","https","5000","100","7","7","2026-10-12T19:14:12.252Z","185"
"5.175.192.43","elite","AS211066","NL","Simon Mariacher","15","MagicHosting","1080","socks5","1099","100","1","1","2026-10-12T19:38:31.696Z","185"
"180.194.9.255","transparent","AS9299","PH","Philippine Long Distance Telephone Co.","233","Philippine Long Distance Telephone Company","8081","http","909","23","71","305","2026-10-12T19:03:46.042Z","186"
"177.93.33.76","transparent","AS262186","CO","TV AZTECA SUCURSAL COLOMBIA","174","TV AZTECA SUCURSAL COLOMBIA","999","https","5613","100","7","7","2026-10-12T19:29:17.438Z","188"
"109.68.215.84","elite","AS9123","RU","JSC \"TIMEWEB\"","48","JSC \"TIMEWEB\"","1080","socks5","803","99","759","764","2026-10-12T19:39:05.971Z","189"
"42.113.52.93","anonymous","AS18403","VN","FPT Telecom Company","203","Vietnam Internet Network Information Center","8081","https","614","99","163","164","2026-10-12T19:28:54.979Z","191"
"208.87.128.239","elite","AS29802","US","HIVELOCITY, Inc.","97","Strasmore, Inc.","9150","socks5","374","100","7","7","2026-10-12T19:18:36.831Z","191"
"213.136.77.119","elite","AS51167","FR","Contabo GmbH","6","Contabo GmbH","8888","https","124","100","405","406","2026-10-12T19:18:04.088Z","192"
"137.59.47.73","transparent","AS131429","VN","MOBIFONECNTT","218","N/A","3128","https","194","100","761","763","2026-10-12T19:38:24.777Z","194"
"59.36.172.219","elite","AS4134","CN","Chinanet","186","Chinanet GD","5004","http","384","92","699","756","2026-10-12T19:40:11.305Z","194"
"27.75.146.255","elite","AS7552","VN","Viettel Group","175","VIETTEL","1080","socks4","719","76","430","566","2026-10-12T19:38:46.028Z","194"
"45.177.53.197","transparent","AS19429","CO","ETB - Colombia","182","N/A","999","http","3661","99","302","305","2026-10-12T19:38:33.498Z","194"
"185.199.53.71","elite","AS47583","IN","Hostinger International Limited","136","Hostinger","1080","socks4","604","100","767","769","2026-10-12T19:40:18.274Z","195"
"182.53.96.56","elite","AS23969","TH","TOT Public Company Limited","213","TOT Public Company Limited","4145","socks4","2672","100","202","202","2026-10-12T19:39:09.949Z","195"
"143.42.6.185","transparent","AS63949","US","Akamai Technologies, Inc.","81","Linode","3128","https","1945","100","74","74","2026-10-12T19:20:58.853Z","195"
"147.45.136.45","elite","AS210976","NL","Timeweb, LLP","13","TW Cloud","1080","socks5","30","100","750","753","2026-10-12T19:04:39.174Z","196"
"82.22.174.245","elite","AS215703","DE","Freakhosting LTD","4","Freakhosting LTD","1080","socks5","1013","99","548","555","2026-10-12T19:18:27.913Z","196"
"103.69.107.70","transparent","AS147087","ID","PT. Berkat Dunia Digital Cikande","178","N/A","8181","http","690","91","359","394","2026-10-12T19:39:58.080Z","196"
"98.159.107.20","elite","AS53850","US","GorillaServers, Inc.","116","IDC","1080","socks5","255","100","2","2","2026-10-12T19:26:25.134Z","196"
"174.77.111.196","elite","AS22773","US","Cox Communications Inc.","160","Cox Communications","4145","socks5","5001","100","10","10","2026-10-12T19:39:46.750Z","197"
"167.114.172.208","elite","AS16276","CA","OVH SAS","99","OVH Hosting, Inc.","1088","socks5","386","100","739","739","2026-10-12T19:38:54.915Z","200"
"65.21.252.66","elite","AS24940","FI","Hetzner Online GmbH","38","Hetzner","10809","socks5","5364","100","203","203","2026-10-12T19:39:49.921Z","200"
"138.124.69.9","elite","AS41745","RU","Baykov Ilya Sergeevich","55","Baykov Ilya Sergeevich","1080","socks5","2405","100","684","686","2026-10-12T19:40:26.500Z","201"
"103.247.23.244","transparent","AS58485","ID","PT wifian Solution","194","N/A","1111","http","711","99","366","369","2026-10-12T19:16:10.057Z","201"
"167.233.76.72","elite","AS24940","DE","Hetzner Online GmbH","16","Hetzner","3128","https","20","99","172","174","2026-10-12T19:39:55.832Z","203"
"186.33.61.21","elite","AS52468","GT","Ufinet Panama S.A.","222","UFINET Guatemala S. A","1080","socks5","2264","95","348","368","2026-10-12T19:38:03.115Z","205"
"192.210.178.88","elite","AS36352","US","HostPapa","155","RackNerd LLC","1080","socks5","3754","65","43","66","2026-10-12T19:01:32.563Z","205"
"27.75.151.160","elite","AS7552","VN","Newass2011xDSLHN","176","N/A","1080","socks4","718","99","434","440","2026-10-12T19:39:35.484Z","206"
"61.142.113.42","elite","AS4134","CN","Chinanet","211","Chinanet GD","6666","socks5","5001","100","12","12","2026-10-12T19:39:34.841Z","206"
"5.75.133.113","elite","AS24940","DE","Hetzner Online GmbH","10","Hetzner","10805","socks5","50","100","203","203","2026-10-12T19:41:41.626Z","207"
"103.72.101.51","elite","AS44259","IN","Ultahost, Inc.","127","N/A","1020","socks4","4668","98","49","50","2026-10-12T19:05:49.580Z","207"
"78.142.61.78","elite","AS200628","BG","BGO Cloud OOD","29","BGO Cloud OOD","3128","https","5001","100","7","7","2026-10-12T19:28:56.515Z","208"
"87.97.5.248","transparent","AS20845","HU","DIGI Tavkozlesi es Szolgaltato Kft","21","Digi - Invitel","18080","https","45","99","560","563","2026-10-12T19:39:27.130Z","209"
"51.15.253.45","elite","AS12876","FR","SCALEWAY","18","ONLINE","8080","socks5","6270","100","316","316","2026-10-12T19:39:26.054Z","209"
"95.64.159.130","elite","AS8359","RU","MTS PJSC","50","Customers P2P 2022 15 WAN","1080","socks5","234","100","52","52","2026-10-12T19:21:33.886Z","209"
"77.222.58.239","elite","AS44112","RU","SpaceWeb Hosting provider","44","SpaceWeb CJSC","14541","socks5","1543","99","760","764","2026-10-12T19:10:13.026Z","210"
"45.74.31.41","elite","AS219326","NL","Secure Internet LLC","56","Internet Security - AU","9942","socks5","1125","85","58","68","2026-10-12T19:30:02.035Z","210"
"111.125.154.22","elite","AS45178","AF","Telecom Development Company Afghanistan","103","Roshan","1080","socks4","6583","100","7","7","2026-10-12T19:05:46.221Z","210"
"120.220.197.198","elite","AS9808","CN","China Mobile communications corporation","276","China Mobile Communications Group Co., Ltd","59999","socks5","3211","96","622","650","2026-10-12T19:38:15.833Z","211"
"184.181.217.201","elite","AS22773","US","Cox Communications Inc.","167","Cox Communications","4145","socks4","5002","100","10","10","2026-10-12T19:31:04.381Z","212"
"107.172.46.245","elite","AS36352","US","HostPapa","94","RackNerd LLC","1080","socks5","502","96","733","762","2026-10-12T19:14:14.157Z","213"
"103.20.61.251","elite","AS133380","HK","Layerstack Limited","184","N/A","1080","socks5","382","93","426","456","2026-10-12T19:19:44.831Z","213"
"110.34.1.178","transparent","AS4007","NP","Subisu Cablenet","170","N/A","7777","http","1730","100","58","58","2026-10-12T19:02:19.580Z","213"
"119.63.95.3","elite","AS38794","TH","United Information Highway Co., Ltd.","190","United Information Highway Co., Ltd","4153","socks4","4019","100","10","10","2026-10-12T19:20:51.643Z","213"
"180.191.126.114","transparent","AS4775","PH","Globe Telecom","211","N/A","8082","https","2997","75","416","558","2026-10-12T19:03:57.628Z","214"
"78.156.229.34","elite","AS43574","RU","OJSC \"Dagsvyazinform\"","70","Open Joint-stock company","1080","socks5","276","98","85","87","2026-10-12T19:39:36.087Z","215"
"91.203.242.66","transparent","AS47335","RU","JSC Advanced Business Network","47","Advanced Business Network LTD","222","http","95","99","153","154","2026-10-12T19:07:55.016Z","217"
"124.217.67.142","transparent","AS9299","PH","Philippine Long Distance Telephone Co.","247","Philippine Long Distance Telephone Co","8082","http","810","79","188","239","2026-10-12T19:40:21.046Z","218"
"67.206.213.202","transparent","AS11992","PR","Liberty Mobile Puerto Rico Inc.","135","Liberty Mobile Puerto Rico Inc","3120","http","245","100","302","303","2026-10-12T19:40:13.327Z","219"
"116.204.166.178","transparent","AS216472","TR","High Speed For Internet Services L.L.C","59","High Speed","8080","http","6239","93","41","44","2026-10-12T19:39:40.773Z","219"
"45.74.31.47","elite","AS219326","NL","Secure Internet LLC","27","Internet Security - AU","7829","socks5","1151","92","187","204","2026-10-12T19:40:40.521Z","220"
"45.175.39.95","transparent","AS267843","VE","TCA SERVICES C.A.","147","TCA SERVICES C.A","999","https","2300","98","542","555","2026-10-12T19:30:25.700Z","221"
"201.222.50.218","elite","AS28103","PY","TECNOLOGIA EN ELECTRONICA E INFORMATICA SOCIEDAD ANONIMA (T.E.I.S.A)","216","TECNOLOGIA EN ELECTRONICA E INFORMATICA SOCIEDAD ANONIMA (T.E.I.S.A)","80","http","976","100","7","7","2026-10-12T19:38:39.473Z","222"
"2.27.47.146","transparent","AS213877","FI","U1 DIGITAL SERVICES LTD","38","u1host Finland","3128","https","162","97","180","185","2026-10-12T19:33:49.829Z","223"
"92.118.230.166","elite","AS212171","US","WorkTitans B.V","29","WorkTitans B.V","1088","socks5","1170","100","18","18","2026-10-12T19:39:14.886Z","223"
"49.0.245.175","elite","AS136907","HK","Huawei International Pte. LTD","183","N/A","5555","socks5","2410","100","4","4","2026-10-12T19:41:05.536Z","223"
"2.27.14.177","elite","AS198550","SE","Node Host Limited","35","Node Host Limited","8080","http","2779","58","72","124","2026-10-12T19:02:35.783Z","224"
"194.182.187.78","elite","AS61098","AT","Akenes SA","15","CH-EXOSCALE","1080","socks5","84","100","7","7","2026-10-12T19:39:49.842Z","224"
"45.74.31.40","elite","AS219326","NL","Secure Internet LLC","33","Internet Security - AU","9777","socks5","337","89","181","204","2026-10-12T19:29:17.560Z","226"
"192.252.220.89","elite","AS46562","US","Performive LLC","159","Total Server Solutions L.L.C","4145","socks5","5000","99","122","123","2026-10-12T19:06:50.293Z","226"
"95.220.199.192","elite","AS12714","RU","PJSC MegaFon","65","Net By Net Holding LLC","1080","socks5","245","95","189","199","2026-10-12T19:34:01.034Z","227"
"98.170.57.231","elite","AS22773","US","Cox Communications Inc.","154","Cox Communications","4145","socks5","5000","90","9","10","2026-10-12T19:14:59.045Z","227"
"185.27.135.75","elite","AS34119","GB","UK-IFASTNET","22","I FastNet LTD","1080","socks5","290","100","2","2","2026-10-12T19:39:56.048Z","227"
"103.18.77.156","transparent","AS55701","ID","PT Usaha Adi Sanggoro","167","N/A","3125","http","716","99","73","74","2026-10-12T19:39:25.380Z","229"
"52.128.241.109","elite","AS963","US","N963","146","Netsec Limited","1080","socks5","2106","100","36","36","2026-10-12T19:41:08.555Z","229"
"47.253.213.29","elite","AS45102","US","Alibaba Cloud LLC","85","Alibaba Cloud - US","7890","http","694","97","353","365","2026-10-12T19:20:29.689Z","230"
"85.155.228.112","elite","AS210464","AL","Andrew Kristuli","62","Andrew Kristuli","3128","https","6727","100","4","4","2026-10-12T19:33:31.011Z","230"
"58.144.196.192","elite","AS4837","CN","CNC Group CHINA169 Chongqing Province Network","181","N/A","39105","socks5","2414","100","12","12","2026-10-12T19:41:30.771Z","232"
"182.160.125.164","transparent","AS24323","BD","Aamra Networks Limited","193","N/A","12331","http","1012","79","388","492","2026-10-12T19:14:15.704Z","234"
"181.78.200.26","transparent","AS52468","EC","Ufinet Panama S.A.","273","UFINET","999","http","337","100","395","396","2026-10-12T19:27:08.845Z","235"
"89.111.153.21","transparent","AS197695","RU","\"Domain names registrar REG.RU\", Ltd","40","Reg.Ru","3128","http","173","100","700","703","2026-10-12T19:39:02.533Z","238"
"""

reader = csv.DictReader(raw_csv.strip().splitlines())
items = []
ips = []
proxies = []

for row in reader:
    ip = row["ip"].strip()
    port = row["port"].strip()
    proto = row["protocols"].strip().lower()
    if proto not in ("http", "https", "socks4", "socks5"):
        proto = "http"
    
    proxy_url = f"{proto}://{ip}:{port}"
    ips.append(ip)
    proxies.append(proxy_url)
    
    items.append({
        "ip": ip,
        "port": int(port) if port.isdigit() else 8080,
        "protocol": proto,
        "proxy_url": proxy_url,
        "anonymity": row.get("anonymityLevel", "elite"),
        "country": row.get("country", ""),
        "isp": row.get("isp", ""),
        "org": row.get("org", ""),
        "latency_ms": int(row.get("latency", 0)) if str(row.get("latency", "")).isdigit() else 0,
        "response_time_ms": int(row.get("responseTime", 0)) if str(row.get("responseTime", "")).isdigit() else 0,
        "speed": int(row.get("speed", 0)) if str(row.get("speed", "")).isdigit() else 0,
        "uptime": int(row.get("upTime", 100)) if str(row.get("upTime", "")).isdigit() else 100,
        "asn": row.get("asn", "")
    })

print(f"Parsed {len(items)} items. Total IPs: {len(ips)}, Total Proxies: {len(proxies)}")

# Save to output/ranked_ips.json
output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output")
os.makedirs(output_dir, exist_ok=True)
ranked_path = os.path.join(output_dir, "ranked_ips.json")

ranked_data = {
    "generated_at": 1791845000.0,
    "total_count": len(ips),
    "source": "User Elite Proxy Pool",
    "rotation_algorithm": "User-Provided-High-Anonymity-Pool",
    "ips": ips,
    "proxies": proxies,
    "items": items
}

with open(ranked_path, "w", encoding="utf-8") as f:
    json.dump(ranked_data, f, indent=2)

print(f"Saved to {ranked_path}")
