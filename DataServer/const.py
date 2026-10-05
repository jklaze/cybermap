META = [{
        'lookup': 'city',
        'tag': 'city',
        'path': ['names','en'],
        },{
        'lookup': 'continent',
        'tag': 'continent',
        'path': ['names','en'],
        },{
        'lookup': 'continent_code',
        'tag': 'continent',
        'path': ['code'],
        },{
        'lookup': 'country',
        'tag': 'country',
        'path': ['names','en'],
        },{
        'lookup': 'iso_code',
        'tag': 'country',
        'path': ['iso_code'],
        },{
        'lookup': 'latitude',
        'tag': 'location',
        'path': ['latitude'],
        },{
        'lookup': 'longitude',
        'tag': 'location',
        'path': ['longitude'],
        },{
        'lookup': 'metro_code',
        'tag': 'location',
        'path': ['metro_code'],
        },{
        'lookup': 'postal_code',
        'tag': 'postal',
        'path': ['code'],
        }]

PORTMAP = {
    0:"DoS",     # Denial of Service
    1:"ICMP",    # ICMP
    20:"FTP",     # FTP Data
    21:"FTP",     # FTP Control
    22:"SSH",     # SSH
    23:"TELNET",  # Telnet
    25:"EMAIL",   # SMTP
    43:"WHOIS",   # Whois
    53:"DNS",     # DNS
    80:"HTTP",    # HTTP
    81:"HTTP",    # HTTP Alternative
    88:"AUTH",    # Kerberos
    109:"EMAIL",   # POP v2
    110:"EMAIL",   # POP v3
    115:"FTP",     # SFTP
    118:"SQL",     # SQL
    143:"EMAIL",   # IMAP
    156:"SQL",     # SQL
    161:"SNMP",    # SNMP
    220:"EMAIL",   # IMAP v3
    389:"AUTH",    # LDAP
    443:"HTTPS",   # HTTPS
    445:"SMB",     # SMB
    465:"EMAIL",   # SMTPS
    502:"IOT",     # Modbus (industrial control)
    554:"IOT",     # RTSP (IP cameras)
    587:"EMAIL",   # SMTP submission
    636:"AUTH",    # LDAP of SSL/TLS
    993:"EMAIL",   # IMAPS
    995:"EMAIL",   # POP3S
    1080:"PROXY",   # SOCKS proxy
    1433:"SQL",     # MS SQL Server
    1434:"SQL",     # MS SQL Monitor
    1521:"SQL",     # Oracle
    1900:"IOT",     # UPnP / SSDP
    2083:"HTTPS",   # cPanel
    2087:"HTTPS",   # WHM
    2096:"HTTPS",   # cPanel webmail
    2222:"SSH",     # SSH Alternative
    2323:"TELNET",  # Telnet Alternative
    3000:"HTTP",    # HTTP Alternative (dev servers, Grafana)
    3128:"PROXY",   # Squid proxy
    3306:"SQL",     # MySQL
    3389:"RDP",     # RDP
    4433:"HTTPS",   # HTTPS Alternative
    4443:"HTTPS",   # HTTPS Alternative
    5000:"HTTP",    # HTTP Alternative
    5060:"VOIP",    # SIP
    5061:"VOIP",    # SIP over TLS
    5432:"SQL",     # PostgreSQL
    5555:"IOT",     # Android Debug Bridge
    5900:"RDP",     # VNC:0
    5901:"RDP",     # VNC:1
    5902:"RDP",     # VNC:2
    5903:"RDP",     # VNC:3
    5984:"SQL",     # CouchDB
    6379:"SQL",     # Redis
    7547:"IOT",     # TR-069 (router management)
    8000:"HTTP",    # HTTP Alternative
    8001:"HTTP",    # HTTP Alternative
    8008:"HTTP",    # HTTP Alternative
    8080:"HTTP",    # HTTP Alternative
    8081:"HTTP",    # HTTP Alternative
    8085:"HTTP",    # HTTP Alternative
    8088:"HTTP",    # HTTP Alternative
    8090:"HTTP",    # HTTP Alternative
    8443:"HTTPS",   # HTTPS Alternative
    8880:"HTTP",    # HTTP Alternative
    8888:"HTTP",    # HTTP Alternative
    9000:"HTTP",    # HTTP Alternative
    9200:"SQL",     # Elasticsearch
    9443:"HTTPS",   # HTTPS Alternative
    11211:"SQL",     # Memcached
    27017:"SQL",     # MongoDB
    34567:"IOT",     # DVR / NVR (XMEye)
    37215:"IOT",     # Huawei router (Mirai)
    52869:"IOT",     # Realtek UPnP (Mirai)
}
