# 🐧 Linux Network Services Deployment

## 📋 Project Overview

Complete deployment and configuration of essential network services on secured Linux servers for enterprise environments. This project demonstrates comprehensive Linux system administration skills and network service management.

**Academic Projects Compilation** | Master 1 & 2 - SSI | 2023-2025

---

## 🎯 Objectives

- Deploy and configure core network services on Linux
- Implement security best practices for each service
- Demonstrate infrastructure management skills
- Integrate services for complete network solution
- Automate service deployment where possible
- Monitor service availability and performance

---

## 🛠️ Technologies Stack

### **Operating Systems**
- **Debian 12** - Primary server platform
- **Rocky Linux 8** - Alternative enterprise distribution
- **Ubuntu Server** - Additional testing platform

### **Network Services**
- **BIND9** - DNS server
- **ISC DHCP** - DHCP server
- **Apache HTTP Server** - Web server
- **Nginx** - Web server and reverse proxy
- **Postfix** - Mail Transfer Agent (MTA)
- **OpenVPN** - VPN server
- **IPsec/StrongSwan** - Site-to-site VPN
- **Squid** - HTTP/HTTPS proxy
- **SquidGuard** - Content filtering

### **Security & Monitoring**
- **iptables/nftables** - Firewall
- **Fail2ban** - Intrusion prevention
- **Let's Encrypt** - SSL/TLS certificates
- **SNMP** - Service monitoring
- **Nagios/LibreNMS** - Infrastructure monitoring

---

## 🏗️ Infrastructure Architecture
```
Enterprise Linux Infrastructure
         │
    Linux Servers
         │
    ┌────┴────────────────────────────┐
    │                                 │
Debian 12 Server              Rocky Linux 8
192.168.1.10                  192.168.1.20
    │                                 │
    ├─ DNS (BIND9)                   ├─ Web (Apache)
    ├─ DHCP (ISC DHCP)               ├─ Monitoring (Nagios)
    ├─ Web (Nginx)                   ├─ Mail (Postfix)
    ├─ Mail (Postfix)                └─ VPN (OpenVPN)
    ├─ Proxy (Squid)
    └─ VPN (IPsec)
```

---

## 📦 Services Deployed

### **1. DNS Server (BIND9)**

**Purpose:** Internal DNS resolution with DNSSEC support

**Key Features:**
- Forward zone configuration (domain.local)
- Reverse zone configuration (PTR records)
- Zone transfers for secondary DNS
- DNSSEC implementation for security
- Integration with monitoring tools

**Configuration Example:**
```bash
# Install BIND9
apt install bind9 bind9utils bind9-doc

# Configure named.conf
vi /etc/bind/named.conf.local

zone "domain.local" {
    type master;
    file "/etc/bind/zones/db.domain.local";
};

zone "1.168.192.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.192.168.1";
};

# Create zone files
vi /etc/bind/zones/db.domain.local
# SOA, NS, A, CNAME records

vi /etc/bind/zones/db.192.168.1
# PTR records for reverse lookup

# Validate configuration
named-checkconf
named-checkzone domain.local /etc/bind/zones/db.domain.local

# Restart service
systemctl restart bind9
systemctl enable bind9
```

**Security Measures:**
- ACLs for zone transfers
- Rate limiting for queries
- DNSSEC signing
- Firewall rules (port 53 TCP/UDP)

---

### **2. DHCP Server (ISC DHCP)**

**Purpose:** Dynamic IP allocation for network clients

**Key Features:**
- Subnet configuration with IP pools
- Static IP reservations (MAC-based)
- Lease time management
- DNS server distribution
- Gateway configuration
- Network boot options (PXE)

**Configuration Example:**
```bash
# Install DHCP server
apt install isc-dhcp-server

# Configure dhcpd.conf
vi /etc/dhcp/dhcpd.conf

subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.100 192.168.1.200;
    option routers 192.168.1.254;
    option domain-name-servers 192.168.1.10;
    option domain-name "domain.local";
    default-lease-time 600;
    max-lease-time 7200;
}

# Static reservations
host server1 {
    hardware ethernet 00:11:22:33:44:55;
    fixed-address 192.168.1.50;
}

# Start service
systemctl restart isc-dhcp-server
systemctl enable isc-dhcp-server
```

---

### **3. Web Servers (Apache & Nginx)**

#### **Apache HTTP Server**

**Use Case:** Application hosting, Nagios web interface

**Configuration:**
```bash
# Install Apache
apt install apache2

# Enable SSL module
a2enmod ssl
a2enmod headers
a2enmod rewrite

# Configure virtual host
vi /etc/apache2/sites-available/domain.conf

<VirtualHost *:80>
    ServerName domain.local
    DocumentRoot /var/www/html
    
    # Redirect to HTTPS
    Redirect permanent / https://domain.local/
</VirtualHost>

<VirtualHost *:443>
    ServerName domain.local
    DocumentRoot /var/www/html
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/domain.crt
    SSLCertificateKeyFile /etc/ssl/private/domain.key
    
    # Security headers
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Strict-Transport-Security "max-age=31536000"
</VirtualHost>

# Enable site
a2ensite domain.conf
systemctl reload apache2
```

#### **Nginx**

**Use Case:** Reverse proxy, LibreNMS interface, high-performance web server

**Configuration:**
```bash
# Install Nginx
apt install nginx

# Configure server block
vi /etc/nginx/sites-available/librenms

server {
    listen 80;
    server_name librenms.domain.local;
    root /opt/librenms/html;
    index index.php;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/run/php-fpm-librenms.sock;
        fastcgi_index index.php;
        include fastcgi.conf;
    }
}

# Enable site
ln -s /etc/nginx/sites-available/librenms /etc/nginx/sites-enabled/
systemctl reload nginx
```

**Security Hardening:**
- Hide server version
- Disable unnecessary modules
- SSL/TLS configuration with strong ciphers
- Rate limiting
- WAF (ModSecurity) integration

---

### **4. Mail Server (Postfix)**

**Purpose:** SMTP relay for system notifications and alerts

**Key Features:**
- SMTP relay configuration
- Gmail integration with STARTTLS
- SPF/DKIM/DMARC implementation
- TLS encryption for all connections
- Authentication mechanisms (SASL)
- Anti-spam integration

**Configuration Example:**
```bash
# Install Postfix
apt install postfix mailutils

# Configure main.cf
vi /etc/postfix/main.cf

# Gmail relay configuration
relayhost = [smtp.gmail.com]:587
smtp_use_tls = yes
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_security_level = encrypt
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt

# Create password file
vi /etc/postfix/sasl_passwd
[smtp.gmail.com]:587 username@gmail.com:app_password

# Hash password file
postmap /etc/postfix/sasl_passwd
chmod 600 /etc/postfix/sasl_passwd*

# Restart Postfix
systemctl restart postfix

# Test email
echo "Test email body" | mail -s "Test Subject" recipient@domain.com
```

**Integration:**
- Nagios alert notifications
- System cron job outputs
- Security alert forwarding
- Log monitoring alerts

---

### **5. VPN Services**

#### **OpenVPN - Remote Access VPN**

**Purpose:** Secure remote access for administrators

**Configuration:**
```bash
# Install OpenVPN
apt install openvpn easy-rsa

# Initialize PKI
make-cadir ~/openvpn-ca
cd ~/openvpn-ca
./easyrsa init-pki
./easyrsa build-ca nopass

# Generate server certificate
./easyrsa gen-req server nopass
./easyrsa sign-req server server

# Generate DH parameters
./easyrsa gen-dh

# Generate TLS auth key
openvpn --genkey secret ta.key

# Server configuration
vi /etc/openvpn/server.conf

port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun

# Start OpenVPN
systemctl start openvpn@server
systemctl enable openvpn@server
```

#### **IPsec - Site-to-Site VPN**

**Purpose:** Secure inter-site communication

**Technologies:** StrongSwan, IPsec

**Features:**
- IKEv2 protocol
- Strong encryption (AES-256)
- Perfect forward secrecy
- Automatic tunnel establishment
- Failover capabilities

---

### **6. Proxy Server (Squid + SquidGuard)**

**Purpose:** Web traffic filtering and caching

**Key Features:**
- HTTP/HTTPS proxy
- Content caching for bandwidth optimization
- URL filtering with blacklists
- Access control lists (ACLs)
- Authentication integration
- Traffic logging and reporting

**Configuration Example:**
```bash
# Install Squid and SquidGuard
apt install squid squidguard

# Configure Squid
vi /etc/squid/squid.conf

# ACLs
acl localnet src 192.168.1.0/24
acl SSL_ports port 443
acl Safe_ports port 80 443 21 20
acl CONNECT method CONNECT

# Deny all except safe ports
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports

# Allow local network
http_access allow localnet
http_access deny all

# Proxy port
http_port 3128

# SquidGuard integration
url_rewrite_program /usr/bin/squidGuard -c /etc/squidguard/squidGuard.conf

# Configure SquidGuard
vi /etc/squidguard/squidGuard.conf

dbhome /var/lib/squidguard/db
logdir /var/log/squidguard

dest adult {
    domainlist adult/domains
    urllist adult/urls
}

dest social {
    domainlist social-networks/domains
}

acl {
    default {
        pass !adult !social all
        redirect http://blocked.domain.local
    }
}

# Restart services
systemctl restart squid
```

---

## 🔐 Security Implementation

### **Firewall Configuration (iptables)**
```bash
# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (with rate limiting)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow DNS
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT

# Allow DHCP
iptables -A INPUT -p udp --dport 67:68 -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow SMTP
iptables -A INPUT -p tcp --dport 25 -j ACCEPT
iptables -A INPUT -p tcp --dport 587 -j ACCEPT

# Allow OpenVPN
iptables -A INPUT -p udp --dport 1194 -j ACCEPT

# Allow Squid proxy
iptables -A INPUT -p tcp --dport 3128 -j ACCEPT

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### **Fail2ban Configuration**
```bash
# Install Fail2ban
apt install fail2ban

# Configure jails
vi /etc/fail2ban/jail.local

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[postfix]
enabled = true
port = smtp,ssmtp,submission
filter = postfix
logpath = /var/log/mail.log

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log

# Restart Fail2ban
systemctl restart fail2ban
```

---

## 🧪 Testing & Validation

### **DNS Testing**
```bash
# Forward lookup
nslookup server.domain.local 192.168.1.10

# Reverse lookup
nslookup 192.168.1.10

# DNSSEC validation
dig +dnssec domain.local @192.168.1.10
```

### **DHCP Testing**
```bash
# Request DHCP lease
dhclient -v eth0

# Check lease database
cat /var/lib/dhcp/dhcpd.leases
```

### **Web Server Testing**
```bash
# HTTP connectivity
curl -I http://domain.local

# HTTPS with SSL verification
curl -v https://domain.local

# SSL certificate check
openssl s_client -connect domain.local:443 -showcerts
```

### **Mail Server Testing**
```bash
# SMTP connection test
telnet localhost 25

# Send test email
echo "Test message" | mail -s "Test" user@domain.com

# Check mail logs
tail -f /var/log/mail.log
```

### **VPN Testing**
```bash
# OpenVPN client connection
openvpn --config client.ovpn

# Check tunnel interface
ip addr show tun0

# Test connectivity through VPN
ping 10.8.0.1
```

---

## 📊 Monitoring Integration

All services are monitored using:
- **Nagios** for service availability
- **LibreNMS** for network metrics
- **SNMP** for performance data
- **Custom scripts** for specific checks

**Monitored Metrics:**
- Service uptime and availability
- Response times
- Resource usage (CPU, RAM, Disk)
- Network traffic
- Error rates
- Security events

---

## 🎓 Skills Demonstrated

### **Linux System Administration**
- Package management (apt, yum)
- Service management (systemd)
- User and permission management
- System security hardening
- Performance tuning
- Log analysis and troubleshooting
- Backup and recovery procedures

### **Network Services**
- DNS architecture and zone management
- DHCP configuration and IP management
- Web server deployment and optimization
- Mail server setup and relay configuration
- VPN implementation (OpenVPN, IPsec)
- Proxy server configuration and filtering
- Load balancing and high availability

### **Security**
- Firewall configuration (iptables)
- SSL/TLS certificate management
- Service hardening and security policies
- Access control implementation
- Intrusion prevention (Fail2ban)
- Security monitoring and alerting
- Vulnerability assessment and remediation

### **Automation & Scripting**
- Bash scripting for automation
- Configuration management
- Service orchestration
- Automated deployment scripts
- Monitoring integration

---

## 📚 Related Projects

- [Secure Infrastructure with SIEM](https://github.com/mariama-diack/secure-infrastructure-siem-wazuh)
- [Nagios Security Monitoring](https://github.com/mariama-diack/nagios-security-monitoring)
- [LibreNMS Network Supervision](https://github.com/mariama-diack/librenms-network-supervision)
- [Windows Penetration Testing](https://github.com/mariama-diack/windows-penetration-testing)

---

## 👤 Author

**Mariama DIACK**  
Master 2 - Sécurité des Systèmes d'Information  
Institut Supérieur d'Informatique

**Contact:**
- 🌐 Portfolio: [mariama-diack.github.io](https://mariama-diack.github.io)
- 💼 LinkedIn: [linkedin.com/in/mariamd3](https://linkedin.com/in/mariamd3)
- 📧 Email: diackmariam3@gmail.com
- 💻 GitHub: [@mariama-diack](https://github.com/mariama-diack)

---

## 📄 License

This project is for educational purposes.

---

⭐ **If you found this project useful, please give it a star!**
