# Mailcow Email Server Kurulum Kılavuzu

Bu doküman, **Ubuntu Server 24.04** üzerinde **Mailcow** email server kurulumu için önerilen temel yapılandırmaları içerir. Amaç; güvenli, stabil ve uzun süre bakım gerektirmeyen bir email sunucusu elde etmektir.

---

## 🚀 Hızlı Kurulum (Otomatik Script)

Tüm kurulum adımlarını otomatik olarak yapmak için:

```bash
# Script'i indirin
wget https://raw.githubusercontent.com/OsmanYavuz-web/ubuntu-mailcow-installer/main/emailserver-full-install.sh
# veya
curl -O https://raw.githubusercontent.com/OsmanYavuz-web/ubuntu-mailcow-installer/main/emailserver-full-install.sh

# Çalıştırma izni verin
chmod +x emailserver-full-install.sh

# Root yetkisiyle çalıştırın
sudo bash emailserver-full-install.sh
```

### Script Özellikleri

✅ **Güvenli Tekrar Çalıştırma:** Script idempotent tasarımlıdır. Tekrar çalıştırırsanız:
- Mailcow zaten kuruluysa atlanır (mevcut yapılandırma korunur)
- Diğer servisler çalışıyorsa atlanır
- Sadece eksik olanlar kurulur ve optimizasyonlar güncellenir

✅ **Kurulum İçeriği:**
- Sistem güncellemeleri
- SSH, Fail2Ban, UFW (Firewall) - Mail sunucusu portları (25, 80, 443, 587, 465, 993, 995, 143, 110)
- Dinamik Swap yapılandırması (RAM'e göre 2x, min 4GB, max 8GB)
- Docker ve Docker Compose kurulumu
- Mailcow kurulumu (generate_config.sh ile otomatik)
- Sistem optimizasyonları (limits, noatime, TCP, journald, logrotate, ZRAM)
- Yardımcı araçlar (DNS kontrol)

✅ **Kurulum Süresi:** 15-20 dakika

✅ **Log Dosyası:** `/var/log/mailcow-installer.log`

---

## Manuel Kurulum Adımları

Aşağıdaki bölümler script'in yaptığı işlemleri manuel olarak yapmak isterseniz takip edilebilir.

---

## 1. Sanal Makine Oluşturma

```
VirtualBox veya VmWare kullanarak sanal makine oluşturun.
```

---

## 2. İşletim Sistemi Kurulumu

```
Ubuntu Server (ubuntu-24.04.3-live-server-amd64) kurulumu yapılır.
```

---

## 3. Sistem Güncelleme ve Temel Araçlar

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install wget curl net-tools htop sudo -y
```

---

## 4. SSH Sunucusu Kurulumu

```bash
sudo apt install openssh-server -y
sudo systemctl enable ssh
sudo systemctl start ssh
sudo systemctl status ssh
```

---

## 5. Saat Dilimi ve NTP Senkronizasyonu

```bash
sudo timedatectl set-timezone Europe/Istanbul
sudo timedatectl set-ntp true

timedatectl
```

---

## 6. Otomatik Güvenlik Güncellemeleri

```bash
sudo apt install unattended-upgrades -y
echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades
```

> Öneri: `50unattended-upgrades` içinde sadece `-security` repository'si aktif olsun; `-updates` ve paket yükseltmeleri elle yapılmalı (email servis kesintisi riskini azaltmak için).

---

## 7. Firewall (UFW) — Mail Sunucusu Portları

Mail sunucusu için gerekli portlar:

```bash
# UFW yükle (eğer yoksa)
sudo apt install ufw -y

# Mail sunucusu için gerekli portlar
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw allow 25/tcp comment 'SMTP'
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw allow 587/tcp comment 'SMTP Submission'
sudo ufw allow 465/tcp comment 'SMTPS'
sudo ufw allow 993/tcp comment 'IMAPS'
sudo ufw allow 995/tcp comment 'POP3S'
sudo ufw allow 143/tcp comment 'IMAP'
sudo ufw allow 110/tcp comment 'POP3'

# Aktif et
sudo ufw --force enable
sudo ufw status verbose
```

> Neden: İnternete açık sunucularda sadece ihtiyaç duyulan portları açmak temel savunmadır.

---

## 8. Fail2Ban Kurulumu (SSH Brute-Force Koruma)

```bash
sudo apt install fail2ban -y
sudo systemctl enable --now fail2ban
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

---

## 9. Swap Yönetimi (Dinamik: 4-8GB)

RAM miktarına göre dinamik swap oluşturulur (RAM x 2, minimum 4GB, maksimum 8GB).

```bash
# Varolan swap kapat
sudo swapoff -a
sudo rm -f /swapfile || true

# RAM miktarını kontrol et
RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
SWAP_SIZE=$((RAM_GB * 2))
[ $SWAP_SIZE -lt 4 ] && SWAP_SIZE=4
[ $SWAP_SIZE -gt 8 ] && SWAP_SIZE=8

# Swap oluştur
sudo fallocate -l ${SWAP_SIZE}G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# kalıcı yapmak için fstab'a ekle
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# swappiness düşük tut (10)
echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/99-swappiness.conf
echo 'vm.vfs_cache_pressure=50' | sudo tee -a /etc/sysctl.d/99-swappiness.conf
sudo sysctl --system
```

---

## 10. Docker Kurulumu

```bash
curl -fsSL https://get.docker.com | sudo bash
sudo systemctl enable docker
sudo systemctl start docker
sudo docker --version
```

---

## 11. Docker Compose Plugin Kurulumu

```bash
sudo apt install docker-compose-plugin -y
docker compose version
```

---

## 12. Mailcow Kurulumu

Resmi dökümantasyon: [https://mailcow.github.io/mailcow-dockerized-docs/](https://mailcow.github.io/mailcow-dockerized-docs/)

```bash
cd /opt
git clone https://github.com/mailcow/mailcow-dockerized
cd mailcow-dockerized

# generate_config.sh çalıştırılabilir yap
chmod +x generate_config.sh

# Yapılandırma oluştur (hostname FQDN olmalı: mail.example.com)
# Script otomatik olarak şunları sorar:
# 1) Mail server hostname (FQDN)
# 2) Timezone
# 3) Branch seçimi (1 = master)
bash ./generate_config.sh
```

---

## 13. Mailcow'u Başlatma

```bash
cd /opt/mailcow-dockerized
docker compose up -d
```

Mailcow Web UI: `https://MAILCOW-HOSTNAME` (varsayılan kullanıcı: `admin`, şifre: `moohoo`)

---

## 14. Sistem Optimizasyonları

### File Limits

```bash
echo "* soft nofile 65535
* hard nofile 65535" | sudo tee -a /etc/security/limits.conf
```

### Systemd Limits

```bash
sudo mkdir -p /etc/systemd/system.conf.d
echo "[Manager]
DefaultLimitNOFILE=65535" | sudo tee /etc/systemd/system.conf.d/limits.conf
sudo systemctl daemon-reload
```

### Disk Optimizasyonu (noatime)

```bash
sudo sed -i.bak 's/\(.*ext4.*defaults\)/\1,noatime/' /etc/fstab
```

### Kernel TCP Optimizasyonları

```bash
sudo tee /etc/sysctl.d/99-mailcow-optimizations.conf > /dev/null << 'EOF'
net.core.somaxconn = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 120
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 8192
EOF

sudo sysctl --system
```

### Journald Log Yönetimi

```bash
sudo mkdir -p /etc/systemd/journald.conf.d
sudo tee /etc/systemd/journald.conf.d/limits.conf > /dev/null << 'EOF'
[Journal]
SystemMaxUse=500M
SystemKeepFree=1G
SystemMaxFileSize=100M
MaxRetentionSec=7day
EOF

sudo systemctl restart systemd-journald
```

### Logrotate (Mailcow Logları)

```bash
sudo tee /etc/logrotate.d/mailcow > /dev/null << 'EOF'
/opt/mailcow-dockerized/data/web/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
}
EOF
```

### ZRAM

```bash
sudo apt install zram-config -y
```

---

## 15. Yardımcı Araçlar

Script otomatik olarak aşağıdaki yardımcı araçları oluşturur:

### DNS Kontrol Aracı

Gelişmiş DNS kontrol aracı: [email-server-dns-checker](https://github.com/OsmanYavuz-web/email-server-dns-checker)

```bash
cd /opt/mailcow-dockerized
./dns_check_full.sh example.com mail.example.com
```

**Özellikler:**
- ✅ A, MX, SPF, DKIM, DMARC, PTR kayıtları kontrolü
- ✅ CAA kayıtları kontrolü
- ✅ Cloudflare proxy kontrolü
- ✅ TLSA (DANE) kontrolü
- ✅ Otomatik skorlama sistemi (100 üzerinden)

**Parametreler:**
- `domain`: Ana domain adı (örn: `example.com`)
- `mail-domain`: Mail subdomain adı (örn: `mail.example.com`)

---

## 16. Kurulum Sonrası Kontroller

* Mailcow Web UI: `https://MAILCOW-HOSTNAME`
* UFW durum: `sudo ufw status verbose`
* Fail2Ban durumu: `sudo fail2ban-client status`
* Journald limitleri: `journalctl --disk-usage`
* Swap doğrulama: `swapon --show`
* Docker durumu: `docker ps`
* Mailcow durumu: `cd /opt/mailcow-dockerized && docker compose ps`

---

## 17. DNS Yapılandırması

Mailcow'un düzgün çalışması için DNS kayıtlarınızı yapılandırmanız gerekir:

### A Kaydı
```
mail.example.com    A    SUNUCU-IP
```

### MX Kaydı
```
example.com    MX    10    mail.example.com
```

### SPF Kaydı
```
example.com    TXT    "v=spf1 mx a:mail.example.com ~all"
```

### DKIM Kaydı
Mailcow Web UI'den DKIM anahtarınızı alın ve DNS'e ekleyin:
```
dkim._domainkey.example.com    TXT    "v=DKIM1; k=rsa; p=..."
```

### DMARC Kaydı
```
_dmarc.example.com    TXT    "v=DMARC1; p=quarantine; rua=mailto:admin@example.com"
```

### PTR (Reverse DNS)
Sunucu IP'nizin PTR kaydı mail.example.com'a işaret etmeli (hosting sağlayıcınızdan yapılır).

---

## 18. Neden Bunları Ekledik?

Kısa özet:

* **Firewall**: Saldırı düzeyini azaltır, sadece gerekli portları açar.
* **Swap**: OOM/RAM baskısını azaltır, stabil çalışma sağlar.
* **Logrotate**: Disk dolmasını engeller, performans kaybını önler.
* **Sistem Optimizasyonları**: File limits, TCP optimizasyonları ve disk I/O iyileştirmeleri email sunucusunun yük altında stabil çalışmasını sağlar.
* **ZRAM**: RAM kullanımını optimize eder.
* **Yardımcı Araçlar**: DNS kontrol işlemlerini kolaylaştırır.

---

