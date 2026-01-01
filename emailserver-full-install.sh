#!/usr/bin/env bash
# Ubuntu Mailcow Email Server Tam Otomatik Kurulum Scripti
# Ubuntu Server 24.04 için optimize edilmiştir
# Kullanım: sudo bash emailserver-full-install.sh
#
# Geliştirici: Osman Yavuz
# GitHub: https://github.com/OsmanYavuz-web/ubuntu-mailcow-installer
# Repository: https://github.com/OsmanYavuz-web/ubuntu-mailcow-installer

set -euo pipefail

# Renkli çıktı için
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Root kontrolü
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${RED}Bu script root yetkisi ile çalıştırılmalıdır!${NC}"
  echo "Kullanım: sudo bash emailserver-full-install.sh"
  exit 1
fi

# Banner
echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════╗"
echo "║   Ubuntu Mailcow Email Server Otomatik Kurulum Scripti ║"
echo "║   Ubuntu 22.04 & 24.04 + Docker + Mailcow              ║"
echo "╚════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${GREEN}✓ Bu script güvenli tekrar çalıştırılabilir (idempotent)${NC}"
echo -e "${GREEN}  Mevcut kurulumlar korunur, sadece eksik olanlar kurulur.${NC}"
echo ""

# Onay
echo -e "${YELLOW}Bu script şunları yapacak:${NC}"
echo "  - Sistem güncellemesi"
echo "  - SSH, Fail2Ban, UFW kurulumu"
echo "  - Otomatik güvenlik güncellemeleri"
echo "  - Swap oluşturma (dinamik: 4-8GB)"
echo "  - Docker ve Docker Compose kurulumu"
echo "  - Mailcow kurulumu (generate_config.sh ile OTOMATİK)"
echo "  - Sistem optimizasyonları (ZRAM dahil)"
echo "  - Yardımcı araçlar (DNS check)"
echo ""
echo -e "${YELLOW}Devam etmek istiyor musunuz? (y/N)${NC}"
read -r REPLY
if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
  echo "İptal edildi."
  exit 0
fi

# Mailcow hostname sorusu
echo ""
echo -e "${YELLOW}Mailcow hostname (FQDN) girin:${NC}"
echo -e "${YELLOW}Örnek: mail.example.com veya mail.domain.com${NC}"
DETECTED_HOSTNAME=$(hostname -f 2>/dev/null || hostname)
if [ -n "$DETECTED_HOSTNAME" ] && [ "$DETECTED_HOSTNAME" != "localhost" ] && [ "$DETECTED_HOSTNAME" != "localhost.localdomain" ]; then
  echo -e "${GREEN}Tespit edilen hostname: ${DETECTED_HOSTNAME}${NC}"
  echo -e "${YELLOW}Bu hostname'i kullanmak için Enter'a basın, farklı bir hostname için yazın:${NC}"
else
  echo -e "${YELLOW}Hostname girin (boş bırakırsanız otomatik tespit denenir, yoksa çıkılır):${NC}"
fi
read -r MAILCOW_HOSTNAME_INPUT

# Hostname'i ayarla (FQDN zorunlu)
if [ -z "$MAILCOW_HOSTNAME_INPUT" ]; then
  if [ -n "$DETECTED_HOSTNAME" ] && [ "$DETECTED_HOSTNAME" != "localhost" ] && [ "$DETECTED_HOSTNAME" != "localhost.localdomain" ]; then
    MAILCOW_HOSTNAME="$DETECTED_HOSTNAME"
  else
    echo -e "${RED}Geçerli bir FQDN hostname tespit edilemedi ve giriş yapılmadı. Çıkılıyor.${NC}"
    exit 1
  fi
else
  MAILCOW_HOSTNAME="$MAILCOW_HOSTNAME_INPUT"
fi

# Basit FQDN kontrolü
if [[ "$MAILCOW_HOSTNAME" != *.* ]]; then
  echo -e "${RED}Hostname FQDN olmalı (örnek: mail.example.com).${NC}"
  exit 1
fi

echo -e "${GREEN}Mailcow hostname: ${MAILCOW_HOSTNAME}${NC}"
echo ""

# Log dosyası
LOG_FILE="/var/log/mailcow-installer.log"
exec > >(tee -a "$LOG_FILE")
exec 2>&1

echo -e "\n${GREEN}[1/14] Sistem güncelleniyor...${NC}"
apt update && apt upgrade -y
apt install -y wget curl net-tools htop sudo

echo -e "\n${GREEN}[2/14] Gerekli paketler yükleniyor...${NC}"
apt install -y curl git ca-certificates gnupg lsb-release bind9-dnsutils wget net-tools htop

echo -e "\n${GREEN}[3/14] SSH Sunucusu kontrol ediliyor...${NC}"
if systemctl is-active --quiet ssh; then
  echo -e "${YELLOW}✓ SSH zaten kurulu ve çalışıyor, atlanıyor...${NC}"
else
  echo "SSH kuruluyor..."
  apt install -y openssh-server
  systemctl enable ssh
  systemctl start ssh
fi
echo "SSH durumu:"
systemctl status ssh --no-pager | head -5

echo -e "\n${GREEN}[4/14] Saat dilimi ve NTP ayarlanıyor...${NC}"
timedatectl set-timezone Europe/Istanbul
timedatectl set-ntp true
timedatectl

echo -e "\n${GREEN}[5/14] Otomatik güvenlik güncellemeleri yapılandırılıyor...${NC}"
apt install -y unattended-upgrades
echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";' > /etc/apt/apt.conf.d/20auto-upgrades
echo -e "${YELLOW}Not: unattended-upgrades sadece security güncellemelerini yapacak şekilde yapılandırılmalıdır.${NC}"

echo -e "\n${GREEN}[6/14] UFW Firewall yapılandırılıyor...${NC}"
apt install -y ufw

# UFW zaten aktifse kuralları koru, değilse yeni kurallar ekle
if ufw status | grep -q "Status: active"; then
  echo -e "${YELLOW}✓ UFW zaten aktif, mevcut kurallar korunuyor...${NC}"
  # Eksik kuralları ekle (mail sunucusu portları)
  for port in 22 25 80 443 587 465 993 995 143 110; do
    ufw allow ${port}/tcp 2>/dev/null || true
  done
else
  echo "UFW ilk kez yapılandırılıyor..."
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  # Mail sunucusu için gerekli portlar
  ufw allow 22/tcp comment 'SSH'
  ufw allow 25/tcp comment 'SMTP'
  ufw allow 80/tcp comment 'HTTP'
  ufw allow 443/tcp comment 'HTTPS'
  ufw allow 587/tcp comment 'SMTP Submission'
  ufw allow 465/tcp comment 'SMTPS'
  ufw allow 993/tcp comment 'IMAPS'
  ufw allow 995/tcp comment 'POP3S'
  ufw allow 143/tcp comment 'IMAP'
  ufw allow 110/tcp comment 'POP3'
  ufw --force enable
fi
ufw status verbose

echo -e "\n${GREEN}[7/14] Fail2Ban kontrol ediliyor...${NC}"
if systemctl is-active --quiet fail2ban; then
  echo -e "${YELLOW}✓ Fail2Ban zaten kurulu ve çalışıyor, atlanıyor...${NC}"
else
  echo "Fail2Ban kuruluyor..."
  apt install -y fail2ban
  systemctl enable fail2ban
  systemctl start fail2ban
fi
fail2ban-client status || true

echo -e "\n${GREEN}[8/14] Swap yapılandırılıyor...${NC}"
if swapon --show | grep -q '/swapfile'; then
  CURRENT_SWAP_SIZE=$(swapon --show --noheadings --bytes | grep '/swapfile' | awk '{print $3}')
  RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
  EXPECTED_SIZE=$((RAM_GB * 2))
  [ $EXPECTED_SIZE -lt 4 ] && EXPECTED_SIZE=4
  [ $EXPECTED_SIZE -gt 8 ] && EXPECTED_SIZE=8
  EXPECTED_SIZE_BYTES=$((EXPECTED_SIZE * 1024 * 1024 * 1024))

  if [ "$CURRENT_SWAP_SIZE" -ge "$EXPECTED_SIZE_BYTES" ]; then
    echo -e "${YELLOW}✓ Swap zaten yapılandırılmış ($(swapon --show | grep swapfile | awk '{print $3}')), atlanıyor...${NC}"
  else
    echo "Mevcut swap küçük, yeniden oluşturuluyor..."
    swapoff -a || true
    rm -f /swapfile || true
    RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
    SWAP_SIZE=$((RAM_GB * 2))
    [ $SWAP_SIZE -lt 4 ] && SWAP_SIZE=4
    [ $SWAP_SIZE -gt 8 ] && SWAP_SIZE=8
    fallocate -l ${SWAP_SIZE}G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
  fi
else
  echo "Swap oluşturuluyor..."
  # Varolan swap'ı kapat
  swapoff -a || true
  rm -f /swapfile || true

  # Dinamik swap oluştur (RAM'e göre 2x, min 4GB, max 8GB)
  RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
  SWAP_SIZE=$((RAM_GB * 2))
  [ $SWAP_SIZE -lt 4 ] && SWAP_SIZE=4
  [ $SWAP_SIZE -gt 8 ] && SWAP_SIZE=8

  fallocate -l ${SWAP_SIZE}G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
fi

# fstab'a ekle (eğer yoksa)
if ! grep -q '/swapfile' /etc/fstab; then
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# swappiness ayarla
if [ ! -f /etc/sysctl.d/99-swappiness.conf ] || ! grep -q 'vm.swappiness=10' /etc/sysctl.d/99-swappiness.conf; then
  echo 'vm.swappiness=10' > /etc/sysctl.d/99-swappiness.conf
  echo 'vm.vfs_cache_pressure=50' >> /etc/sysctl.d/99-swappiness.conf
  sysctl --system
fi

echo "Swap durumu:"
swapon --show
free -h

echo -e "\n${GREEN}[9/14] Docker kontrol ediliyor...${NC}"
if command -v docker &> /dev/null && systemctl is-active --quiet docker; then
  echo -e "${YELLOW}✓ Docker zaten kurulu ve çalışıyor, atlanıyor...${NC}"
  docker --version
else
  echo "Docker kuruluyor..."
  curl -fsSL https://get.docker.com | bash
  systemctl enable docker
  systemctl start docker
fi
echo "Docker durumu:"
if systemctl is-active --quiet docker; then
  echo "✓ Docker çalışıyor"
else
  echo "✗ Docker çalışmıyor"
fi
systemctl status docker --no-pager || true

echo -e "\n${GREEN}[10/14] Docker Compose plugin kontrol ediliyor...${NC}"
if docker compose version &> /dev/null; then
  echo -e "${YELLOW}✓ Docker Compose plugin zaten kurulu, atlanıyor...${NC}"
  docker compose version
else
  echo "Docker Compose plugin kuruluyor..."
  apt install -y docker-compose-plugin
fi

echo -e "\n${GREEN}[11/14] Mailcow indiriliyor ve generate_config.sh çalıştırılıyor...${NC}"
cd /opt
if [ ! -d "mailcow-dockerized" ]; then
  git clone https://github.com/mailcow/mailcow-dockerized
else
  echo "Mevcut mailcow-dockerized dizini bulundu, güncelleniyor..."
  git -C mailcow-dockerized pull || true
fi

cd mailcow-dockerized

# generate_config.sh çalıştırılabilir yap
chmod +x generate_config.sh || true

RUN_GEN_CONFIG=0
if [ -f "mailcow.conf" ]; then
  echo -e "${YELLOW}Mevcut bir mailcow.conf bulundu.${NC}"
  echo -e "${YELLOW}Yeniden oluşturmak ister misiniz? (y/N)${NC}"
  read -r REGEN_REPLY
  if [[ "$REGEN_REPLY" =~ ^[Yy]$ ]]; then
    RUN_GEN_CONFIG=1
  else
    RUN_GEN_CONFIG=0
  fi
else
  RUN_GEN_CONFIG=1
fi

if [ "$RUN_GEN_CONFIG" -eq 1 ]; then
  echo -e "${GREEN}generate_config.sh otomatik olarak çalıştırılıyor...${NC}"
  # Sırasıyla:
  # 1) Mail server hostname (FQDN)
  # 2) Timezone
  # 3) Branch seçimi (1 = master)
  printf "%s\n%s\n1\n" "$MAILCOW_HOSTNAME" "Europe/Istanbul" | bash ./generate_config.sh || true
else
  echo -e "${YELLOW}Mevcut mailcow.conf korunuyor, generate_config.sh atlanıyor.${NC}"
fi

echo -e "\n${GREEN}[12/14] Sistem optimizasyonları uygulanıyor...${NC}"

# Sistem limitleri
if ! grep -q "nofile 65535" /etc/security/limits.conf; then
  echo "File limits yapılandırılıyor..."
  echo "* soft nofile 65535
* hard nofile 65535" >> /etc/security/limits.conf
else
  echo -e "${YELLOW}✓ File limits zaten yapılandırılmış${NC}"
fi

# systemd limitleri
mkdir -p /etc/systemd/system.conf.d
if [ ! -f /etc/systemd/system.conf.d/limits.conf ] || ! grep -q "DefaultLimitNOFILE=65535" /etc/systemd/system.conf.d/limits.conf; then
  echo "Systemd limits yapılandırılıyor..."
  echo "[Manager]
DefaultLimitNOFILE=65535" > /etc/systemd/system.conf.d/limits.conf
  systemctl daemon-reload
else
  echo -e "${YELLOW}✓ Systemd limits zaten yapılandırılmış${NC}"
fi

# Disk optimizasyonu (noatime)
if ! grep -q "noatime" /etc/fstab; then
  # Sadece ext4 dosya sistemleri için noatime ekle
  if grep -q "ext4" /etc/fstab; then
    echo "Disk optimizasyonu (noatime) yapılandırılıyor..."
    sed -i.bak 's/\(.*ext4.*defaults\)/\1,noatime/' /etc/fstab
  fi
else
  echo -e "${YELLOW}✓ Disk optimizasyonu zaten yapılandırılmış${NC}"
fi

# Kernel TCP optimizasyonları
if [ ! -f /etc/sysctl.d/99-mailcow-optimizations.conf ]; then
  echo "Kernel TCP optimizasyonları yapılandırılıyor..."
  cat > /etc/sysctl.d/99-mailcow-optimizations.conf << 'SYSCTL_EOF'
net.core.somaxconn = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 120
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 8192
SYSCTL_EOF
  sysctl --system
else
  echo -e "${YELLOW}✓ Kernel TCP optimizasyonları zaten yapılandırılmış${NC}"
fi

# Journald log boyut yönetimi
mkdir -p /etc/systemd/journald.conf.d
if [ ! -f /etc/systemd/journald.conf.d/size-limit.conf ]; then
  echo "Journald log yönetimi yapılandırılıyor..."
  cat > /etc/systemd/journald.conf.d/size-limit.conf <<'EOF'
[Journal]
SystemMaxUse=500M
SystemKeepFree=1G
SystemMaxFileSize=100M
MaxRetentionSec=7day
EOF
  systemctl restart systemd-journald
else
  echo -e "${YELLOW}✓ Journald log yönetimi zaten yapılandırılmış${NC}"
fi
echo "journald disk kullanımı:"
journalctl --disk-usage

# Logrotate optimizasyonu
if [ ! -f /etc/logrotate.d/mailcow ]; then
  echo "Logrotate yapılandırılıyor..."
  cat > /etc/logrotate.d/mailcow << 'LOG_EOF'
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
LOG_EOF
else
  echo -e "${YELLOW}✓ Logrotate zaten yapılandırılmış${NC}"
fi

# ZRAM
if dpkg -l zram-config 2>/dev/null | grep -q "^ii"; then
  echo -e "${YELLOW}✓ ZRAM zaten kurulu${NC}"
else
  echo "ZRAM kuruluyor..."
  apt install -y zram-config
fi

echo -e "${GREEN}Sistem optimizasyonları tamamlandı${NC}"

echo -e "\n${GREEN}[13/14] Otomatik bakım mekanizmaları yapılandırılıyor...${NC}"

# apt autoremove otomasyonu (haftalık)
if [ ! -f /etc/cron.weekly/apt-autoremove ]; then
  echo "apt autoremove cron job oluşturuluyor..."
  cat > /etc/cron.weekly/apt-autoremove <<'EOF'
#!/bin/bash
# Otomatik kullanılmayan paket temizliği
/usr/bin/apt-get autoremove -y >/dev/null 2>&1
/usr/bin/apt-get autoclean -y >/dev/null 2>&1
EOF
  chmod +x /etc/cron.weekly/apt-autoremove
else
  echo -e "${YELLOW}✓ apt autoremove cron job zaten mevcut${NC}"
fi

# Disk temizliği (haftalık - /tmp, eski loglar)
if [ ! -f /etc/cron.weekly/system-cleanup ]; then
  echo "Sistem temizliği cron job oluşturuluyor..."
  cat > /etc/cron.weekly/system-cleanup <<'EOF'
#!/bin/bash
# Otomatik disk temizliği
# /tmp dizinindeki 7 günden eski dosyaları temizle
find /tmp -type f -atime +7 -delete 2>/dev/null
find /tmp -type d -empty -delete 2>/dev/null

# Eski kernel paketlerini temizle (en son 2 kernel'i koru)
OLD_KERNELS=$(dpkg -l | grep -E 'linux-image-[0-9]' | grep -v $(uname -r | sed 's/-generic//') | awk '{print $2}' | head -n -2)
if [ -n "$OLD_KERNELS" ]; then
  apt-get purge -y $OLD_KERNELS >/dev/null 2>&1
fi
EOF
  chmod +x /etc/cron.weekly/system-cleanup
else
  echo -e "${YELLOW}✓ Sistem temizliği cron job zaten mevcut${NC}"
fi

# Sistem sağlık kontrolü (günlük - disk kullanımı uyarısı)
if [ ! -f /etc/cron.daily/system-health-check ]; then
  echo "Sistem sağlık kontrolü cron job oluşturuluyor..."
  cat > /etc/cron.daily/system-health-check <<'EOF'
#!/bin/bash
# Disk kullanımı kontrolü ve uyarı
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 85 ]; then
  echo "UYARI: Disk kullanımı %${DISK_USAGE} - Kritik seviyeye yaklaşıyor!" | logger -t system-health
fi

# Swap kullanımı kontrolü
SWAP_USAGE=$(free | awk '/^Swap:/ {if ($2>0) printf "%.0f", $3*100/$2; else print "0"}')
if [ "$SWAP_USAGE" -gt 80 ]; then
  echo "UYARI: Swap kullanımı %${SWAP_USAGE} - RAM yetersiz olabilir!" | logger -t system-health
fi
EOF
  chmod +x /etc/cron.daily/system-health-check
else
  echo -e "${YELLOW}✓ Sistem sağlık kontrolü cron job zaten mevcut${NC}"
fi

echo -e "${GREEN}Otomatik bakım mekanizmaları yapılandırıldı${NC}"

echo -e "\n${GREEN}[14/15] Yardımcı araçlar oluşturuluyor...${NC}"

# Mailcow dizinine geç (zaten oradayız ama emin olmak için)
cd /opt/mailcow-dockerized 2>/dev/null || {
  mkdir -p /opt/mailcow-dockerized
  cd /opt/mailcow-dockerized
}

# DNS Kontrol Aracı (geliştirilmiş - dns_check_full.sh)
if [ ! -f /opt/mailcow-dockerized/dns_check_full.sh ]; then
  echo "DNS kontrol aracı indiriliyor..."
  curl -o /opt/mailcow-dockerized/dns_check_full.sh https://raw.githubusercontent.com/OsmanYavuz-web/email-server-dns-checker/main/dns_check_full.sh
  chmod +x /opt/mailcow-dockerized/dns_check_full.sh
  echo -e "${GREEN}✓ DNS kontrol aracı indirildi${NC}"
else
  echo -e "${YELLOW}✓ DNS kontrol aracı zaten mevcut, güncelleniyor...${NC}"
  curl -o /opt/mailcow-dockerized/dns_check_full.sh https://raw.githubusercontent.com/OsmanYavuz-web/email-server-dns-checker/main/dns_check_full.sh
  chmod +x /opt/mailcow-dockerized/dns_check_full.sh
fi


echo -e "\n${GREEN}[15/15] Kurulum özeti${NC}"

echo -e "\n${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Kurulum başarıyla tamamlandı!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Kurulum Sonrası Adımlar:${NC}"
echo ""
echo "1. Mailcow'u başlatmak için:"
echo "   cd /opt/mailcow-dockerized && docker compose up -d"
echo ""
echo "2. Mailcow Web UI:"
echo "   https://${MAILCOW_HOSTNAME}"
echo "   (Varsayılan kullanıcı: admin, şifre: moohoo)"
echo ""
echo "3. Sistem Durumu:"
echo "   - UFW: $(ufw status | grep Status)"
echo "   - Fail2Ban: $(fail2ban-client status | grep 'Number of jail' 2>/dev/null || echo 'Çalışıyor')"
echo "   - Swap: $(swapon --show | tail -1 | awk '{print $3}' || echo 'Aktif')"
echo "   - Docker: $(docker --version 2>/dev/null || echo 'Kurulu')"
echo ""
echo -e "${YELLOW}Yardımcı Araçlar:${NC}"
echo ""
echo "- DNS Kontrol: cd /opt/mailcow-dockerized && ./dns_check_full.sh domain.com mail.domain.com"
echo ""
echo -e "${YELLOW}Önemli Notlar:${NC}"
echo ""
echo "- Tüm kurulum logları: $LOG_FILE"
echo "- Firewall durumu: sudo ufw status verbose"
echo "- Fail2Ban durumu: sudo fail2ban-client status"
echo ""
echo -e "${GREEN}Başarılar! 🚀${NC}"

exit 0
