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

## Manuel Kurulum (İsteğe Bağlı)

Script otomatik olarak tüm kurulumu yapar. Manuel kurulum için aşağıdaki adımları takip edebilirsiniz:

### Sistem Hazırlığı

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install wget curl openssh-server ufw fail2ban -y
sudo timedatectl set-timezone Europe/Istanbul
sudo timedatectl set-ntp true
```

### Firewall ve Güvenlik

```bash
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
sudo ufw --force enable
sudo systemctl enable --now fail2ban
```

### Swap ve Docker

```bash
# Dinamik swap (RAM x 2, min 4GB, max 8GB)
RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
SWAP_SIZE=$((RAM_GB * 2))
[ $SWAP_SIZE -lt 4 ] && SWAP_SIZE=4
[ $SWAP_SIZE -gt 8 ] && SWAP_SIZE=8
sudo swapoff -a 2>/dev/null || true
sudo rm -f /swapfile || true
sudo fallocate -l ${SWAP_SIZE}G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/99-swappiness.conf
sudo sysctl --system

# Docker kurulumu
curl -fsSL https://get.docker.com | sudo bash
sudo apt install docker-compose-plugin -y
sudo systemctl enable --now docker
```

### Mailcow Kurulumu

```bash
cd /opt
git clone https://github.com/mailcow/mailcow-dockerized
cd mailcow-dockerized
chmod +x generate_config.sh
bash ./generate_config.sh  # Hostname FQDN girin (örn: mail.example.com)
docker compose up -d
```

Kurulum sonrası: `https://MAILCOW-HOSTNAME` (varsayılan: `admin` / `moohoo`)

> **Detaylı manuel kurulum:** Script otomatik olarak sistem optimizasyonları (limits, TCP, journald, logrotate, ZRAM), DNS kontrol aracı ve otomatik bakım mekanizmalarını yapılandırır. Detaylar için script kaynak koduna bakın.

---

## Kurulum Sonrası

1. **Mailcow Web UI:** `https://MAILCOW-HOSTNAME` - İlk girişte şifreyi değiştirin
2. **DNS Yapılandırması:** A, MX, SPF, DKIM, DMARC, PTR kayıtlarını yapılandırın
3. **Durum Kontrolleri:**
   ```bash
   sudo ufw status verbose
   sudo fail2ban-client status
   docker ps
   cd /opt/mailcow-dockerized && docker compose ps
   ```

**DNS Kontrol Aracı:** `cd /opt/mailcow-dockerized && ./dns_check_full.sh example.com mail.example.com`

> **Detaylı DNS yapılandırması:** [Mailcow Resmi Dökümantasyon](https://mailcow.github.io/mailcow-dockerized-docs/)

---

## 📞 Destek ve Kaynaklar

**Geliştirici:** Osman Yavuz

📧 **Email:** omnyvz.yazilim@gmail.com

**GitHub Repository:** [https://github.com/OsmanYavuz-web/ubuntu-mailcow-installer](https://github.com/OsmanYavuz-web/ubuntu-mailcow-installer)

**Mailcow Resmi Dökümantasyon:** [https://mailcow.github.io/mailcow-dockerized-docs/](https://mailcow.github.io/mailcow-dockerized-docs/)

---

## ⚠️ Önemli Notlar

- Mailcow hostname FQDN olmalıdır (örn: mail.example.com)
- İlk kurulumda admin kullanıcısı oluşturmanız gerekir (varsayılan şifre: moohoo)
- DNS kayıtlarınızı yapılandırmanız gerekir (A, MX, SPF, DKIM, DMARC, PTR)
- Docker ve Docker Compose kurulu olmalıdır
- Minimum 4GB RAM önerilir (8GB+ tercih edilir)
- Disk alanı izleme için sistem sağlık kontrolü cron job'ı aktif edilir

---

**Not**: Bu script Linux sunucular için tasarlanmıştır. Windows'ta çalışmaz.

---

