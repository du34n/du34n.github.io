---
title: OSCP Notları
icon: fas fa-terminal
order: 6
---

# OSCP Notları

OSCP (PEN-200) lab ve sınav odaklı saldırı notları: **active directory ve standalone
makineler** için uçtan uca teknik komut kitabı. HackTricks tarzı — her teknik için
kısa tanım, tespit komutu ve sömürme adımları.

Kullanım sırası sabit değildir: makinenin durumuna göre ilgili sayfaya atla.
Standart akış: **enumerasyon → (web/parola) ilk erişim → yetki yükseltme →
(AD ise) yatay hareket → pivoting gerekirse tünel → kanıt toplama.**

> **Hızlı filter:** herhangi bir sayfada **`/`** tuşuna bas (veya sağ alttaki
> **⌕ Ara** düğmesine tıkla); teknik/komut/bölüm yaz (ör. `kerberoast`, `SUID`,
> `chisel`), Enter'la **doğrudan** ilgili bölüme atla. Tema üstündeki 🔍 ise
> tam-metin aramasıdır.

## Bölümler

- [**Bölüm 1 — Port Tarama & Servis Enumerasyonu**](/oscp/01-enumerasyon/) — nmap/rustcan, SMB/SNMP/SMTP/LDAP/NFS/FTP/veritabanı enum, Windows/Linux keşfi, ilk erişim öncesi kontrol listesi.
- [**Bölüm 2 — Web Saldırıları**](/oscp/02-web-saldirilari/) — SQLi, XSS, LFI/log poisoning, dosya yükleme, komut enjeksiyonu, dizin gezintisi, brute-force, yaygın uygulama saldırıları (WordPress vb.).
- [**Bölüm 3 — Parola Saldırıları & Hash Kırma**](/oscp/03-parola-saldirilari/) — hashcat/john/hydra, parola politikaları ve kelime listeleri, Pass-the-Hash, kimlik bilgisi avcılığı.
- [**Bölüm 4 — Windows Yetki Yükseltme**](/oscp/04-windows-privesc/) — servis/DLL hijacking, unquoted path, yetkili servisler, potato ailesi, LAPS, AlwaysInstallElevated, credential avcılığı.
- [**Bölüm 5 — Linux Yetki Yükseltme**](/oscp/05-linux-privesc/) — SUID/capabilities, sudo yanlışları, cron, NFS, kernel/CVE'ler, PATH/LD_PRELOAD oyunları.
- [**Bölüm 6 — Active Directory: Enumerasyon**](/oscp/06-ad-enumerasyon/) — domain keşfi, PowerView/LDAP, BloodHound, SYSVOL/GPP, kullanıcı ve grup avcılığı.
- [**Bölüm 7 — AD: Kimlik Doğrulama Saldırıları, Yatay Hareket & Kalıcılık**](/oscp/07-ad-saldirilari/) — AS-REP/Kerberoast, NTLM relay, PtH/PtT, PsExec/WinRM/WMI/DCOM, golden ticket, DCSync, AD CS.
- [**Bölüm 8 — Pivoting & Tünelleme**](/oscp/08-pivoting/) — SSH -L/-R/-D, proxychains, chisel, ligolo-ng, plink, çift yönlü tünel kurma.
- [**Bölüm 9 — İstemci Saldırıları & AV Kaçınma**](/oscp/09-istemci-av/) — VBA makroları, .library-ms/WebDAV, shellcode çalıştırıcı, exploit derleme/uyarlama.
- [**Bölüm 10 — Sahadan Vaka Dersleri**](/oscp/10-vakalar/) — Çözülmüş lab/CTF makinelerinden çıkarılmış genelleştirilmiş dersler ve tekrar eden kalıplar.
- [**Bölüm 11 — Servis & Protokol Enumerasyonu**](/oscp/11-servis-enumerasyon/) — FTP, SMB/RPC, DNS, SMTP, IMAP/POP3, SNMP, NFS, MySQL/MSSQL, Oracle TNS, IPMI, SSH/Rsync, RDP, WinRM için derin enum ve anonim/default erişim.
- [**Bölüm 12 — Dosya Transferi**](/oscp/12-dosya-transferi/) — Windows/Linux indirme-yükleme, SMB/FTP/WebDAV sunucu, base64 kopyala-yapıştır, /dev/tcp, fileless ve canlı dil tek satırlıkları.
- [**Bölüm 13 — Shell'ler & Payload'lar**](/oscp/13-shell-payload/) — reverse/bind shell (nc, bash, PowerShell, python), socat (şifreli/kararlı), TTY yükseltme, kısıtlı shell kaçışı, webshell'ler, tmux.
- [**Bölüm 14 — Yaygın Uygulama Saldırıları**](/oscp/14-yaygin-uygulamalar/) — WordPress, Drupal, Joomla, Tomcat (+CGI/Ghostcat/Shellshock), Jenkins, Splunk, PRTG, osTicket, GitLab.
- [**Bölüm 15 — Metasploit & msfvenom**](/oscp/15-metasploit/) — modül/payload mantığı, db & workspace, auxiliary enum, autoroute pivot, local_exploit_suggester, payload üretimi ve encoding.
- [**Bölüm 16 — Post-Exploitation & Looting**](/oscp/16-post-exploitation/) — credential dumping (SAM/LSASS, shadow), loot checklist, kalıcılık (Win/Linux) ve iz temizleme.
- [**Bölüm 17 — Komut Referansı**](/oscp/17-komut-referansi/) — Windows cmd + PowerShell + Linux/bash hızlı referans, LOLBAS/GTFOBins mantığı, execution policy bypass.

## Kapsam dışı

Wireless (PEN-210), cloud, OSINT ve binary exploitation notları bu bölümde
bilinçli olarak yok — odak OSCP müfredatıdır.

## Not

Bu notlar lab/sınav ortamı için genelleştirilmiş teknikler içerir; herhangi bir
gerçek sistem üzerinde yalnızca **yazılı yetkin** olduğunda kullan.
