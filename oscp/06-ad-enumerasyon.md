---
layout: page
title: "Bölüm 6 — Active Directory: Enumerasyon"
oscp: true
toc: true
permalink: /oscp/06-ad-enumerasyon/
---

{% raw %}
Bu bölüm, AD hedefinde **keşiften saldırı planına** giden yolu komut-komut verir.
Kural: **BloodHound/otomasyon aracına geçmeden önce** anonim/null oturum ve
credential'lı temel enum (kullanıcı → grup → bilgisayar → SPN → ACL → share)
tamamlanır; böylece araçların sessizce atladığı şeyleri elle yakalarsın.

Placeholder'lar: `TARGET` = hedef IP (örn. `10.10.10.X`), `<DOMAIN>.lab` = FQDN,
`<KULLANICI>` / `<PAROLA>` / `<HASH>` = bulunan credential'lar.

## 1. Domain Keşfi — İlk Adımlar (Linux)

### 1.1 DNS çözümleme düzeneği
**Ne / ne zaman:** Domain adı çözümlenmiyorsa önce saldırı makinesinin DNS'i DC'yi
gösterecek şekilde ayarlanır; aksi halde Kerberos/SMB/LDAP her adımda kırılır.

```bash
# systemd-resolved yönetimli arayüze DNS + domain ekle
sudo resolvectl dns <INTERFACE> TARGET
sudo resolvectl domain <INTERFACE> <DOMAIN>.lab
resolvectl status <INTERFACE>
sudo resolvectl flush-caches

# Manuel yol (resolved devrede değilse): /etc/resolv.conf
nameserver TARGET
```

**Tuzaklar / notlar:**
- `/etc/resolv.conf`'ta `127.0.0.53` görüyorsan DNS'i systemd-resolved yönetiyor;
  dosyayı elle değiştirmek işe yaramaz, `resolvectl` kullan veya resolved'ı durdur.
- DNS düzelmeden verilen "user not found / SPN not found" hataları **yanlış
  negatiftir**; önce çözümlemeyi doğrula.

### 1.2 DC'yi bul: Kerberos 88 + tipik AD portları
**Ne:** DC'ler Kerberos (88), LDAP (389/636), SMB (445), KRB kpasswd (464) dinler.
88 açık host büyük ihtimalle DC'dir.

```bash
sudo nmap -p 88,135,139,445,389,636,464,3268,3269,5985,3389 TARGET-AGI/24 \
  --open -oA ad_ports
```

**Tuzaklar / notlar:**
- `3268/3269` (Global Catalog) açıksa forest genelinde sorgu atılabilir.
- Sadece 445 açık host null session'ı test etmeye değer (1.4).

### 1.3 Pasif dinleme ile ortamı tanı
**Ne / ne zaman:** Hiç paket göndermeden host adı, protokol ve broadcast davranışı
gözlemlenir. LLMNR/NBT-NS/MDNS için ayrıntılı zehirleme [Bölüm 7](/oscp/07-ad-saldirilari/)'dedir.

```bash
# Responder'ın sadece-analiz modu (zehirleme YAPMAZ)
sudo responder -I <INTERFACE> -A

# Ya da ham kayıt
sudo tcpdump -i <INTERFACE> -w output.pcap
```

**Tuzaklar / notlar:**
- `-A` analiz modundaki Responder dışarıdan aynı görünür; zehirleme gerekmeyen
  saf keşifte bile aktif cihazların adları (MDNS/ARP) dökülür.

### 1.4 SMB NULL session testi
**Ne / ne zaman:** Credential'sız başlangıçta DC'nin anonim erişime izin verip
vermediğini ölçer; veriyorsa kullanıcı listesi ve parola politikası bedava gelir.

```bash
# rpcclient ile null oturum + domain bilgisi
rpcclient -U "" -N TARGET
rpcclient $> querydominfo        # domain adı, DC adı, rollar
rpcclient $> getdompwinfo        # parola politikası (min len, lockout)
rpcclient $> enumdomusers        # kullanıcı + RID listesi
rpcclient $> queryuser 0x457     # RID'den kullanıcı detayı
rpcclient $> enumdomgroups       # grup + RID listesi
rpcclient $> querygroupmem 0x200 # grup üyeleri (RID)

# Windows tarafında aynı test
net use \\TARGET\ipc$ "" /u:""
```

**Tuzaklar / notlar:**
- `querydominfo` çalışmıyorsa null session kapalı demektir → 1.6/1.7'ye geç.
- RID (Relative Identifier) = SID'in son bölümü; hex `0x457` = 1111. Domain SID
  `S-1-5-21-...-1111` = domain SID + RID ile objeyi eşsiz tanımlar.
- Windows 10 1709+ ve hardening yapılmış DC'lerde `enumdomusers` bile
  "access denied" verebilir — bu durumda anon LDAP (1.5) veya Kerberos
  userenum (1.7) dene.

### 1.5 enum4linux(-ng) ve anon LDAP bind
**Ne:** Null session + LDAP anonymous bind'i tek araçla tarar.

```bash
enum4linux -U TARGET | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
enum4linux -P TARGET                                # parola politikası
enum4linux-ng -P TARGET -oA lab_enum                # JSON/YAML çıktı

# LDAP anonymous bind (artık default kapalı; açık unutulmuş olabilir)
ldapsearch -h TARGET -x -b "DC=<DOMAIN>,DC=lab" -s sub "*" \
  | grep -m1 -B10 pwdHistoryLength
```

**Tuzaklar / notlar:**
- LDAP anonymous bind modern domainlerde kapalıdır; açık bulursan tüm kullanıcı
  + grup + bilgisayar + parola politikası anonim çekilir — büyük av.
- `-x` simple bind; `-s sub` tüm ağacı, `-s base` sadece kökü tarar.

### 1.6 ldapsearch ile hedefli sorgular
**Ne / ne zaman:** Credential veya anon bind ile LDAP'tan spesifik nesneler çekilir.
LDAP filtrelerini bilmek PowerView/araca bağımlı olmamayı sağlar.

```bash
BASE="DC=<DOMAIN>,DC=lab"
# Kullanıcılar
ldapsearch -h TARGET -x -b "$BASE" "(&(objectCategory=person)(objectClass=user))" \
  | grep sAMAccountName:

# Parola politikası
ldapsearch -h TARGET -x -b "$BASE" -s base "*" | grep -i -A12 "pwdProperties\|minPwdLength\|lockoutThreshold"

# SPN'li hesaplar (Kerberoasting adayları)
ldapsearch -h TARGET -x -b "$BASE" "(&(objectCategory=user)(servicePrincipalName=*))" \
  servicePrincipalName sAMAccountName

# Credential'lı bind (-D bind DN, -w parola)
ldapsearch -h TARGET -x -D "CN=<KULLANICI>,CN=Users,$BASE" -w '<PAROLA>' -b "$BASE" "(sAMAccountName=*)"
```

**Tuzaklar / notlar:**
- DN biçimi: `CN=Ada,OU=IT,DC=<DOMAIN>,DC=lab` — sağdan sola okunur
  (DC → OU/CN kapsayıcıları → nesne).
- Çıktıyı daraltmak için attribute listesi ekle: `... sAMAccountName memberof`.

### 1.7 Kerberos tabanlı kullanıcı numaralandırma (kerbrute)
**Ne:** Kerberos pre-auth yokluğundan yararlanır; geçersiz kullanıcıya KDC
`PRINCIPAL UNKNOWN`, geçerli olana pre-auth talebi döner. **4625 logon-failure
üretmez, kilitlenme sayacını artırmaz** — en sessiz kullanıcı keşfi.

```bash
./kerbrute userenum -d <DOMAIN>.lab --dc TARGET /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  -o valid_users.txt
```

**Tuzaklar / notlar:**
- `-d` domain FQDN (`<DOMAIN>.lab`), `--dc` DC'nin IP'si (`TARGET`).
- Userenum zararsız; aynı yöntemle **password spraying** yapılırsa başarısız
  pre-auth denemeleri lockout'a sayılır → parola politikasına (1.4) göre bekle.

## 2. Credential ile Enum (Linux)

### 2.1 NetExec / CrackMapExec ile hızlı durum taraması
**Ne / ne zaman:** Tek credential ile domainin tüm klasik enum'u (kullanıcı,
grup, share, parola politikası, logged-on) tek araçtan.

```bash
# Parola politikası ve temel bilgi
nxc smb TARGET -u <KULLANICI> -p '<PAROLA>' --pass-pol

# Kullanıcı ve gruplar
nxc smb TARGET -u <KULLANICI> -p '<PAROLA>' --users
nxc smb TARGET -u <KULLANICI> -p '<PAROLA>' --groups
nxc smb TARGET -u <KULLANICI> -p '<PAROLA>' --loggedon-users
nxc smb TARGET -u <KULLANICI> -p '<PAROLA>' --shares
```

**Tuzaklar / notlar:**
- Hash ile de çalışır: `-H <HASH>` (PtH). NTLMv2 hash yakalandıysa parola
  kırmadan ilerlenir (bkz. [Bölüm 7](/oscp/07-ad-saldirilari/)).
- `--continue-on-success` spraying'de kullanışlı; yalnızca `-u/-p` değil
  `-u users.txt -p parolalar.txt` listeleri de geçerlidir.

### 2.2 smbmap ve paylaşım içeriği
**Ne:** Kimlikle erişilebilen share'leri ve içeriklerini recursive listeler.

```bash
smbmap -u <KULLANICI> -p '<PAROLA>' -d <DOMAIN>.lab -H TARGET
smbmap -u <KULLANICI> -p '<PAROLA>' -d <DOMAIN>.lab -H TARGET -R 'PaylasimAdi'
```

**Tuzaklar / notlar:**
- `-R` çıktısı uzun olur; `tee` ile dosyaya alıp `grep -i "pass\|cred\|key\|.kdbx"` ile tara.

### 2.3 spider_plus ile share taramasını otomatikleştirme
**Ne:** Okunabilen tüm share'leri gezip dosya listesini JSON olarak kaydeder.

```bash
nxc smb TARGET -u <KULLANICI> -p '<PAROLA>' -M spider_plus
# Çıktı: /tmp/cme_spider_plus/TARGET.json
```

**Tuzaklar / notlar:**
- Büyük share'lerde yavaştır; arka planda çalıştır, sonuçları grep'le.

### 2.4 windapsearch
**Ne:** LDAP tabanlı enum; domain admin üyeliği ve nested-privileged kullanıcıları
hızlı gösterir.

```bash
python3 windapsearch.py --dc-ip TARGET -u <KULLANICI>@<DOMAIN>.lab -p '<PAROLA>' --da
python3 windapsearch.py --dc-ip TARGET -u <KULLANICI>@<DOMAIN>.lab -p '<PAROLA>' -PU
```

**Tuzaklar / notlar:**
- `-PU` recursive (iç içe grup) üyelik arar; gösterilen "privileged" her kullanıcı
  hedef listene girer.

## 3. Windows'ta Enum — Built-in Araçlar

### 3.1 Host ve domain bilgisi (situation awareness)
**Ne:** İçeride bir shell varsa önce hostun kendisini ve domain bağlantısını tanı.

```powershell
hostname; [System.Environment]::OSVersion.Version
systeminfo
ipconfig /all
echo %USERDOMAIN%        # domain adı (CMD)
echo %LOGONSERVER%       # check-in yaptığı DC (CMD)
set
arp -a; route print
qwinsta                  # bu makinede açık oturumlar var mı?
```

### 3.2 net.exe / net1
**Ne:** Her Windows'ta var; hızlı ama eksik (attribute göstermez, nested grup
görmez) ve EDR tarafından izlenir.

```cmd
net user /domain
net user <KULLANICI> /domain
net group /domain
net group "Domain Admins" /domain
net group "Domain Controllers" /domain
net group "<GRUP>" /domain
net accounts /domain          # parola + lockout politikası
net localgroup administrators # yerel adminler (DA default dahil)
net view /domain
```

**Tuzaklar / notlar:**
- `net1` aynı binary'dir; `net` string'i izleniyorsa `net1 user /domain` kullan.
- `net group` yalnızca **kullanıcı** üyeleri listeler; grup içinde grup (nested)
  görünmez → LDAP/PowerView ile doğrula.

### 3.3 Credential enjeksiyonu — runas /netonly
**Ne / ne zaman:** Domain-join olmayan veya farklı hesapla çalışmak istenen
makinada credential'ı NTLM oturumuna enjekte eder. Keşif için MMC/RSAT açmadan önce.

```cmd
runas.exe /netonly /user:<DOMAIN>.lab\<KULLANICI> cmd.exe
```

**Tuzaklar / notlar:**
- `/netonly` şart: lokal kimliği değiştirmez, ağ trafiği belirtilen kimlikle çıkar.
- Şifre istemi görünür; komut satırında asla parola bırakma.

### 3.4 MMC + RSAT snap-in'leri
**Ne / ne zaman:** Grafiksel enum; RSAT kurulu herhangi bir Windows'ta AD'yi
ADUC/GPMC üzerinden gezer.

```text
mmc → File → Add/Remove Snap-in → Active Directory Users and Computers /
      Sites and Services / Domains and Trusts ekle
ADUC → sağ tık → Change Domain → <DOMAIN>.lab
ADUC → View → Advanced Features   (güvenlik sekmesini/ACL'leri görmek için ŞART)
```

**Tuzaklar / notlar:**
- Advanced Features kapalıysa **ACL'ler ve birçok attribute görünmez** — enum
  için mutlaka aç.
- RSAT default yalnızca DC'de kuruludur; istemcide kurmak admin ister.

### 3.5 ActiveDirectory PowerShell modülü (RSAT cmdlet'leri)
**Ne:** En temiz cmdlet seti; `-Filter` vs `-Identity` ayrımını bilmek gerekir.

```powershell
Import-Module ActiveDirectory

Get-ADDomain
Get-ADDomainController -Filter *              # tüm DC'ler

# -Identity: tek obje (ad, DN, GUID, SID olabilir)
Get-ADUser -Identity <KULLANICI> -Properties *

# -Filter: çoklu/şartlı arama
Get-ADUser -Filter *
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName  # SPN'li hesaplar
Get-ADUser -Filter 'Enabled -eq $false' -Properties Description,SamAccountName          # devre dışı hesaplar
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl      # reversible encryption
Get-ADUser -Filter 'badPwdCount -gt 0'                                                  # spraying'de kaçınılacaklar

# Gruplar ve üyelik
Get-ADGroup -Filter * | select name, groupscope
Get-ADGroup -Identity "Domain Admins" -Properties Members
Get-ADGroupMember -Identity "Domain Admins" -Recurse     # nested üyelik dahil

# Objeler, silinmiş objeler, trust'lar
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects
Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -IncludeDeletedObjects
Get-ADTrust -Filter *

# Domain-join olmayan makineden uzak domaine sorgu
Get-ADUser -Identity <KULLANICI> -Server <DOMAIN>.lab -Properties *
```

**Tuzaklar / notlar:**
- `-Recurse` olmadan `Get-ADGroupMember` nested üyeleri **kaçırır**.
- `badPwdCount -gt 0` listesi, lockout riski taşımadan spraying listesi temizlemek
  için altın değerindedir (bkz. [Bölüm 7](/oscp/07-ad-saldirilari/)).
- `-Server` domain-join olmayan makinede cmdlet'leri çalıştırmayı mümkün kılar.

### 3.6 dsquery (built-in DLL)
**Ne / ne zaman:** RSAT yokken DC üzerinde (veya System32'de dsquery.dll olan
hostta, SYSTEM/elevated context ile) LDAP filtreli arama.

```cmd
dsquery user
dsquery computer
dsquery * "CN=Users,DC=<DOMAIN>,DC=lab"                       # OU'daki tüm objeler
dsquery user "DC=<DOMAIN>,DC=lab" -disabled                   # pasif hesaplar
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -attr sAMAccountName   # DC hesapları
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl   # PASSWD_NOTREQD
```

**Tuzaklar / notlar:**
- Matching OID'ler: `...803` = bit tam eşleşme (AND), `...804` = herhangi bir bit
  (OR), `...1941` = DN/membership recursive eşleşme.
- UAC bit değerleri: `2`=disabled, `32`=PASSWD_NOTREQD, `128`=reversible
  encryption, `4194304`=DONT_REQ_PREAUTH (AS-REP roast adayı → [Bölüm 7](/oscp/07-ad-saldirilari/)).

## 4. PowerShell/.NET ile Elle LDAP Enum

### 4.1 PDC ve DN'yi dinamik bul (ADSI/.NET)
**Ne / ne zaman:** PowerView gibi araç yoksa .NET sınıflarıyla LDAP path kurulur.
PDC'ye sorgu atmak en güncel veriyi verir.

```powershell
# Domain + PDC (PdcRoleOwner) bul
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name

# Domain DN
$DN = ([adsi]'').distinguishedName            # DC=<DOMAIN>,DC=lab

# Tam LDAP path
$LDAP = "LDAP://$PDC/$DN"                     # LDAP://DC01.<DOMAIN>.lab/DC=<DOMAIN>,DC=lab
```

**Tuzaklar / notlar:**
- Domain adı herhangi bir DC'ye resolve olabilir; PDC (FSMO PdcRoleOwner) tek ve
  yetkilidir — lockout/parola bilgisi için önemli.
- Script çalıştırırken execution policy engellerse: `powershell -ep bypass` veya
  `Set-ExecutionPolicy Bypass -Scope Process` (kalıcı değişiklik yok).

### 4.2 DirectorySearcher ile sorgu + LDAPSearch fonksiyonu
**Ne:** `DirectoryEntry` + `DirectorySearcher` ile rafine LDAP filtreleri.

```powershell
$direntry  = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
$dirsearch = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearch.filter = "samAccountType=805306368"   # 0x30000000 = tüm kullanıcılar
$dirsearch.FindAll()

# Fonksiyon olarak sakla (function.ps1)
function LDAPSearch {
    param ([string]$LDAPQuery)
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DN  = ([adsi]'').distinguishedName
    $DE  = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DN")
    $DS  = New-Object System.DirectoryServices.DirectorySearcher($DE, $LDAPQuery)
    return $DS.FindAll()
}

Import-Module .\function.ps1
LDAPSearch -LDAPQuery "(samAccountType=805306368)"     # kullanıcılar
LDAPSearch -LDAPQuery "(objectclass=group)"            # gruplar
LDAPSearch -LDAPQuery "(&(objectCategory=user)(cn=<KULLANICI>))"

# Grup üyeleri (nested dahil)
foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
    $group.properties | select {$_.cn}, {$_.member}
}
```

**Tuzaklar / notlar:**
- `samAccountType` değerleri: `805306368`=user, `805306369`=machine,
  `268435456`=group.
- `net.exe`'nin kaçırdığı **nested grup** üyelikleri yalnızca LDAP'ta görünür;
  büyük gruplarda `member` attribute'u sorguyu daralt.

## 5. PowerView ile Enum

### 5.1 Temel nesne enum'u
**Ne:** Tek script ile domain/kullanıcı/grup/bilgisayar/GPO/trust durum farkındalığı.

```powershell
Import-Module .\PowerView.ps1

Get-NetDomain
Get-NetDomainController
Get-NetUser | select cn,pwdlastset,lastlogon,description
Get-NetUser | select *
Get-NetGroup | select cn
Get-NetGroup "Domain Admins" | select member
Get-NetGroupMember -Identity "Domain Admins" -Recurse
Get-NetComputer | select operatingsystem,dnshostname
Get-DomainOU
Get-DomainGPO
Get-DomainPolicy                     # default domain + DC policy (parola politikası)
Get-DomainTrustMapping               # tüm trust'lar (cross-forest dahil)
```

**Tuzaklar / notlar:**
- `description` ve `info` alanlarına bak — parola notu düşülmüş olur.
- `admincount=1` kullanıcılar privileged'dır; hedef listesine öncelikli al.
- PowerView, PowerSploit'ten ayrı olarak BC-Security/Empire 4 tarafından
  güncellenir; SharpView (.NET port) PowerShell yasaklı ortamlarda alternatiftir:
  `.\SharpView.exe Get-DomainUser -Identity <KULLANICI>`.

### 5.2 SPN enum (Kerberoasting hedef listesi)
**Ne / ne zaman:** SPN'li kullanıcı hesapları Kerberoasting için adaydır; bu liste
[Bölüm 7](/oscp/07-ad-saldirilari/)'deki saldırının girdisidir.

```cmd
setspn -L <KULLANICI>              # tek hesabın SPN'leri
setspn -Q */*                      # domaindeki TÜM SPN'ler
```

```powershell
Get-NetUser -SPN | select samaccountname,serviceprincipalname
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
# TGS'yi Hashcat formatında çek (saldırı kısmı Bölüm 7)
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\tgs.csv -NoTypeInformation
```

**Tuzaklar / notlar:**
- Bilgisayar hesaplarını (`HOST/...`, `TERMSRV/...`) atla; asıl av **kullanıcı**
  hesaplarına bağlı SPN'lerdir (MSSQLSvc, HTTP, exchangeAB...).
- `msDS-SupportedEncryptionTypes` attribute'una bak: RC4-only hesaplar offline
  kırması çok daha kolay ticket üretir.
- TGS almak enumeration sayılır, kırma işi offline'dır → ağda iz bırakmaz.

### 5.3 Bilgisayar/OS ve hedef haritalama
**Ne:** AD üzerinden OS versiyonu + hostname; EOL OS'ler privesc için hedef olur.

```powershell
Get-NetComputer | select operatingsystem,dnshostname,lastlogontimestamp
Find-LocalAdminAccess              # mevcut kullanıcının local admin olduğu makineler
Test-AdminAccess -ComputerName <HOST>
Get-DomainUserLocation             # kimin nerede oturum açtığı
```

**Tuzaklar / notlar:**
- `Find-LocalAdminAccess` SCM (OpenServiceW) ile taram yapar; büyük ortamda
  dakikalar sürer, sabırlı ol.
- OS versiyonu eski (Server 2008/2012, Win7) makineleri işaretle — ayrıcalık
  yükseltme vektörü envanteri ([Bölüm 7](/oscp/07-ad-saldirilari/)).

### 5.4 Oturumlar ve logon bilgisi
**Ne:** Kimin nerede oturum açtığını bilmek lateral movement'ı planlamayı sağlar.

```powershell
Get-NetSession -ComputerName <HOST>     # NetSessionEnum; erişim reddedebilir (aşağıya bak)
Get-NetSession -ComputerName <HOST> -Verbose
# Sessiz alternatif (Sysinternals): Remote Registry gerekir
.\PsLoggedon.exe \\<HOST>
# Yerelde
qwinsta
```

**Tuzaklar / notlar:**
- `Get-NetSession`'ın başarılı/başarısız olması o hostta yetkin olup olmadığının
  sinyalidir; izinleri `HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity`
  (`SrvsvcSessionInfo`) registry key'i belirler — kontrol:
  `Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl`
- PsLoggedOn Remote Registry servisine bağımlıdır (Win8+ default kapalı).

### 5.5 ACL enum (privesc vektörlerinin kaynağı)
**Ne / ne zaman:** Nesneler üzerindeki ACE'ler; AD saldırılarının çoğu bir ACL
hakkının suistimalidir. En kazançlı enum budur.

İlgili haklar ve anlamları:

| Hak | Anlamı / tipik suistimal |
|---|---|
| `GenericAll` | Objede tam kontrol → parola reset, grup üyeliği |
| `GenericWrite` | Attribute yazma → `scriptPath`, sahte SPN ekleme |
| `WriteOwner` | Owner'ı değiştir → kendine WriteDACL ver |
| `WriteDACL` | ACE ekle → GenericAll kendine ver |
| `AllExtendedRights` | Parola değiştirme dahil geniş haklar |
| `ForceChangePassword` | Mevcut parolayı bilmeden parola reset |
| `Self (Self-Membership)` | Kendini gruba ekleme |

```powershell
Get-ObjectAcl -Identity <KULLANICI>
Convert-SidToName S-1-5-21-....-1104
ConvertFrom-SID S-1-5-21-....-1108

# GenericAll verenleri listele
Get-ObjectAcl -Identity "<GRUP>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} |
  select SecurityIdentifier,ActiveDirectoryRights
"S-1-5-21-....-512","S-1-5-21-....-1104" | Convert-SidToName

# Tüm domainde "ilginç" ACE'ler (built-in olmayana hakkı olanlar)
Find-InterestingDomainAcl
Find-InterestingDomainAcl -ResolveGUIDs | Out-File C:\Tools\acls.txt

# Kendi kullanıcının haklarını SID ile hedefle
$sid = Convert-NameToSid <KULLANICI>
Get-DomainObjectACL -Identity * -ResolveGUIDs | ? {$_.SecurityIdentifier -eq $sid}
```

**Tuzaklar / notlar:**
- `Find-InterestingDomainAcl` tüm ACL'i çeker → büyük ortamda dosyaya döküp
  `Select-String`/grep ile kendi SID'lerini ara.
- `-ResolveGUIDs` olmadan ExtendedRight'lar GUID döner (okunamaz). GUID → hak
  adı eşlemesi için:
  `Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * | select Name,rightsGuid`
- DCSync hakkı da bir ACL sorusudur: `Replicating Directory Changes All` hakkını
  domain kökü üzerinde kimler tutuyor bak (tam saldırı [Bölüm 7](/oscp/07-ad-saldirilari/)):
  `Get-ObjectAcl "DC=<DOMAIN>,DC=lab" -ResolveGUIDs | ? {$_.ObjectAceType -match 'Replication-Get'}`
- BloodHound bu ilişkileri çizdiği için 7. bölümdeki planı önce orada doğrula.

### 5.6 LAPS enum
**Ne / ne zaman:** LAPS kurulu makinelerin local admin parolalarını kim okuyabiliyor?

```powershell
Find-LAPSDelegatedGroups                  # LAPS okumaya yetkili gruplar
Find-AdmPwdExtendedRights                 # "All Extended Rights" = parola okuyabilir
Get-LAPSComputers                         # LAPS parolasını açık gösterir (hakkın varsa)
```

**Tuzaklar / notlar:**
- Makineyi domain'e join eden hesap o makinede All Extended Rights'a sahiptir →
  LAPS parolasını okuyabilir; join hesaplarını hedefle.
- LAPS kurulmamış makineler = local admin parolası muhtemelen ortak/ayarlanmış;
  bunlar lateral movement kolaylığıdır.

### 5.7 Share enum
```powershell
Find-DomainShare
Find-DomainShare -CheckShareAccess        # yalnızca bizim erişebildiklerimiz
Get-NetShare -ComputerName <HOST>
Find-InterestingDomainShareFile           # share'larda parola/config arama
```

## 6. SYSVOL ve GPP Parola Avcılığı

### 6.1 SYSVOL taraması
**Ne / ne zaman:** SYSVOL her domain kullanıcısına okunabilirdir; GPO scriptleri ve
**Group Policy Preferences (GPP) parolaları** burada yaşar. Klasik ve hâlâ işleyen av.

```powershell
ls \\<DC>\sysvol\<DOMAIN>.lab\
Get-ChildItem \\<DC>\sysvol\<DOMAIN>.lab\Policies -Recurse -Filter Groups.xml -ErrorAction SilentlyContinue
Get-ChildItem \\<DC>\sysvol\<DOMAIN>.lab\ -Recurse -Include *.xml,*.ini,*.bat,*.ps1,*.vbs -ErrorAction SilentlyContinue |
  Select-String -Pattern "cpassword","password","pwd" -List
```

```bash
# Linux'tan aynı tarama
smbclient -U '<KULLANICI>%<PAROLA>' //TARGET/SYSVOL -c 'recurse; ls'
grep -r "cpassword" /mnt/sysvol/ 2>/dev/null
```

### 6.2 cpassword çözme (gpp-decrypt)
**Ne:** GPP `cpassword` alanı "AES-256 ile şifreli"dir ama anahtar **MSDN'de
yayınlıdır** — herkes çözebilir.

```bash
gpp-decrypt "<BASE64_CPASSWORD>"
```

**Tuzaklar / notlar:**
- MS14-025 sonrası GPP parolası yazılmıyor, ama **eski policy dosyaları** SYSVOL'da
  kalıyor — `Policies/` altında eski GUID klasörlerini de tara.
- `cpassword` bulduysan iş bitti sayılır; bulduğun hesabın grubuna bak
  (local admin mı, domain admin mı?).
- Ayrıca scriptlerde hardcoded credential, `Unattend.xml`, `.kdbx`, `.rdp`
  dosyalarını da aynı taramada yakala.

## 7. BloodHound — Toplama ve Sorgu

### 7.1 SharpHound (Windows toplayıcı)
**Ne / ne zaman:** Enum verisini graf veritabanına döker; ACL/session/group
ilişkilerini elle yakalamak imkânsızken tek taramada toplar.

```powershell
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\<KULLANICI>\Desktop\ -OutputPrefix "<DOMAIN>"
# veya binary
.\SharpHound.exe -c All --zipfilename <DOMAIN>
# DC'leri dışarıda bırak (daha az gürültü, lab ortamında pratik)
.\SharpHound.exe --CollectionMethods All --Domain <DOMAIN>.lab --ExcludeDCs
```

**Tuzaklar / notlar:**
- **KRİTİK:** BloodHound görünürlüğü toplayan kullanıcının yetkisine bağlıdır —
  her kullanıcı için **farklı** edge'ler görünebilir. Yeni credential ele
  geçirdikçe **yeniden veri topla**; eski veriyle karşılaştır.
- `locate SharpHound.exe` → `/usr/lib/...` altındaki SharpHound sürümü, kurulu
  BloodHound sürümüyle uyumludur; sürüm kayması yükleme hatası doğurur.

### 7.2 bloodhound-python (Linux toplayıcı)
**Ne:** Linux'tan credential ile toplama; domain-join makineye erişim yoksa.

```bash
sudo bloodhound-python -u '<KULLANICI>' -p '<PAROLA>' -ns TARGET -d <DOMAIN>.lab -c all
# veya hash ile
sudo bloodhound-python -u '<KULLANICI>' --hashes '<HASH>' -ns TARGET -d <DOMAIN>.lab -c all
# çıktı: *.json/zip dosyaları bulunulan klasöre
```

### 7.3 Neo4j + BloodHound kurulumu
```bash
sudo neo4j console
# auth kapalı olsun istiyorsan /etc/neo4j/neo4j.conf:
#   dbms.security.auth_enabled=false
# BloodHound GUI → "Upload Data" → zip'i yükle
```

### 7.4 Temel sorgular (Cypher)
**Ne:** Planlamanın kalbi; kaynaktan hedefe en kısa abuse path'i çizer.

```cypher
// Mevcut kullanıcının Domain Admins'e en kısa yolu
MATCH (u:User {name: '<KULLANICI>@<DOMAIN>.LAB'}),(g:Group {name: 'DOMAIN ADMINS@<DOMAIN>.LAB'})
MATCH p = shortestPath((u)-[*1..]->(g)) RETURN p

// Pre-built: "Find Principals with DCSync Rights", "Shortest Paths to High Value Targets",
// "Find Dangerous Rights for Everyone", "Kerberoastable accounts"
// Kendi grubun için genel path:
MATCH p = shortestPath((g1:Group)-[*1..]->(g2:Group)) WHERE g1.name =~ '(?i).*<GRUP>.*'
AND g2.name =~ '(?i).*admin.*' RETURN p

// Bilgisayarın başka bilgisayarda AdminTo olması (relay/pivot ipucu)
MATCH p=(c1:Computer)-[r1:MemberOf*1..]->(g:Group)-[r2:AdminTo]->(n:Computer) RETURN p
```

**Tuzaklar / notlar:**
- Kanonikleşmiş adlar büyük harf + FQDN'dir: `'DOMAIN ADMINS@<DOMAIN>.LAB'`.
- BloodHound'daki her edge bir enum bulgusudur; abuse komutları
  [Bölüm 7](/oscp/07-ad-saldirilari/)'dedir.

## 8. Savunma Durumu Enum'u (keşfin parçası)

### 8.1 Defender, AppLocker, Constrained Language
**Ne:** Araç çalıştırmadan önce engelleri bilmek patlama sesini azaltır.

```powershell
Get-MpComputerStatus                              # Defender durumu
sc query windefend
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
$ExecutionContext.SessionState.LanguageMode       # ConstrainedLanguage?
netsh advfirewall show allprofiles
```

**Tuzaklar / notlar:**
- AppLocker `powershell.exe` (system32) bloklasa bile
  `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` veya
  `powershell_ise.exe` açık kalabilir — kontrol et.
- PS 2.0 (`powershell -version 2`) logging'ı atlar; ama `-version 2` komutunun
  kendisi loglanabilir.
- CLM aktifse PowerView/Mimikatz çalışmaz → .NET binary'ler (SharpHound,
  Rubeus, Seatbelt) alternatiftir.

### 8.2 Credential Guard notu
**Ne / ne zaman:** Credential Guard (LSA Isolation) LSASS'tan plaintext/WDigest
parolalarını ve NTLM hash türetimini zorlaştırır. **Enum edilmesi:**
`lsaiso.exe` process'i varsa Guard aktiftir; `msinfo32` veya
`Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard`
(örn. `SecurityServicesRunning` içinde `2` = Credential Guard).

**Tuzaklar / notlar:**
- CG aktifse LSASS dump'tan çoğu credential gelmez; yön değiştir:
  Kerberos ticket'ları (sekurlsa::tickets), SAM/LSA secrets, token impersonation,
  DCSync (uzaktan) ve [Bölüm 7](/oscp/07-ad-saldirilari/)'deki ticket saldırıları.
- CG yalnızca credential hırsızlığını zorlaştırır; **ACL abuse, Kerberoasting,
  GPP, spraying gibi kimlik hırsızlığı gerektirmeyen vektörleri durdurmaz** —
  bu bölümün enum'u tamamen geçerlidir.

## 9. Lab Dışı (Gerçek) Domain'de İlk Adımlar

**Ne / ne zaman:** VPN/onsite erişimi verilmiş ama hiç bilgi yoksa sıralı yol:

```bash
# 1) Pasif: broadcast + trafik dinle
sudo responder -I <INTERFACE> -A
sudo tcpdump -i <INTERFACE> -w recon.pcap

# 2) Aktif: canlı hostlar + DC bul
fping -asgq 10.10.10.0/24
sudo nmap -p 88,445,389,636,3389,5985 --open 10.10.10.0/24

# 3) Credential'sız: null session / anon LDAP / kerbrute
rpcclient -U "" -N TARGET
enum4linux-ng -A TARGET -oA recon_enum
./kerbrute userenum -d <DOMAIN>.lab --dc TARGET adjectives.txt -o users.txt

# 4) İlk credential ile (spray/hash/poisoning sonucu, bkz. Bölüm 7):
nxc smb TARGET -u users.txt -p '<PAROLA>' --continue-on-success | grep +
nxc smb TARGET -u <KULLANICI> -p '<PAROLA>' --users --groups --shares --pass-pol

# 5) Kullanıcı + parola kesinleşince BloodHound topla ve plan çıkar
sudo bloodhound-python -u '<KULLANICI>' -p '<PAROLA>' -ns TARGET -d <DOMAIN>.lab -c all
```

**Tuzaklar / notlar:**
- Harici DNS yoksa iç DNS'i öğrenmek ilk iş: `ipconfig /all`'den DHCP sunucusu,
  veya pcap'ta DNS/MDNS sorguları.
- OSINT (bgp.he.net, Google dork'ları, sızıntı veritabanları) domain adını ve
  kullanıcı adı formatını (`ad.soyad` vs `ads`) önceden verir — wordlist'i buna göre üret.
- Her yeni credential'da: kim bu kullanıcı (grup), nereye admin (ACL/session),
  hangi SPN'leri var → matrisi güncelle.

## 10. Enum Çıktısını Saldırı Planına Çevirme

**Ne:** Ham çıktıyı önceliklendirilmiş saldırı listesine dönüştürme şablonu.

| Bulgu (enum) | Anlamı | Sonraki adım |
|---|---|---|
| SPN'li kullanıcı hesabı | Kerberoasting adayı | TGS iste + offline kır ([Bölüm 7](/oscp/07-ad-saldirilari/)) |
| `GenericAll/ForceChangePassword` hedef üzerinde | Parola reset / grup ekleme | PowerView abuse chain ([Bölüm 7](/oscp/07-ad-saldirilari/)) |
| `WriteDACL/WriteOwner` | Kendine hak yaz | → GenericAll'a yükselt |
| Nested grup üyeliği ile hedefe hak | Görünmez privesc | `Get-ADGroupMember -Recurse` ile doğrula |
| SYSVOL'da `cpassword` | Anında credential | `gpp-decrypt` → hesabın yetkisini sorgula |
| LAPS okuyabilen hesap | Local admin parolası | `Get-LAPSComputers` → PtH ile eriş |
| DCSync hakkı tutan hesap | NTDS dump yetkisi | DCSync → domain compromise ([Bölüm 7](/oscp/07-ad-saldirilari/)) |
| `Find-LocalAdminAccess` çıktısı | Hazır lateral yol | WMI/WinRM/PsExec ile geç ([Bölüm 7](/oscp/07-ad-saldirilari/)) |
| Reversible encryption (UAC 128) | Cleartext parola NTDS'te | DCSync/dump'ta plaintext düşer |
| Trust ilişkisi | Cross-domain path | `Get-DomainTrustMapping` → forest'a çıkış |
| ESki OS + session bilgisi | Oturum hırsızlığı hedefi | token/ticket saldırıları ([Bölüm 7](/oscp/07-ad-saldirilari/)) |

**Operasyonel kurallar:**
1. Önce **düşük gürültülü** vektörler: anon/ldap enum, BloodHound, SYSVOL.
2. Her bulguyu "kimlik → yetki → hedef" üçlüsüyle not et; kanıtı kaydet
   ([Bölüm 0](/methodology/00-hazirlik/) hijyeni).
3. Lockout riski olan adımlarda (spraying) önce `badPwdCount` ve lockout
   threshold'u kontrol et.
4. Enum bitmeden saldırıya geçme; yarım harita = körlük = kilitlenmiş hesaplar.

**Kaynaklar:**
- HackTricks — AD Enum: https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/index.html
- PowerSploit / PowerView: https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
- BC-Security SharpHound: https://github.com/BloodHoundAD/SharpHound
- bloodhound-python: https://github.com/fox-it/BloodHound.py
- kerbrute: https://github.com/ropnop/kerbrute
- Microsoft — LDAP ADsPath/DN: https://learn.microsoft.com/en-us/windows/win32/adsi/ldap-adspath
- Microsoft — AD PowerShell modülü: https://learn.microsoft.com/en-us/powershell/module/activedirectory/
- SpecterOps — BloodHound/Cypher: https://bloodhound.readthedocs.io/
- Microsoft — Credential Guard: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
{% endraw %}

---

[← Bölüm 5](/oscp/05-linux-privesc/) · [Bölüm 7 →](/oscp/07-ad-saldirilari/)
