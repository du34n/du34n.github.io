---
layout: page
title: "Bölüm 1 — Port Tarama & Servis Enumerasyonu"
oscp: true
toc: true
permalink: /oscp/01-enumerasyon/
---

{% raw %}
Bu bölüm, hedefe ilk dokunuştan (host discovery) servis bazlı derin enum'a kadar
olan katmandır. Kural: **önce port, sonra servis, sonra servis bazlı enum.**
Açık port listesi çıkmadan brute-force veya exploit denemesi yapılmaz.

## Tarama Stratejisi

### 1.1 Host discovery (canlı host bulma)

**Ne / ne zaman:** Tarama öncesi ağda hangi hostların ayakta olduğunu bulur.
Windows hostlar ICMP'yi bloklayabilir — ping cevapsızlığı host yok demek değildir.

```bash
# ARP tabanlı keşif (aynı broadcast domaininde en güvenilir)
sudo arp-scan -I eth0 -l
sudo netdiscover -i eth0 -r 10.10.10.0/24

# Nmap ping sweep (ICMP + TCP 443 SYN + TCP 80 ACK + ICMP timestamp)
nmap -sn 10.10.10.0/24 -oG alive.txt

# ICMP cevap vermiyorsa host discovery'yi atla
nmap -Pn -p- 10.10.10.X        # -Pn: "host ayakta" varsay, taramaya devam et
```

- **Tuzak:** `-sn` sweep'i "host bulamadım" diye bitirmek yaygın hatadır;
  her zaman `-Pn` ile tam tarama da dene.

### 1.2 Hızlı tarama: rustscan → nmap

**Ne / ne zaman:** rustscan tüm TCP portlarını saniyeler içinde tarar, bulduğu
açık portları doğrudan nmap'e besler. OSCP'de zaman kazandıran varsayılan akış budur.

```bash
# Tek komutta: rustscan bulur, nmap -sC -sV ile servis/versiyon çeker
rustscan -a TARGET -- -sC -sV -oN nmap-default.txt

# Sadece port listesi
rustscan -a TARGET -g
```

- **Not:** rustscan tek başına yeterli değildir; `-sC -sV` (default script + version)
  mutlaka nmap ile alınır. Çıktıyı `nmap-default.txt` gibi dosyaya kaydet —
  [Bölüm 10](/oscp/10-vakalar/) vaka analizi bu kayıtlara dayanır.

### 1.3 Nmap ile tam TCP tarama

**Ne / ne zaman:** rustscan yoksa veya doğrulama gerekiyorsa tüm 65535 portu tarar.

```bash
# SYN scan, tüm portlar, çıktı tüm formatlarda
sudo nmap -p- --min-rate 10000 TARGET -oN nmap-alltcp.txt

# Açık portlar çıkınca: servis versiyonu + default script + OS tahmini
sudo nmap -p 22,80,445,3306 -sC -sV -O TARGET -oN nmap-detail.txt

# Ek script katmanı (güvenlik açığı taraması değil, bilgi toplama)
sudo nmap -p 445 --script "safe" -v TARGET
```

- **Tuzaklar:**
  - `-sS` SYN scan el sıkışmayı tamamlamadığı için uygulama loglarına düşmez —
    "stealth" lakabına aldanma, modern IDS/IPS bunu görür.
  - Banner'lar admin tarafından sahte servis adıyla değiştirilebilir; versiyon
    çıktısına körü körüne güvenme.
  - `-A` (aggressive) taraması çok paket üretir; zaman kısıtlı sınavda
    önce `-sV -sC`, `-A` yalnızca gerekli hostta.

### 1.4 UDP tarama

**Ne / ne zaman:** DNS, SNMP, NFS, TFTP gibi kritik servisler UDP'dedir ve
sıklıkla `open|filtered` döner. TCP temizse bile mutlaka dene.

```bash
# En yaygın UDP portları (top 100) — hızlı ön kontrol
sudo nmap -sU --top-ports 100 TARGET -oN nmap-udp-top100.txt

# Hedefli: bilinen UDP servis portları
sudo nmap -sU --open -p 53,67,68,69,111,123,161,162,500,2049,623 TARGET

# Belirli port açık görünüyorsa versiyon al
sudo nmap -sU -sV -p 161 TARGET
```

- **Tuzak:** UDP'de "filtered" ≠ kapalı. `-sV` ve servis-özel komutlarla (örn.
  `snmpwalk`) teyit et. `nmap -sU` yavaştır; `--top-ports` ile başla, sonra genişlet.

### 1.5 Nmap scriptleri (NSE)

**Ne / ne zaman:** Servisler hakkında konfigürasyon, kullanıcı, versiyon gibi
derin bilgi verir. Script yardımını mutlaka oku:

```bash
# Script kullanım kılavuzu
nmap --script-help smb-os-discovery
nmap --script-help http-headers

# Script kategorileri: default, safe, intrusive, vuln, discovery, brute...
nmap -p 80 --script http-headers TARGET
nmap -p 80 --script http-methods --script-args http.methods-url.path=/webdav/ TARGET
nmap -p 80 --script "http-*" --exclude http-brute TARGET

# Script argümanları + izlenebilirlik
nmap -p 21 --script ftp-anon --script-trace TARGET
```

### 1.6 Netcat ile manuel port kontrolü

**Ne / ne zaman:** nmap yoksa ya da tek portu hızlıca doğrulamak/banner almak
istersen. Ayrıca firewall davranışını anlamada kullanışlıdır.

```bash
# TCP port tarama (zero-I/O)
nc -nvv -w 1 -z TARGET 3388-3390

# UDP port tarama
nc -nv -u -z -w 1 TARGET 120-123

# Banner grabbing
nc TARGET 22
```

- **Windows (LOLBAS):** hedef Windows ise yerel kontrol için
  `Test-NetConnection -Port 445 TARGET` ve tüm portlar için PowerShell
  `TcpClient` döngüsü kullanılabilir.

### 1.7 Tarama trafiğini anlama (iptables ile ölçüm)

**Ne / ne zaman:** Hangi nmap seçeneğinin ne kadar trafik ürettiğini görmek
için — gürültülü taramaların etkisini kavramak sınavda zaman yönetimi sağlar.

```bash
sudo iptables -I INPUT 1 -s TARGET -j ACCEPT
sudo iptables -I OUTPUT 1 -d TARGET -j ACCEPT
sudo iptables -Z
nmap -sT TARGET
sudo iptables -vn -L   # paket/byte sayaçlarını oku
sudo iptables -Z       # sıfırla, başka tarama tipi dene
```

## Servis Bazlı Enumerasyon

Port listesi çıktıktan sonra her servis için aşağıdaki akış uygulanır:
**banner → versiyon → anonim/null erişim → kullanıcı/share/veri enum →
kimlik bilgisi varsa derin enum.** Bulunan her kimlik bilgisi önce kaydedilir,
sonra [Bölüm 3](/oscp/03-parola-saldirilari/) hash kırma / parola saldırılarına
ve [Bölüm 7](/oscp/07-ad-saldirilari/) yatay harekete beslenir.

### SMB (445/tcp, 139/tcp)

**Ne / ne zaman:** Dosya paylaşımı, kullanıcı/domain bilgisi, RID enum. Windows
ve Samba hedeflerde ilk bakılacak servislerden.

```bash
# Servis tespiti ve versiyon
nmap -v -p 139,445 --script smb-os-discovery,smb-protocols,smb-security-mode TARGET

# Anonymous / null session ile paylaşım listesi
smbclient -L //TARGET/ -N
smbmap -H TARGET -R          # recursive: tüm paylaşım/dizin ağacı

# NSE ile derin enum (null veya credential ile)
nmap -p 445 --script smb-enum-shares,smb-enum-users,smb-enum-sessions,smb-enum-domains TARGET \
  --script-args smbusername=<KULLANICI>,smbpassword=<PAROLA>

# rpcclient ile null session shell'i (Samba dahil)
rpcclient -U "" -N TARGET
#   srvinfo            → OS ve sunucu bilgisi
#   enumdomains        → domain listesi
#   netshareenumall    → tüm paylaşımlar
#   enumdomusers       → domain kullanıcıları (RID'lerle)
#   queryuser 0x1f4    → RID'den kullanıcı detayı
#   querydominfo       → domain/sunucu özeti

# RID brute-force (kullanıcı adı keşfi)
for i in $(seq 500 1100); do
  rpcclient -N -U "" TARGET -c "queryuser 0x$(printf '%x\n' $i)" \
    | grep "User Name\|user_rid\|group_rid" && echo "";
done

# Hepsi-bir-arada (mutlaka -a ile)
enum4linux -a TARGET
enum4linux -u "<KULLANICI>" -p "<PAROLA>" -a TARGET

# Paylaşıma bağlanıp dosya çekme
smbclient //TARGET/<SHARE> -N
#   prompt off → çoklu indirme için onayı kapat
#   recurse on → alt dizinlere in
#   mget *     → tümünü indir
```

- **Tuzaklar:**
  - `smb-os-discovery` yalnızca SMBv1 etkinse çalışır — modern Windows'ta
    boş döner, bu SMB yok demek değildir; `smb-protocols` ile devam et.
  - Samba config'inde `map to guest = bad user` ve `guest ok = yes` yaygındır;
    kimliksiz erişimi mutlaka dene.
  - Windows tarafında `net view \\HOSTNAME /all` ile share listelenebilir;
    `net use * /delete` eski oturumları temizler.
  - Credential yakalandıysa `smbmap -u <KULLANICI> -p <PAROLA> -H TARGET -x '<KOMUT>'`
    ile uzaktan komut çalıştırılabilir; upload/download için `--upload`/`--download`.

### SNMP (161/udp)

**Ne / ne zaman:** Ağ cihazları ve sunucularda konfigürasyon, kullanıcı, proses,
kurulu yazılım, dinlenen port bilgisi sızdırır. v1/v2c'de community string =
parola, varsayılan `public`/`private`.

```bash
# UDP 161 tara
sudo nmap -sU --open -p 161 TARGET -oG open-snmp.txt

# Community string tespiti (varsayılanlar + SecLists)
echo -e "public\nprivate\nmanager" > community.txt
onesixtyone -c community.txt TARGET
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt TARGET

# Tüm MIB tree'yi çek
snmpwalk -v2c -c public TARGET
snmpwalk -v2c -c public TARGET -Oa        # hex string'leri ASCII'ye çevir

# Windows'a özel hedefli OID'ler
snmpwalk -v2c -c public TARGET 1.3.6.1.4.1.77.1.2.25   # yerel kullanıcılar
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.4.2.1.2  # çalışan prosesler
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.6.3.1.2  # kurulu yazılımlar
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.6.13.1.3    # dinlenen TCP portlar

# Community biliniyorsa OID brute-force (hızlı toplu çekim)
braa public@TARGET:.1.3.6.*
```

- **Tuzaklar:**
  - `rwcommunity noauth` gibi bir satır bulursan OID tree **yazılabilir** — config
    değiştirme yetkisi demek.
  - Community string'ler bazen host adı + sembol kalıbındadır (örn.
    `switch1-ro`); örüntüyü çözüp crunch ile kelime listesi genişlet.
  - v1/v2c şifresizdir; LAN'da dinleyerek community string ele geçirilebilir.

### SMTP (25/tcp, 587, 465)

**Ne / ne zaman:** Kullanıcı adı doğrulama (VRFY/EXPN/RCPT TO) ve open relay
tespiti. Elde edilen kullanıcı listesi parola saldırılarına gider.

```bash
# Elle VRFY / EXPN / RCPT denemesi
nc -nv TARGET 25
EHLO <DOMAIN>.lab
VRFY root                 # 250/252 = var olabilir, 550 = yok
EXPN all                  # dağıtım listesi tüm üyeleri döker
MAIL FROM: test@<DOMAIN>.lab
RCPT TO: <KULLANICI>      # 550 = kullanıcı yok, 250/2.1.5 = var
DATA                      # . ile bitir
QUIT

# Otomatik enum (VRFY / EXPN / RCPT modları)
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t TARGET

# Open relay kontrolü
nmap -p 25 -Pn --script smtp-open-relay TARGET

# Relay bulunursa sahte mail (phishing zemini)
swaks --from notifications@<DOMAIN>.lab --to employees@<DOMAIN>.lab \
  --header 'Subject: Bildirim' --body 'https://example.org/' --server TARGET
```

- **Tuzak:** Bazı sunucular `252` koduyla var olmayan kullanıcıyı da "onaylar";
  doğruluk için RCPT TO yanıtındaki `550 5.1.1 ... User unknown` cevabına güven.
- **Not:** POP3 (110/995) ve IMAP (143/993) açıksa aynı kullanıcı listesiyle
  parola denemesi yapılır; mail brute-force'da kullanıcıya `@<DOMAIN>` eklemeyi unutma.
- **Cloud:** hedef Office 365 kullanıyorsa `o365spray.py --validate/--enum/--spray`
  ile kullanıcı enum ve parola spraying yapılır (lockout'a dikkat) — detay
  [Bölüm 3](/oscp/03-parola-saldirilari/).

### LDAP (389/tcp, 636, 3268)

**Ne / ne zaman:** AD ortamında kullanıcı, grup, bilgisayar, OU envanteri.
Domain keşfinin anahtarı; derin AD teknikleri [Bölüm 6](/oscp/06-ad-enumerasyon/).

```bash
# Tespit ve naming context bulma
nmap -p 389,636,3268 --script ldap-rootdse TARGET

# Anonymous bind ile naming context çek
ldapsearch -x -H ldap://TARGET -s base namingcontexts
#   dn: → DC=<DOMAIN>,DC=lab gibi root DN döner

# Anonymous tarama (root DN ile)
ldapsearch -x -H ldap://TARGET -b "DC=<DOMAIN>,DC=lab" "(objectClass=*)" | head

# Kullanıcıları çek (varsa kimlikle)
ldapsearch -x -H ldap://TARGET -D "<KULLANICI>@<DOMAIN>.lab" -w '<PAROLA>' \
  -b "DC=<DOMAIN>,DC=lab" "(objectClass=user)" sAMAccountName
```

- **Tuzak:** Anonymous bind çoğu modern AD'de kapalıdır ama sınav/lab
  ortamında sık açıktır — mutlaka dene; `enum4linux -a` LDAP çıktısını da birleştirir.
- Global Catalog 3268/tcp bütün forest'ı listeler; domain adını bilmeden önce oraya bak.

### NFS (2049/tcp, 111/tcp/udp)

**Ne / ne zaman:** Linux/Unix dosya paylaşımı. `no_root_squash` bulunursa
yetki yükseltme zemini oluşur ([Bölüm 5](/oscp/05-linux-privesc/)).

```bash
# Tespit ve export listesi
sudo nmap --script nfs* -sV -p 111,2049 TARGET
showmount -e TARGET           # hangi dizinler kime açık?

# Mount et ve gez
mkdir -p target-nfs
sudo mount -t nfs TARGET:/ ./target-nfs/ -o nolock
ls -l  target-nfs/            # kullanıcı/grup isimleri
ls -n  target-nfs/            # UID/GID numaraları — sahiplik analizi
tree target-nfs/

# Kopya çek, sonra unmount et
sudo umount ./target-nfs
```

- **Tuzaklar:**
  - Export yalnızca belirli ağlara açıksa mount edemezsin — VPN/tünel alt ağını
    export kapsamına sokmak gerekebilir ([Bölüm 8](/oscp/08-pivoting/)).
  - `no_root_squash` + yazılabilir export = root olarak dosya yazıp SUID
    çalıştırılabilir; ama önce `no_subtree_check`, `rw`, `insecure` kombinasyonlarını not al.
  - NFSv3'te kimlik doğrulama yoktur; UID/GID eşleşmesi yeterlidir. Client ve
    server'da aynı UID farklı kullanıcıya denk gelebilir — `ls -n` ile sayısal bak.

### FTP (21/tcp, 20)

**Ne / ne zaman:** Dosya sunucusu. Anonymous erişim ve directory traversal
(`../`) klasik ilk erişim yoludur.

```bash
# Tespit + anon kontrolü
nmap -p 21 --script ftp-anon,ftp-syst,ftp-bute TARGET --script-args userdb=users.txt

# Anonymous bağlan
ftp TARGET                    # kullanıcı: anonymous, parola: boş veya e-posta
ls -la                        # gizli dosyaları da göster
ls -R                         # recursive listeleme (sunucuda açıksa)

# Tüm siteyi indir
wget -m --no-passive ftp://anonymous:anonymous@TARGET/

# TLS'li FTP'de sertifikayı/banner'ı gör
openssl s_client -connect TARGET:21 -starttls ftp
```

- **Tuzaklar:**
  - `ftp-anon` NSE scripti anon erişimi bulursa kök dizin içeriğini otomatik
    listeler — `ftp-syst` ile STAT bilgisi (sunucu versiyonu) değerlidir.
  - vsFTPd, ProFTPD gibi servislerin eski versiyyonlarını (ör. mod_copy RCE)
    exploit veritabanlarında ara; versiyon banner'dan gelir.
  - `debug`, `trace`, `stat` komutları sunucudan ek bilgi sızdırabilir.

### SSH (22/tcp)

**Ne / ne zaman:** Uzak kabuk. Enum, auth yöntemlerini ve zayıf
konfigürasyonu tespit etmekle sınırlıdır.

```bash
# Banner ve algoritmalar
nc TARGET 22
nmap -p 22 --script banner,ssh2-enum-algos TARGET
nmap -p 22 --script ssh-hostkey --script-args ssh_hostkey=full TARGET

# İzin verilen auth yöntemleri (none/password/publickey bilgisi)
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=<KULLANICI>" TARGET

# Konfig zayıflık denetimi
./ssh-audit.py TARGET

# Sadece parola auth denemek için
ssh -v <KULLANICI>@TARGET -o PreferredAuthentications=password
```

- **Tuzaklar:**
  - `none_auth` dönüyorsa parolasız giriş mümkündür — hemen dene.
  - Tehlikeli ayarlar: `PermitEmptyPasswords yes`, `PermitRootLogin yes`,
    `Protocol 1`. Bunlar brute-force'u mantıklı kılar.
  - SSH anahtarı bulduysan parolası varsa kır (`ssh2john`) — [Bölüm 3](/oscp/03-parola-saldirilari/).
  - Banner'lar admin tarafından değiştirilebilir; gerçek versiyyonu
    `ssh2-enum-algos` imzasından doğrula.

### HTTP ilk bakış (80, 443, 8080 vb.)

**Ne / ne zaman:** Web yüzeyi varsa önce hızlı pasif karakterizasyon, sonra
[Bölüm 2](/oscp/02-web-saldirilari/)'ye derinlemesine geçiş. Buradaki amaç
"servis ne, ne kadar yüzey var" sorusunu 5 dakikada cevaplamak.

```bash
# Banner + başlıklar
curl -sik http://TARGET/ | head -40
nmap -p 80 --script http-headers,http-title TARGET

# Teknoloji fingerprint
whatweb http://TARGET/
wafw00f http://TARGET/ -a          # WAF var mı?

# robots.txt + sitemap.xml (gizli yol ipuçları)
curl -s http://TARGET/robots.txt
curl -s http://TARGET/sitemap.xml

# Hızlı dizin taraması
dirb http://TARGET/ /usr/share/seclists/Discovery/Web-Content/common.txt

# Metasploit yardımcıları
use auxiliary/scanner/http/http_version
use auxiliary/scanner/http/brute_dirs
use auxiliary/scanner/http/robots_txt
```

- **Tuzaklar:**
  - `robots.txt` Disallow girdileri indexlenmemesi istenen dizinleri işaret eder —
    tam da oraya bak.
  - vhost bazlı hosting'de IP ile istek default siteye düşer; `Host:` header'ı
    ve vhost fuzzing gerekebilir (Bölüm 2).
  - `dirb`/`gobuster` boş dönerse önce kelime listesini kontrol et; hata
    hedefte değil ortamdadır.
  - `phpinfo.php`, sunucu hata sayfaları versiyyon ve yol bilgisi sızdırır.

### MySQL / MSSQL / PostgreSQL (3306, 1433, 5432)

**Ne / ne zaman:** Veritabanları — boş parola, default hesaplar ve
`xp_cmdshell` gibi RCE özellikleri ile ilk erişim kaynağı.

```bash
# MySQL tespit + boş parola denemesi
nmap -p3306 --script mysql-info,mysql-empty-password,mysql-users,mysql-databases \
  --script-args mysqluser='root',mysqlpass='' TARGET
nmap -p3306 --script mysql-dump-hashes --script-args username='root',password='<PAROLA>' TARGET
nmap -p3306 --script mysql-query --script-args query='show databases;',username='root',password='<PAROLA>' TARGET

# MySQL istemcisi
mysql -h TARGET -u root -p
#   show databases;  use <DB>;  show tables;
#   select table_name,table_schema from information_schema.tables;
#   select load_file("/etc/passwd");      -- dosya okuma (FILE priv gerekir)
```

```bash
# MSSQL — bilgi + boş sa parolası + hash dump + xp_cmdshell
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info \
  -sV -p 1433 TARGET
nmap -p1433 --script ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac \
  --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password='' TARGET
nmap -p1433 --script ms-sql-dump-hashes --script-args username='<KULLANICI>',password='<PAROLA>' TARGET
nmap -p1433 --script ms-sql-xp-cmdshell \
  --script-args username='<KULLANICI>',password='<PAROLA>',cmd='whoami' TARGET

# Impacket ile Windows auth bağlantısı
python3 mssqlclient.py <DOMAIN>.lab/<KULLANICI>@TARGET -windows-auth
#   SELECT name FROM sys.databases;
#   use <DB>; SELECT * FROM INFORMATION_SCHEMA.TABLES;
```

- **Tuzaklar:**
  - MySQL'de `root` dışındaki hesaplar da default olabilir; `mysql-empty-password`
    negatifse bile yaygın parolalar dene.
  - MySQL konfig dosyaları (`my.cnf`, uygulama `config.php`/`web.config`)
    düz metin kimlik bilgisi içerir — dosya okuma yetkisiyle kap.
  - MSSQL `sa` boş parolalıysa `xp_cmdshell` ile doğrudan komut çalışır;
    kapalıysa `sp_configure` ile açmak mümkün olabilir.
  - Hash'ler (`sys.user$`, `mysql.user`, `master..syslogins`) offline kırılır —
    [Bölüm 3](/oscp/03-parola-saldirilari/).
- **PostgreSQL:** `psql -h TARGET -U postgres`; default `postgres`/`postgres`
  ve `template1` veritabanı ile dene; `COPY ... FROM PROGRAM` RCE zemini
  ([Bölüm 5](/oscp/05-linux-privesc/) bağlamında değerlendir).

### RPC / NetBIOS (111, 135, 137/udp)

**Ne / ne zaman:** RPC endpoint mapper (135) ve NetBIOS name service (137/udp)
isim, domain ve servis envanteri verir; SMB enum'un tamamlayıcısıdır.

```bash
# NetBIOS taraması (137/udp, ağ geneli)
sudo nbtscan -r 10.10.10.0/24

# nmblookup ile isim sorgusu
nmblookup -A TARGET

# RPC endpoint mapper
nmap -p 135 --script rpc-grind,msrpc-enum TARGET
rpcinfo -p TARGET        # Linux RPC (portmapper) servis kayıtları

# rpcclient null session ile domain/RPC bilgisi (bkz. SMB bölümü)
rpcclient -U "" -N TARGET -c "srvinfo"
```

- **Tuzak:** `nbtscan` yalnızca aynı segmentte çalışır; uzak hedefte
  `nmblookup -A` ve nmap NSE'ye güven. Samba için `rpcclient` null session
  sıklıkla en verimli kaynaktır.

### RDP / WinRM / rsync / IPMI / Oracle (kısa notlar)

**Ne / ne zaman:** Ana hedefler değil ama yan servisler ilk erişim kapısı olur.

```bash
# RDP (3389) — NLA ve şifreleme denetimi
nmap -sV -sC -p 3389 --script rdp* TARGET
./rdp-sec-check.pl TARGET
xfreerdp /u:<KULLANICI> /p:'<PAROLA>' /v:TARGET

# WinRM (5985/5986) — evil-winrm ile shell
evil-winrm -i TARGET -u <KULLANICI> -p '<PAROLA>'

# rsync (873) — anon paylaşım listeleme ve çekme
nc -nv TARGET 873            # @RSYNCD: 31.x gör → "#list" gönder
rsync -av --list-only rsync://TARGET/<MODUL>
rsync -av rsync://TARGET/<MODUL> ./

# IPMI/BMC (623/udp) — default creds + RAKP hash dump
sudo nmap -sU --script ipmi-version -p 623 TARGET
use auxiliary/scanner/ipmi/ipmi_dumphashes      # hashcat -m 7300 ile kır

# Oracle TNS (1521) — SID brute + ODAT
sudo nmap -p1521 -sV --script oracle-sid-brute TARGET
./odat.py all -s TARGET
sqlplus <KULLANICI>/<PAROLA>@TARGET/<SID>       # as sysdba dene
```

- **Tuzaklar:**
  - RDP NLA açıksa kullanıcı doğrulaması bağlantı öncesi yapılır — brute-force
    izleri daha belirgin olur; lockout politikasına dikkat.
  - IPMI 2.0 RAKP hatası herhangi bir geçerli kullanıcının salt'lı hash'ini
    sızdırır; default BMC parolaları (örn. `root/calvin`, `ADMIN/ADMIN`)
    önce elle dene.
  - rsync SSH üzerinden çalışıyorsa `-e ssh` (veya `-e "ssh -p 2222"`) ekle.

## İlk Erişim Öncesi Kontrol Listesi

İlk exploit/login denemesinden önce şu tablo tamamlanmış olmalı:

1. **Port envanteri:** Tam TCP (`-p-`) + hedefli UDP taraması kayıtlı
   (`nmap-alltcp.txt`, `nmap-udp*.txt`). Açık portun altında servis/versiyon
   (`-sV -sC`) kayıtlı mı?
2. **Her açık port için not:** Banner, versiyon, anon/null erişim denendi mi?
   Sonuç (açık / kapalı / belirsiz) yazılı mı?
3. **Kimlik bilgisi stoğu:** Enum'dan geçen her kullanıcı adı, parola, hash,
   anahtar ayrı kaydedildi mi? Kaynağı (hangi servis/dosya) notlandı mı?
4. **Versiyon → CVE eşlemesi:** Her servis versiyonu exploit-db/CVE karşılığı
   için arandı mı? (Bkz. [Bölüm 9](/oscp/09-istemci-av/) derleme/uyarlama.)
5. **Default / zayıf kimlik:** Tüm servislerde default parolalar, boş parola,
   anonymous erişim denendi mi?
6. **Parola saldırı planı:** Kullanıcı listesi × parola listesi hangi servislere
   (SSH/SMB/FTP/SQL/web form) uygulanacak, lockout riski nedir?
   (Bkz. [Bölüm 3](/oscp/03-parola-saldirilari/).)
7. **Web yüzeyi:** HTTP varsa teknoloji, dizinler, WAF, vhost tarandı mı?
   (Derin saldırı [Bölüm 2](/oscp/02-web-saldirilari/)'ye geçer.)
8. **AD sinyalleri:** 389/636/3268, 88 (Kerberos), 445 + domain adı bulunduysa
   akış [Bölüm 6](/oscp/06-ad-enumerasyon/)'ya kayar.
9. **Pivot ihtiyacı:** Hedef iç ağda başka hostlar gösteriyorsa (route, ARP,
   SNMP) pivot planı notlandı mı? (Bkz. [Bölüm 8](/oscp/08-pivoting/).)
10. **Kanıt hijyeni:** Tüm komutlar ve çıktılar dosyaya kayıtlı; zamanaşımı ve
    tekrar üretilebilirlik sağlandı mı?

> Kural: Yukarıdaki listede boş kutu varken "sıkıştım" demek erken değildir —
> enum bitmemiştir. OSCP makinelerinin büyük çoğunluğu ilk erişimi tamamlanmış
> enum'da verilmiş kimlik bilgisiyle verir.

{% endraw %}

---

[← OSCP Notları](/oscp/)

[Bölüm 2 →](/oscp/02-web-saldirilari/)
