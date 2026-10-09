---
layout: page
title: "Bölüm 1 — Keşif & Enumerasyon (Blackbox)"
methodology: true
toc: true
permalink: /methodology/01-kesif-enumerasyon/
---

{% raw %}
Fazın çıkışı: elimine edilmiş, çalışan (live), sınıflandırılmış asset envanteri ve
bir threat model taslağı. Sıralı çalışılır; her adım bir sonrakinin girdisini üretir.

### 1.1 Pasif keşif & OSINT
**Ne:** Hedefe tek paket göndermeden (veya minimum) bilgi toplama: DNS kayıtları,
sertifika kayıtları, sızdırılmış kimlikler, kaynak kod/forks, doküman metadatası.
İlk subdomain ve teknoloji ipuçları burada çıkar.

**Saldırı yüzeyi / nerede:** Kurumsal domain kayıtları, WHOIS, CT logları, iş
ilanları (stack sızıntısı), GitHub/GitLab, paste siteleri, e-posta formatı.

**Tespit — adım adım:**
1. WHOIS ve NS kayıtlarından kayıt firması (registrar) + DNS sağlayıcı çıkar.
2. crt.sh üzerinden CT loglarından tüm SAN'ları çek (wildcard'ları da).
3. Arama motoru dork'ları ile login/admin/doküman/index yüzeylerini bul.
4. GitHub/GitLab'da organizasyonu ara: `.env`, `config`, `secret`, sızmış token.
5. Leak/credential kontrolü (müşteri izniyle) → parola-spray adayları.
6. İş ilanları/docs'tan teknoloji stack'i ve e-posta formatını türet.

**Araçlar & komutlar:**
```bash
T=example.com
# WHOIS + NS
whois $T | tee recon/whois.txt
dig +short NS $T | tee recon/ns.txt

# Sertifika şeffaflığı (CT) — tüm isimler
curl -s "https://crt.sh/?q=%25.$T&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee recon/ct_names.txt
# Organizasyon bazlı CT
curl -s "https://crt.sh/?O=Example+Inc&output=json" | jq -r '.[].name_value' | sort -u

# Arama motoru dork'ları (manuel / API)
#   site:T -www
#   site:T ext:env | ext:sql | ext:bak | ext:log
#   site:T inurl:login | inurl:admin | inurl:api
#   inurl:T "password" filetype:pdf

# GitHub secret arama (organizasyon)
#   gh/search: "T.com" password  |  "T.com" api_key
#   github.com/search?q=org%3A<ORG>+password&type=code
```
**Teknik notları / tuzaklar:**
- crt.sh sık 502/timeout verir → retry + `-H 'User-Agent: ...'`, alternatif
  Censys/Shodan/certspotter.
- `%25.` ile wildcard araması zorunlu; `%25` = URL-encoded `%`.
- WHOIS privacy arkasındaki kayıt alt etki alanını gizler; NS/MX/TXT kayıtları
  sağlayıcı ipucu verir (Google Workspace, M365, Cloudflare).

**Doğrulama barı (çıktı kriteri):** Kaynak atıflı (source-attributed) isim/stack/
e-posta listesi; her satır EN AZ bir kanonik kaynağa (CT, WHOIS, dork URL) bağlı.

**Yanlış pozitif / tuzaklar:** Sosyal medya/forum'da geçen "eski" host'lar artık
başka sahibe ait olabilir; ayrıca CDN/üçüncü taraf isimleri hedef sanmak. Pasif
kayıt canlılık kanıtı DEĞİLDİR → 1.3'te DNS ile doğrula.

**Öncelik / kritiklik:** Yüksek — subdomain ve stack ipuçlarının ana kaynağı.
Sızmış credential bulunursa doğrudan hesap devralma yolu açılabilir.

**Kaynaklar:**
- OWASP WSTG-INFO-01 — Search Engine Discovery: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage
- OWASP WSTG-INFO-02 — Fingerprint Web Server: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server
- HackTricks — External Recon: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html
- CWE-200 (Information Exposure) — https://cwe.mitre.org/data/definitions/200.html

### 1.2 Subdomain enumeration (pasif + aktif + permütasyon)
**Ne:** Hedef domain altındaki tüm alt alanların toplanması. Pasif kaynak
(CT/DNS API'leri) + aktif brute-force + permütasyon (isim kalıbı türetme).

**Saldırı yüzeyi / nerede:** `*.T` tüm host'lar; staging/dev/internal adlandırma
kalıpları; sertifika SAN'ları.

**Tespit — adım adım:**
1. Pasif toplama: `subfinder -all -recursive` (CT + birçok kaynak).
2. CT + OSINT çıktısını birleştir, dedupe et.
3. Aktif DNS çözümlemesiyle canlı olanları ayır (`dnsx`).
4. Wildcard'ı tespit et (1.3) — tüm `*` çözümleniyorsa brute-force gürültü üretir.
5. Permütasyon: bilinen kalıplardan yeni aday isim üret (`alterx`), çözümle.
6. Kalıcı (persistent) brute-force: büyük SecLists listesi + güvenli rate.

**Araçlar & komutlar:**
```bash
T=example.com
# 1) Pasif
subfinder -d $T -all -recursive -silent -o recon/subs_passive.txt
# 1b) JSONL + kaynak atfı (hangi kaynak hangi host'u verdi)
subfinder -d $T -all -oJ -cs -o recon/subs_sourced.jsonl

# 2) CT + OSINT birleştir
cat recon/subs_passive.txt recon/ct_names.txt | sort -u > recon/subs_all.txt

# 3) Aktif çözümleme (canlı host'lar)
dnsx -l recon/subs_all.txt -silent -a -resp -o recon/resolved.txt
cut -d' ' -f1 recon/resolved.txt | sort -u > recon/live_subs.txt

# 5) Permütasyon (isim kalıbı)
alterx -l recon/live_subs.txt -o recon/permuted.txt
dnsx -l recon/permuted.txt -silent -a -resp -o recon/permuted_resolved.txt

# 6) Aktif brute-force (wildcard kontrolünden SONRA)
#   ffuf (DNS modu) örneği aşağıda 1.3 ile birlikte
```
**Teknik notları / tuzaklar:**
- API anahtarı olmayan subfinder düşük sonuç verir; sonuç "hedef küçük" demek değildir.
- `-recursive` bazı kaynaklarda yavaştır; `-rl` ile sınırla.
- Wildcard DNS varsa brute-force her şeye "çözümlendi" der → önce wildcard'ı çöz.
- `dnsx` yalnızca A kaydını değil AAAA/CNAME'i de kontrol etmeli; CDN arkasındaki
  host'lar CNAME ile görünür.

**Doğrulama barı (çıktı kriteri):** `dnsx` ile çözümlenmiş, dedupe edilmiş canlı
subdomain listesi; her host için A/AAAA/CNAME kaydı mevcut.

**Yanlış pozitif / tuzaklar:** Wildcard çözümlemesinden gelen sahte host'lar;
park edilmiş/expired domain'ler; başka tenant'a ait paylaşılan edge isimleri.

**Öncelik / kritiklik:** Yüksek — saldırı yüzeyi büyüklüğünü belirler. staging/
dev/test önekli host'lar en değerli (koruma zayıf olur).

**Kaynaklar:**
- OWASP WSTG-INFO-04 — Enumerate Applications on Webserver: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver
- ProjectDiscovery subfinder: https://docs.projectdiscovery.io/opensource/subfinder/usage
- HackTricks — Subdomain Enum: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html

### 1.3 DNS çözümleme, CNAME/zone & wildcard
**Ne:** Toplanan isimlerin gerçekten çözümlendiğinin, CNAME zincirlerinin (third-
party bağımlılıklar) ve wildcard/zone aktarımı durumunun belirlenmesi.

**Saldırı yüzeyi / nerede:** A/AAAA/CNAME/MX/TXT kayıtları, DNS zone transfer
(AXFR), wildcard davranışı, dangling CNAME (takeover adayı).

**Tespit — adım adım:**
1. Her canlı subdomain için A/AAAA/CNAME kaydını topla.
2. CNAME zincirlerini sakla — üçüncü taraf (S3, Heroku, Azure, GitHub Pages) ipucu.
3. Wildcard testi: rastgele yüksek-entropi etiket çözümleniyor mu?
4. NS sunucularında AXFR dene (nadir ama kritik sızıntı).
5. Dangling CNAME adaylarını işaretle (1.13 takeover ön-kontrolüne girdi).
6. MX/TXT (SPF/DMARC) kayıtlarından e-posta altyapısı ve üçüncü taraf çıkar.

**Araçlar & komutlar:**
```bash
T=example.com
# Kayıt toplama
dnsx -l recon/live_subs.txt -silent -a -aaaa -cname -mx -txt -resp \
  -o recon/dns_records.txt

# CNAME zinciri
dig +short CNAME www.$T

# Wildcard testi (yüksek entropi etiket)
rand=$(head -c8 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c12)
dig +short A ${rand}.$T   # BOŞ dönmeli; dönerse WILDCARD VAR

# Zone transfer (yetkisiz AXFR) denemesi
for ns in $(dig +short NS $T); do
  echo "== $ns =="; dig axfr $T @$ns
done

# DNS brute-force (ffuf, wildcard filtresi ile)
ffuf -u "https://FUZZ.$T" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -mc all -fc 404 -of md -o recon/ffuf_dns.md -t 40 -rate 100
```
**Teknik notları / tuzaklar:**
- AXFR neredeyse hiç açık olmaz; açıksa tüm zone tek komutla sızar (yüksek değer).
- Wildcard CDN (Cloudflare/Akamai) yüzünden neredeyse her etiket çözümlenebilir;
  bu durumda brute-force yalnızca *aynı içeriği* döner → response fingerprint'i filtrele.
- CNAME zinciri sağlayıcıya çıkar: `*.s3.amazonaws.com`, `*.herokuapp.com`,
  `*.github.io`, `*.azurewebsites.net`, `*.cloudfront.net`, `*.fastly.net`.

**Doğrulama barı (çıktı kriteri):** Kayıtları toplanmış canlı host listesi +
wildcard VAR/YOK kararı (rastgele etiket testiyle) + dangling CNAME aday listesi.

**Yanlış pozitif / tuzaklar:** DNS caching eski IP döndürebilir; TTL not al.
Wildcard çözümü, brute-force sonuçlarını zehirler — filtre olmadan "bin host buldum"
tuzağı.

**Öncelik / kritiklik:** Yüksek — dangling CNAME doğrudan subdomain takeover'a,
CNAME zinciri üçüncü taraf ele geçirmeye götürür.

**Kaynaklar:**
- OWASP WSTG-INFO-10 — Map Application Architecture: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Map_Application_Architecture
- HackTricks — DNS: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-dns.html
- CWE-350 (Reliance on Reverse DNS) bağlam: https://cwe.mitre.org/data/definitions/350.html

### 1.4 Port & servis taraması
**Ne:** Canlı host'larda açık TCP/UDP portlarının ve servis sürümlerinin
belirlenmesi. Web dışı (SSH, DB, RDP, panel) yüzeyleri ortaya çıkarır.

**Saldırı yüzeyi / nerede:** Tüm in-scope IP/CIDR ve çözümlenmiş host IP'leri.

**Tespit — adım adım:**
1. Hızlı port keşfi (naabu) — top portlar, doğrulamalı.
2. Açık portları nmap ile servis/sürüm taramasına ver (`-sV -sC`).
3. Kritik portlar için hedefli script taraması (DB, SMB, RDP, panel).
4. UDP için hedefli (DNS/SNMP) — tüm UDP taraması çok yavaş.
5. Web olmayan servisleri 1.14 envanterine ayrı sınıfla yaz.

**Araçlar & komutlar:**
```bash
# 1) Hızlı keşif (doğrulama ile false-open portları ele)
naabu -l recon/live_subs.txt -top-ports 1000 -verify -silent -o recon/ports.txt

# 2) Servis/sürüm taraması (tek/az host için tam tarama)
nmap -sV -sC -Pn -T4 -p- --min-rate 2000 -oN recon/nmap_full.txt <IP>

# 2b) Çok host için önce portları besle, sonra servis
nmap -sV -sC -Pn -T4 -p $(paste -sd, <(cut -d: -f2 recon/ports.txt | sort -un)) \
  -iL recon/hosts_ips.txt -oA recon/nmap_services

# 3) Kritik port scriptleri
nmap -Pn -p 445 --script smb-vuln*,smb-enum-shares <IP>
nmap -Pn -p 3389 --script rdp-enum-encryption <IP>

# 4) Hedefli UDP
nmap -sU -Pn --top-ports 50 <IP>
```
**Teknik notları / tuzaklar:**
- `naabu -verify` kullanılmazsa false-open portlar rapor edilir.
- Firewall `-Pn` olmadan host'u "down" sanır; canlı host'ta `-Pn` şart.
- Rate limit ve IDS kaçınması: paylaşılan hostingde `--min-rate` düşür.
- UDP taraması saatler sürebilir; `--top-ports` ve timeout ile sınırla.

**Doğrulama barı (çıktı kriteri):** Doğrulanmış açık port + nmap servis/banner
çıktısı; her servis için ürün/sürüm (versiyon) bilgisi.

**Yanlış pozitif / tuzaklar:** CDN/anycast IP'leri org'a atfetmek; honeypot'lar;
rate-limit kaynaklı "port kapalı" yanılgısı.

**Öncelik / kritiklik:** Orta-Yüksek — açık DB (3306/5432/27017/6379), elastic
(9200), RDP (3389), yönetim paneli portları yüksek değerde ama genelde scope
kısıtı ve rate limit gerekir.

**Kaynaklar:**
- OWASP WSTG-CONF-01 — Network Infrastructure Configuration: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- ProjectDiscovery naabu: https://docs.projectdiscovery.io/opensource/naabu/usage
- Nmap Book — https://nmap.org/book/

### 1.5 HTTP probing, teknoloji & versiyon fingerprint
**Ne:** Çözümlenmiş host'ların canlı HTTP(S) servislerini tespit edip status,
başlık, sunucu ve teknoloji yığınını çıkarma. Fazın en kritik birleştirme adımı.

**Saldırı yüzeyi / nerede:** Tüm http/https host:port kombinasyonları.

**Tespit — adım adım:**
1. Tüm host:port'ları httpx'e ver; şema fallback ile http+https dene.
2. Status, title, server, teknoloji, redirect zinciri, TLS sertifika SAN'larını topla.
3. Yanıt gövdelerini sakla (JS/route/secret analizine girdi).
4. Ölü/duplicate/CDN-edge host'ları ele; distinct origin'a indir.
5. Web olmayan portları (raw TCP banner) ayrıca kaydet.

**Araçlar & komutlar:**
```bash
# Tüm host + portları besle (naabu çıktısını 'host:port' olarak)
naabu -l recon/live_subs.txt -top-ports 100 -silent -o recon/hp.txt
# httpx tek geçiş: canlılık + fingerprint + cert SAN + gövde
httpx -l recon/hp.txt -sc -title -server -td -fr -location \
  -tls-grab -jarm -json -o recon/httpx.jsonl -sr -srd recon/httpx_store

# Plain URL listesi (crawler'a)
httpx -l recon/hp.txt -silent -o recon/live_urls.txt

# Eksik şema vb. için no-fallback ile tekrar
httpx -l recon/hp.txt -nf -sc -title -silent
```
**Teknik notları / tuzaklar:**
- `-silent` hataları gizler; debug için `-debug` veya JSON çıktısını oku.
- `-tls-grab`/`-jarm` CDN ve sertifika atfında; SAN'lar yeni host seed'i olur.
- `-sr -srd` gövde saklar; disk hijyeni için iş bitince raw'ı temizle (distill et).
- HTTP→HTTPS redirect zinciri loglama: open redirect / host-header ipuçları.

**Doğrulama barı (çıktı kriteri):** Canlı URL listesi (status + title + tech) ve
sertifika SAN listesi; web olmayan servisler ayrık.

**Yanlış pozitif / tuzaklar:** Aynı origin'ın onlarca CDN hostname alias'ı
"yüzey büyüdü" yanılgısı yaratır; default/parked sayfaları (S3 NoSuchBucket,
nginx default, "Index of /") tespit edip etiketle.

**Öncelik / kritiklik:** Yüksek — sonraki tüm web testleri bu canlı sete bağlı.

**Kaynaklar:**
- OWASP WSTG-INFO-02 — Fingerprint Web Server: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server
- OWASP WSTG-INFO-08 — Fingerprint Web Application Framework: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework
- ProjectDiscovery httpx: https://docs.projectdiscovery.io/opensource/httpx/usage

### 1.6 WAF / CDN / reverse-proxy tespiti
**Ne:** Hedef önünde WAF, CDN veya reverse-proxy olup olmadığını belirleme. Bu,
hem orijin (origin) keşfini hem de test stratejisini (rate limit / evasion)
etkiler.

**Saldırı yüzeyi / nerede:** Her canlı host; özellikle login/api uç noktaları.

**Tespit — adım adım:**
1. wafw00f ile WAF/CDN ürününü parmak izle.
2. DNS CNAME + IP ASN ile CDN sağlayıcısını doğrula (Cloudflare, Akamai, Fastly).
3. Header imzaları (`server`, `cf-ray`, `x-akamai-*`, `via`, `x-cache`) incele.
4. Var ise: orijin IP keşif yollarını (DNS geçmişi, subdomain'ler, cert) not et.
5. Rate limit davranışını ölç (küçük hacimli zararsız isteklerle) — eşik/hedefli
   strateji için.

**Araçlar & komutlar:**
```bash
cat recon/live_urls.txt | xargs -n1 wafw00f 2>/dev/null | tee recon/waf.txt
# Tek host, agresif tespit
wafw00f -a https://T

# Header imzaları
curl -sI https://T | grep -Ei 'server|cf-ray|x-akamai|via|x-cache|x-served-by'

# CDN / ASN (CNAME veya IP'den)
whois -h whois.cymru.com " -v $(dig +short T | head -1)"
```
**Teknik notları / tuzaklar:**
- wafw00f yanlış pozitif verebilir (özellikle generic reverse-proxy'lerde).
- CDN arkası orijin IP'ye doğrudan gitmek genelde CDN ToS ihlali olabilir; scope teyit et.
- Rate limit ölçümü ile agresif fuzzing çakışır; önce eşiği nazikçe öğren.

**Doğrulama barı (çıktı kriteri):** WAF VAR/YOK + ürün adı (kanıtlı header/davranış);
CDN sağlayıcısı ve varsa orijin keşif notu.

**Yanlış pozitif / tuzaklar:** Küçük/generic proxy'i WAF sanmak; header taklidi
(spoofed) ile yanlış atıf.

**Öncelik / kritiklik:** Orta-Yüksek — evasion stratejisi ve test hızını belirler;
WAF'ı atlatabilmek birçok injection bulgusunun kaderini belirler.

**Kaynaklar:**
- OWASP WSTG-CONF-01 — Network Infrastructure Configuration: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- wafw00f — https://github.com/EnableSecurity/wafw00f
- HackTricks — WAF bypass: https://book.hacktricks.wiki/en/pentesting-web/web-tool-wafs/index.html

### 1.7 İçerik, dizin ve route keşfi
**Ne:** Gizli dizin, dosya, yapılandırma, backup ve route'ların fuzzing/brute-force
ile ortaya çıkarılması. Bilinen dosya (robots, sitemap, .well-known) ve uzantı
denemeleri dahil.

**Saldırı yüzeyi / nerede:** Tüm web kökleri; `/admin`, `/api`, `/backup`,
`/.git`, `/.env`, `*.bak`, `*.old`, `*.zip`.

**Tespit — adım adım:**
1. Bilinen dosyaları çek: `robots.txt`, `sitemap.xml`, `.well-known/security.txt`.
2. Baseline (soft-404) davranışını ölç: rastgele yol ne döner (status/size)?
3. ffuf ile dizin/dosya fuzz (baseline'a göre `-fc/-fs` filtresi).
4. Uzantı keşfi: `.bak .old .zip .tar.gz .sql .env .swp .log ~`.
5. dirsearch/gobuster ile ikinci geçiş (farklı wordlist, farklı kalıp).
6. Bulunan her yolu 1.5/1.8 çıktılarıyla birleştir; live URL'lere ekle.

**Araçlar & komutlar:**
```bash
U=https://T
# 0) Bilinen dosyalar
for p in robots.txt sitemap.xml .well-known/security.txt humans.txt; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "$U/$p"); echo "$code $p";
done

# 2) Baseline: rastgele yol
curl -sk -o /dev/null -w 'status=%{http_code} size=%{size_download}\n' "$U/$(head -c8 /dev/urandom|base64|tr -dc a-z0-9|head -c12)"

# 3) ffuf dizin fuzz (soft-404 filtresi)
ffuf -u "$U/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc all -fc 404 -fs <BASELINE_SIZE> -t 40 -rate 100 -of json -o recon/ffuf_dirs.json

# 4) uzantı keşfi
ffuf -u "$U/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .bak,.old,.zip,.tar.gz,.sql,.env,.log,~ -mc all -fc 404 -o recon/ffuf_ext.json

# 5) ikinci geçiş
dirsearch -u "$U" -e php,asp,aspx,jsp,js,json,txt --exclude-text='404' -o recon/dirsearch.txt
gobuster dir -u "$U" -w /usr/share/seclists/Discovery/Web-Content/common.txt -q -o recon/gobuster.txt
```
**Teknik notları / tuzaklar:**
- Soft-404 (her yola 200 dönen SPA) en büyük tuzak: `-fs` (yanıt boyu) filtresi şart.
- WAF varsa yoğun fuzz bloklanır; `-rate` düşür, header/varyasyon dene.
- `.git/HEAD`, `/.env`, `/backup.zip` bulguları yüksek değerli ama gerçek erişim
  kanıtı (içerik) ile doğrulanmalı.

**Doğrulama barı (çıktı kriteri):** Baseline'dan FARKLI yanıt veren, erişilebilir
dizin/dosya listesi; 200/301/302/403 kayıtları + içerik örneği.

**Yanlış pozitif / tuzaklar:** Yalnızca status'a bakmak (soft-404); wildcard
yönlendirmeler; CDN cache'inden dönen istekleri "canlı" sanmak.

**Öncelik / kritiklik:** Yüksek — sızmış backup/config/kaynak dosyalar doğrudan
secret ve kod ifşası; erişilemeyen admin route'ları authz testine girdi.

**Kaynaklar:**
- OWASP WSTG-CONF-04 — Review Old Backup and Unreferenced Files: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
- OWASP WSTG-INFO-03 — Review Webserver Metafiles: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage
- SecLists — https://github.com/danielmiessler/SecLists

### 1.8 Crawling & URL toplama (katana / wayback / gau)
**Ne:** Uygulamayı gezip tüm ulaşılabilir URL, parametre ve dinamik istekleri
toplama; ayrıca arşiv (Wayback/CommonCrawl) kaynaklı tarihsel URL'ler.

**Saldırı yüzeyi / nerede:** Tüm yollar, query string'ler, XHR/fetch uç noktaları,
tarihsel (artık link verilmeyen) URL'ler.

**Tespit — adım adım:**
1. Katana ile JS-farkındalıklı crawl (headless opsiyonel) + known-files.
2. gospider ile ikinci crawler geçişi (farklı kapsama).
3. Wayback/CommonCrawl (`waybackurls`, `gau`) ile tarihsel URL'ler.
4. Tümünü `anew`/`sort -u` ile dedupe; parametreli URL'leri ayır.
5. JS dosyalarını ayrı çıkar (1.9'a girdi).
6. Form ve entry point envanterini çıkar.

**Araçlar & komutlar:**
```bash
U=https://T
# 1) Katana (bounded: derinlik + süre + sayfa limiti)
katana -u "$U" -d 3 -ct 10m -mdp 2000 -fsu -jc -kf robotstxt \
  -c 10 -p 10 -rl 50 -ef png,jpg,gif,svg,css,woff,woff2,ttf,map \
  -silent -o recon/katana_urls.txt

# 2) gospider (ikinci geçiş)
gospider -s "$U" -d 3 -c 10 -t 20 --sitemap --robots -q -o recon/gospider/

# 3) Tarihsel URL'ler
cat recon/live_subs.txt | waybackurls | anew recon/all_urls.txt
gau --threads 5 T | anew recon/all_urls.txt

# 4) Dedupe + parametreli URL'ler
sort -u recon/all_urls.txt > recon/all_urls.uniq.txt
grep '?' recon/all_urls.uniq.txt | sort -u > recon/urls_with_params.txt

# 5) JS çıkarımı
grep -Ei '\.js(\?|$)' recon/all_urls.uniq.txt | sort -u > recon/js_urls.txt
```
**Teknik notları / tuzaklar:**
- Katana'nın varsayılan sayfa limiti YOK → `-mdp`/`-ct`/`-d` ile sınırlamazsan
  disk/CPU patlar. İş bitince ham crawl'ı distill edip sil.
- `waybackurls`/`gau`/`anew` sandbox'ta ön kurulu değil (0.3'te kur).
- Arşiv URL'leri ölü olabilir (410/404); canlılığı 1.5/1.7 ile doğrula.
- SPA'da statik crawl yetersiz; headless (`-hl`) + JS parse şart.

**Doğrulama barı (çıktı kriteri):** Dedupe edilmiş, parametreli/tarihsel URL seti +
JS URL listesi + form/entry-point envanteri.

**Yanlış pozitif / tuzaklar:** Arşivden gelen artık var olmayan parametreler;
analytics/CDN URL'lerini uygulama sanmak.

**Öncelik / kritiklik:** Yüksek — injection/fuzz testlerinin ham girdisi; tarihsel
URL'ler yeni (gizli) parametre ortaya çıkarır.

**Kaynaklar:**
- OWASP WSTG-INFO-06 — Identify Application Entry Points: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points
- OWASP WSTG-INFO-07 — Map Execution Paths: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application
- ProjectDiscovery katana: https://docs.projectdiscovery.io/opensource/katana/usage
- HackTricks — Wayback/arşiv: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html

### 1.9 JavaScript analizi — endpoint, secret, source map
**Ne:** Client-side JS'ten endpoint yolları, gizli anahtarlar (API key, token),
DOM XSS sink'leri ve source map (orijinal kaynak) çıkarımı. Blackbox'ta kod
sızıntısına en yakın kaynak.

**Saldırı yüzeyi / nerede:** Tüm `.js` dosyaları, bundle'lar, `.map` dosyaları,
inline script'ler, service worker.

**Tespit — adım adım:**
1. JS URL listesini indir ve beautify et.
2. LinkFinder/grep ile endpoint ve yol kalıplarını çıkar.
3. SecretFinder/nuclei ile secret ve API anahtarı tara.
4. `//# sourceMappingURL` ve `.map` dosyalarını dene → orijinal kaynak.
5. DOM XSS sink'lerini (`innerHTML`, `eval`, `document.write`, `location`) işaretle.
6. Bulunan endpoint'leri live URL setine ve param envanterine ekle.

**Araçlar & komutlar:**
```bash
# 1) İndir + beautify
mkdir -p recon/js; while read -r u; do
  f=recon/js/$(echo "$u" | md5sum | cut -c1-10).js
  curl -sk "$u" -o "$f"; js-beautify "$f" > "${f%.js}.pretty.js" 2>/dev/null
done < recon/js_urls.txt

# 2) Endpoint çıkarımı
python3 /opt/LinkFinder/linkfinder.py -i recon/js/ -o cli 2>/dev/null | tee recon/js_endpoints.txt
#   yedek: grep -oE '"/(api|v[0-9]+|graphql)[^"]*"' recon/js/*.js | sort -u

# 3) Secret taraması
python3 /opt/SecretFinder/SecretFinder.py -i recon/js/*.pretty.js -o cli 2>/dev/null \
  | tee recon/js_secrets.txt
nuclei -silent -t file/keys -t file/js -u recon/js/ 2>/dev/null | tee -a recon/js_secrets.txt

# 4) Source map
grep -rhoE 'sourceMappingURL=[^[:space:]]+' recon/js/ | sort -u
curl -sk https://T/static/app.js.map -o recon/app.js.map

# 5) Hazır script'ler (sandbox'ta mevcut)
bash /home/pentester/tools/JS-Snooper/js_snooper.sh T
bash /home/pentester/tools/jsniper.sh/jsniper.sh T
```
**Teknik notları / tuzaklar:**
- Çoğu secret client-side'da zaten publictir (Firebase config, public API key) →
  "secret" bulgusunu sömürülebilirlik ile doğrula, kör raporlama.
- Source map genelde yayınlanmaz; 404 normaldir, 200 ise yüksek değer.
- Minified kodda isim kaybı; beautify + ilgili bundle'ı ayır.

**Doğrulama barı (çıktı kriteri):** Çıkarılmış endpoint listesi (canlı doğrulanmış),
secret adayları (kullanılabilirlik test edilmiş) ve/veya source map içeriği.

**Yanlış pozitif / tuzaklar:** Public anahtarları secret sanmak; örnek/template
string'leri endpoint sanmak; frontend'de zaten açık olan config'i bulgu saymak.

**Öncelik / kritiklik:** Yüksek — sızmış gerçek secret (private key, servis token)
kritik olabilir; public anahtar genelde düşük.

**Kaynaklar:**
- OWASP WSTG-INFO-05 — Review Webpage Content: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage
- PortSwigger — Information Disclosure: https://portswigger.net/web-security/information-disclosure
- HackTricks — JS client-side: https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/index.html

### 1.10 Parametre & header keşfi (arjun vb.)
**Ne:** Görünmeyen (hidden) query/body parametrelerinin ve anlamlı header'ların
ortaya çıkarılması. Injection ve business-logic testlerinin girdisini genişletir.

**Saldırı yüzeyi / nerede:** Tüm GET/POST endpoint'leri, form action'ları, API
uç noktaları.

**Tespit — adım adım:**
1. Envanterdeki endpoint'leri topla (crawl + JS + arşiv).
2. arjun ile gizli parametreleri tahmin et (GET ve POST ayrı).
3. Her parametre için refleksiyon / uzunluk / hata-durumu farkı ölç.
4. Bulunanları param envanterine yaz; injection testine hazırla.
5. Header tabanlı girdileri not et (`X-Forwarded-*`, `X-Original-URL`, `Host`).

**Araçlar & komutlar:**
```bash
# Tek endpoint
arjun -u "https://T/api/v1/user" -m GET,POST -oJ recon/arjun_user.json

# Toplu (birden fazla URL)
arjun -i recon/urls_with_params.txt -m GET,POST --stable -oJ recon/arjun_all.json

# Refleksiyon hızlı kontrol
for p in id user debug admin test; do
  curl -sk "https://T/api/v1/user?$p=CANARY1337" | grep -q CANARY1337 && echo "reflect: $p"
done
```
**Teknik notları / tuzaklar:**
- arjun dinamik/kısa ömürlü endpoint'lerde false-positive üretir; `--stable` ve
  düşük rate kullan.
- POST-only parametreler GET ile bulunmaz → her method'u ayrı dene.
- Header gizli parametreler (`X-Forwarded-For`) authz bypass'ta kritiktir; API
  gateway arkasında sık işe yarar.

**Doğrulama barı (çıktı kriteri):** Yanıtta ÖLÇÜLEBİLİR fark yaratan (reflection,
uzunluk, hata, status) parametre/header listesi.

**Yanlış pozitif / tuzaklar:** Yanıt uzunluğu gürültüsünden gelen sahte parametreler;
ignore edilen (yok sayılan) params; CDN varyasyonları.

**Öncelik / kritiklik:** Orta-Yüksek — gizli parametreler IDOR/mass-assignment/
debug yollarının kapısı olabilir.

**Kaynaklar:**
- OWASP WSTG-INFO-06 — Identify Application Entry Points: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points
- OWASP WSTG-INPV-01/02 (Reflected/DOM XSS) bağlam: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting
- arjun — https://github.com/s0md3v/Arjun

### 1.11 Sanal host (vhost) keşfi
**Ne:** Aynı IP üzerinde farklı `Host` başlığıyla erişilen (DNS'te olmayan)
uygulamaların ortaya çıkarılması. Aynı IP'de birden çok app barındırılıyorsa
yeni yüzey açığa çıkar.

**Saldırı yüzeyi / nerede:** Paylaşılan IP'ler; yönetim/panel vhost'ları;
`internal`, `staging`, `admin` gibi tanımsız Host değerleri.

**Tespit — adım adım:**
1. Bilinen subdomain listesini vhost wordlist'ine dönüştür.
2. Baseline: rastgele Host'a dönen yanıtın boyutunu/status'unu ölç.
3. ffuf ile `Host: FUZZ.T` fuzz; baseline'dan farklı yanıtı işaretle.
4. Bulunan vhost'ları DNS'e eklemeden doğrudan `Host` başlığıyla test et.
5. Default sanal host davranışını (SNI vs Host) ayırt et.

**Araçlar & komutlar:**
```bash
IP=<target-ip>; T=example.com
# Baseline boyutu
base=$(curl -sk -H "Host: $(head -c8 /dev/urandom|base64|tr -dc a-z0-9|head -c12).$T" \
  -o /dev/null -w '%{size_download}' "https://$IP/")
echo "baseline=$base"

# vhost fuzz
ffuf -u "https://$IP/" -H "Host: FUZZ.$T" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -mc all -fs "$base" -rate 50 -of json -o recon/vhosts.json

# bulunanı doğrula
curl -sk -H "Host: admin.$T" "https://$IP/" | head -40
```
**Teknik notları / tuzaklar:**
- Wildcard/default vhost varsa `-fs` yaklaşımı işe yaramaz; başlık/title farkına bak.
- HTTPS'te SNI ile Host farklı olabilir; her ikisini de dene.
- `-fs` yanlış seçilirse tüm varyasyonlar "aynı" görünür.

**Doğrulama barı (çıktı kriteri):** Baseline'dan FARKLI içerik/status döndüren
Host değerleri + o vhost'un gerçek içeriği.

**Yanlış pozitif / tuzaklar:** CDN/edge'in tüm Host'lara aynı yanıtı dönmesi;
park sayfaları; yalnızca redirect farkı (içerik aynı).

**Öncelik / kritiklik:** Orta-Yüksek — gizli admin/internal vhost'lar authz
atlama ve ek saldırı yüzeyi demektir.

**Kaynaklar:**
- OWASP WSTG-INFO-04 — Enumerate Applications on Webserver: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver
- HackTricks — vhost discovery: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/index.html

### 1.12 API / spec keşfi (OpenAPI, WADL, GraphQL, Postman)
**Ne:** API dokümantasyonu, makine-okunur spec (OpenAPI/Swagger/WADL) ve GraphQL
introspection uç noktalarının bulunması. Spec bulunursa tüm endpoint envanteri
tek seferde çıkar.

**Saldırı yüzeyi / nerede:** `/swagger*`, `/openapi.json`, `/api-docs`, `/graphql`,
`/redoc`, `/v2/api-docs`, WSDL/WADL dosyaları, Postman koleksiyonları.

**Tespit — adım adım:**
1. Yaygın spec/UI yollarını hızlı probe et.
2. Bulunan spec'i indir ve endpoint envanterine dönüştür.
3. GraphQL: introspection açık mı? POST `{__schema{...}}`.
4. WSDL/WADL: SOAP servis metotlarını çıkar.
5. Auth gerektiren spec'ler için anonim vs. auth'lu erişimi karşılaştır.
6. Tüm API yollarını 1.7/1.8 çıktısıyla birleştir.

**Araçlar & komutlar:**
```bash
U=https://T
for p in swagger.json swagger-ui.html swagger-ui/ openapi.json api-docs \
         v2/api-docs v3/api-docs redoc graphql api/graphql .well-known/openapi.json; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "$U/$p"); echo "$code /$p";
done

# GraphQL introspection
curl -sk "$U/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{queryType{name} types{name kind}}}"}' | head -c 2000

# Spec'ten endpoint çıkarma (openapi)
curl -sk "$U/openapi.json" -o recon/openapi.json
jq -r '.paths | keys[]' recon/openapi.json 2>/dev/null | tee recon/api_paths.txt
```
**Teknik notları / tuzaklar:**
- Spec bazen yalnızca iç ağdan erişilir; dışarıdan 404 normal olabilir.
- GraphQL'de introspection kapatılmış olabilir; alan önerisi (field suggestion)
  ile şema çıkarımı dene.
- Swagger UI HTML dönebilir ama spec'i başka yolda olur (`/v3/api-docs`).

**Doğrulama barı (çıktı kriteri):** Geçerli spec dosyası (JSON/YAML parse edilebilir)
veya introspection şeması; buradan türetilmiş endpoint listesi.

**Yanlış pozitif / tuzaklar:** Swagger UI'ın default örnek içeriği; ulaşılamayan
örnek spec; statik dokümantasyon sayfaları (gerçek spec değil).

**Öncelik / kritiklik:** Yüksek — spec varsa API testleri sistematikleşir ve
eksik-yetki uçları net görünür.

**Kaynaklar:**
- OWASP API Security Top 10 — https://owasp.org/API-Security/
- OWASP WSTG-APIT-01 — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL
- HackTricks — GraphQL: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html

### 1.13 İlk zafiyet taraması (nuclei base) & subdomain takeover ön-kontrol
**Ne:** Bilinen CVE/misconfig/exposure şablonlarıyla hızlı ilk tarama ve dangling
CNAME'ler üzerinden subdomain takeover olasılığının ön elemesi. Amaç: hızlı,
gürültülü ama düşük-maliyetli bir ilk filtre; derin testlerin önceliğini belirler.

**Saldırı yüzeyi / nerede:** Tüm canlı URL'ler; tüm çözümlenmiş subdomain'lerin
CNAME zincirleri.

**Tespit — adım adım:**
1. nuclei'yi seviye/tag filtreli ve rate-limitli çalıştır.
2. Bulguları triyaj: yalnızca doğrulanabilir olanları ilerlet (scanner ≠ bulgu).
3. CNAME zincirlerini topla ve üçüncü taraf sağlayıcılara işaretle.
4. Her aday için sağlayıcı "claimable" mı kontrol et (dangling).
5. Şüpheli takeover'ları 1.14 envanterine **open_proof_gap** olarak yaz.

**Araçlar & komutlar:**
```bash
# 1) İlk tarama (gürültüyü ve outbound'u sınırla)
nuclei -l recon/live_urls.txt -as -s medium,high,critical \
  -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -ni \
  -j -o recon/nuclei_base.jsonl

# 2) CNAME zincirleri (takeover adayları)
dnsx -l recon/live_subs.txt -silent -cname -resp | tee recon/cnames.txt
grep -Ei 's3|herokuapp|github\.io|azurewebsites|cloudfront|fastly|pantheonsite|readme\.io|surge\.sh|bitbucket\.io' \
  recon/cnames.txt | tee recon/takeover_candidates.txt

# 3) nuclei takeover şablonları
nuclei -l recon/live_subs.txt -t http/takeovers/ -silent -o recon/nuclei_takeover.txt

# 4) Her aday için HTTP durumu (404 "NoSuchBucket" vb.)
while read -r c; do
  h=$(echo "$c" | awk '{print $1}'); echo "== $h =="; curl -skI "http://$h" | head -3
done < recon/takeover_candidates.txt
```
**Teknik notları / tuzaklar:**
- nuclei template false-positive oranı yüksektir; her isabeti ayrı doğrula (bkz.
  counterevidence prensibi).
- `-ni` (no-interactsh) OAST gerektiren şablonları atlar; OOB testleri için
  interactsh-client kullan.
- Takeover: dangling CNAME ≠ takeover. Sağlayıcı kaynağı gerçekten claim edilebilir
  mi + hedefin gerçekten ölü kaynağa işaret ettiği kanıtlanmalı.

**Doğrulama barı (çıktı kriteri):** Triyaj edilmiş nuclei isabetleri (her biri
manuel doğrulamaya hazır) + takeover adayları için `claimable` kanıtı (sağlayıcı
hata sayfası + boş kaynak).

**Yanlış pozitif / tuzaklar:** Version-bazlı CVE şablonlarının yanlış eşleşmesi;
paylaşılan CDN edge'i takeover sanmak; "provider default page" varken kaynağın
başkası tarafından kullanılması.

**Öncelik / kritiklik:** Orta-Yüksek — hızlı kazanç taraması; takeover doğrulanırsa
yüksek (marka/kimlik doğrulama etkisi).

**Kaynaklar:**
- OWASP WSTG-CONF-11 — Test Cloud Storage: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/11-Test_Cloud_Storage
- can-i-take-over-xyz (takeover sağlayıcı listesi): https://github.com/EdOverflow/can-i-take-over-xyz
- ProjectDiscovery nuclei: https://docs.projectdiscovery.io/opensource/nuclei/running

### 1.14 Saldırı yüzeyi envanteri ve threat model çıkarımı
**Ne:** Tüm keşif çıktısını tek, sınıflandırılmış bir saldırı yüzeyi envanterine
ve blackbox varsayımlarına dayalı bir threat model taslağına dönüştürme. Fazın
çıkış kapısı; Faz 2'nin yol haritası.

**Saldırı yüzeyi / nerede:** Toplanan tüm asset'ler; trust boundary'ler; roller;
tenant'lar; veri akışları.

**Tespit — adım adım:**
1. Asset envanterini tek tabloda birleştir: host, port, servis, teknoloji, auth
   gereksinimi, durum (live/parked), keşif kaynağı.
2. Trust boundary'leri çıkar: internet→edge/CDN→app→API→DB/queue→third-party.
3. Rolleri ve tenant'ları blackbox'ta **çıkarım** olarak yaz (login akışı, URL
   kalıpları, ID biçimleri, e-posta/tenant alanları).
4. Attacker story'leri yaz: anonim→kullanıcı, kullanıcı→admin, tenant A→tenant B,
   dış→iç (SSRF/cloud metadata), edge→orijin.
5. Her yüzeyi bir risk sınıfıyla eşle (WSTG kategorisi; Bölüm 2 numarası).
6. Belirsiz/doğrulanmamış varsayımları açıkça `open_proof_gap` olarak işaretle.
7. Önceliklendirme: yüksek değerli yüzeyler + doğrulanabilir hızlı kazançlar.

**Araçlar & komutlar:**
```bash
# Envanteri birleştir (örnek CSV)
{
  echo "host,port,scheme,status,title,tech,source"
  jq -r '[.host,.port,(.scheme // ""),(.status_code|tostring),(.title // ""),
          (.tech[]? // "" | join("|")),"'${T}'"] | @csv' recon/httpx.jsonl
} > recon/inventory.csv

# Threat model taslağı
cat > recon/threat_model.draft.md <<'EOF'
## Overview   (ne: hedef nedir, blackbox çıkarımı)
## Trust Boundaries  (edge/CDN → app → API → DB → 3rd-party)
## Actors & Roles  (anon / user / admin / tenant — ÇIKARIM, doğrulanmadı)
## Attack Surface  (host/endpoint/param envanteri; risk sınıfı eşlemesi)
## Attacker Stories  (anon→user, user→admin, A→B tenant, SSRF, orijin)
## Severity Calibration  (bu hedef için critical/high/medium/low ne demek)
EOF
```
**Teknik notları / tuzaklar:**
- Blackbox'ta roller/tenant'lar birer **hipotezdir**; bunları bulgu gibi sunma.
- Her envanter satırı bir kaynağa bağlı olmalı (nasıl bulundu?); kaynaksız satır
  sonraki fazda güvenilmez olur.
- Threat model statiktir; test ilerledikçe çürütülen varsayımları güncelle
  (amend), model kimsenin düzeltmediği ilk tahmine dönüşmesin.

**Doğrulama barı (çıktı kriteri):** Tek dedupe edilmiş asset envanteri (kaynak
atıflı) + yazılı threat model taslağı + her yüzeyin risk sınıfı ve önceliği.

**Yanlış pozitif / tuzaklar:** Aynı origin'ın çok sayıda alias'ını farklı asset
sanıp yüzeyi şişirmek; parked/expired host'ları aktif yüzeye katmak; keşif
derinliğini tamlıkla karıştırmak.

**Öncelik / kritiklik:** Kritik (faz çıkışı) — bu adım olmadan Faz 2 sistematik
değil, rastgele olur.

**Kaynaklar:**
- OWASP WSTG-INFO-10 — Map Application Architecture: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Map_Application_Architecture
- OWASP ASVS — Architecture/Design bölümü: https://owasp.org/www-project-application-security-verification-standard/
- HackTricks — External Recon → threat model: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html
- OWASP Threat Modeling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html


---
{% endraw %}

---


[← Web Pentest Methodology](/methodology/)

[← Bölüm 0](/methodology/00-hazirlik/)

[Bölüm 2 →](/methodology/02-zafiyet-siniflari/)
