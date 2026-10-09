---
layout: page
title: "Bölüm 0 — Hazırlık, Kapsam ve Kurulum"
methodology: true
toc: true
permalink: /methodology/00-hazirlik/
---

{% raw %}
Bu bölüm, herhangi bir paket isabetinde ilk 30 dakikada tamamlanması gereken
hazırlık katmanıdır. Kural: **keşif aracı çalıştırmadan önce kapsam ve yetki
yazılıdır.** Yetkisi belirsiz tek bir host bile scope dışı sayılır.

### 0.1 Kapsam, yetki ve Rules of Engagement (ROE)
**Ne:** Testin yasal ve operasyonel sınırlarını yazılı hale getiren sözleşme.
Yetki yazısı (authorization letter), in-scope/out-of-scope listesi, test penceresi
ve kabul edilebilir davranışlar burada sabitlenir. ROE yoksa test başlamaz.

**Kapsam / nerede:** Engagement intake. Girdiler: imzalı yetki yazısı, müşteri
scope dokümanı, bug-bounty program sayfası (varsa), iletişim/eskalasyon matrisi.

**Tespit — adım adım (intake kontrol listesi):**
1. In-scope asset envanterini kilitle: domain'ler, wildcard'lar (`*.T` kabul/red),
   IP/CIDR blokları, mobil/API uç noktaları, cloud hesap ID'leri.
2. Out-of-scope listesini açıkça yaz: üçüncü taraf SaaS, ödeme sağlayıcı,
   yönetilen hosting kontrol düzlemi, e-posta/sosyal mühendislik, DoS/stress.
3. Test penceresi + rate limit + bakım (frozen) penceresi belirle.
4. Cloud/CDN provider politikasını kontrol et: paylaşılan altyapıda (AWS/Azure/GCP)
   agresif tarama provider ToS'unu ihlal edebilir → yalnızca yetkili bloklarda tara.
5. Veri işleme kuralları: gerçek kullanıcı PII/PHI'ye erişilirse dur, dokümante et,
   exfiltrate etme; yalnızca minimum kanıt (tek kayıt + redaksiyon) al.
6. Kanun/uyum: KVKK/GDPR, sektör regülasyonu (PCI/ISO); ifşa (disclosure) SLA'sı.
7. Credential politikası: test hesapları sağlanacak mı; müşteri secrets yönetimi.
8. Acil durdurma (kill-switch) ve iletişim: tek isim, tek kanal, 7/24 numara.

**Araçlar & komutlar:**
```bash
# Scope'u tek dosyada tut; tüm fazlar bu dosyadan okur
cat > scope.txt <<'EOF'
example.com
*.example.com
203.0.113.0/24
EOF

# In-scope host'ları normalize et (küçük harf, tek satır)
tr '[:upper:]' '[:lower:]' < scope.txt | sort -u > scope.norm.txt
```

**Teknik notları / tuzaklar:**
- Wildcard scope (`*.T`) genelde izin VERMEZ sub-subdomain'e; teyit al.
- Bug-bounty program sayfası yetki yazısından farklı olabilir; kayıtlı proof sakla.
- "Aynı şirkete ait görünen" ama listede olmayan host = out-of-scope. Aitlik,
  scope listesine göre belirlenir, DNS sertifikasına göre değil.

**Doğrulama barı (çıktı kriteri):** İmzalı yetki + dondurulmuş in-scope dosyası +
yazılı ROE maddeleri (rate limit, pencere, veri kuralları, kill-switch).

**Yanlış pozitif / tuzaklar:** Sözlü "tamam test edebilirsin" yetki sayılmaz.
Vermiş olduğu eski bir yetki yazısı bu engagement'ı kapsamayabilir.

**Öncelik / kritiklik:** Bu adım eksikse engagement geçersizdir. Kayıt altına
alınmayan kapsam, ileride itiraz edilemez (disputable) tüm bulguları doğurur.

**Kaynaklar:**
- OWASP WSTG — yasal/etik çerçeve: https://owasp.org/www-project-web-security-testing-guide/latest/3-The_OWASP_Testing_Framework/0-The_Web_Security_Testing_Framework
- PTES (Penetration Testing Execution Standard): http://www.pentest-standard.org/
- HackTricks — metodoloji: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html
- CWE-1059 (Insufficient Examination) — kapsam eksikliği bağlamı: https://cwe.mitre.org/data/definitions/1059.html

### 0.2 Test tipleri (blackbox / greybox / whitebox) ve OWASP WSTG eşlemesi
**Ne:** Elde ne kadar bilgi olduğuna göre test modunu seçer ve her faza düşen
WSTG kontrolünü önceden eşler. Bu dokümanın BÖLÜM 1'i **blackbox** varsayar.

**Tespit — adım adım:**
1. Bilgi seviyesini belirle:
   - **Blackbox:** yalnızca domain/URL. Tüm bilgi harici keşifle toplanır (Bölüm 1).
   - **Greybox:** kısmi bilgi (bir test hesabı, kısmi API dokümanı, staging host).
   - **Whitebox:** kaynak kod / IaC / konfigürasyon erişimi (SAST + canlı doğrulama).
2. Test hesabı sayısını ve rollerini netleştir (anonim / user / admin / tenant A-B).
3. Risk sınıflarını önceliklendir (bkz. aşağıdaki eşleme).
4. Her WSTG kategorisinin bu engagement'ta **uygulanabilir / N/A** durumunu not et.

**WSTG kategori eşlemesi (blackbox akış):**
```text
INFO  (01-10)  → Bölüm 1 (tümü): search-engine recon, fingerprint, metafiles,
                 enumerate apps, entry points, exec paths, framework/app fingerprint,
                 mimari haritası
CONF  (01-11)  → Bölüm 1.4-1.7 + Bölüm 2 (misconfig, backup/unreferenced files,
                 HTTP methods, cross-domain policy, cloud storage)
IDNT  (01-05)  → Bölüm 2.1-2.6 (kullanıcı/rol eşleme, kayıt süreci, hesap
                 sağlama, parola politikası)
ATHN  (01-10)  → Bölüm 2.1-2.6 (credential transport, default creds, lockout,
                 bypass, remember-me, parola sıfırlama, zayıf parola)
ATHZ  (01-04)  → Bölüm 2.7-2.9 (directory traversal, bypass şeması, priv-esc, IDOR)
SESS  (01-09)  → Bölüm 2.2 (cookie atribütleri, fixation, CSRF, logout)
INPV  (01-13)  → Bölüm 2.14-2.36 (tüm injection sınıfları)
ERRH  (01-02)  → Bölüm 2.45 (hata mesajları, stack trace)
CRYP  (01-04)  → Bölüm 2.3/2.4 + transport (TLS, zayıf kripto, padding oracle)
BUSL  (01-09)  → Bölüm 2.37-2.43 (data validation, workflow, race, upload,
                 ödeme, hesap devralma)
CLNT  (01-13)  → Bölüm 2.29-2.36 (DOM XSS, JS execution, HTML injection,
                 client-side redirect, CSS, clickjacking)
APIT  (01-XX)  → Bölüm 2.37/2.41/2.42 (API spec, GraphQL, gRPC)
```

**Araçlar & komutlar:**
```bash
# Engagement intake şablonu
mkdir -p ~/engagements/$(date +%Y%m%d)-T/{recon,evidence,notes,report}
cat > ~/engagements/$(date +%Y%m%d)-T/notes/mode.md <<'EOF'
mode: blackbox
accounts: none
in_scope: scope.norm.txt
wstg_applicable: INFO,CONF,ATHN,ATHZ,SESS,INPV,ERRH,BUSL,CLNT,APIT
wstg_na: idnt (kayıt kapalı)
EOF
```

**Teknik notları / tuzaklar:** Greybox'ta test hesabı "yetkili" görmenin kolayıdır
ama sıklıkla yalnızca tek role sahiptir; dikey priv-esc testleri için ayrı admin
hesabı isteyin. Whitebox'ta dinamik doğrulamayı asla atlamayın (statik iz ≠ sömürü).

**Doğrulama barı (çıktı kriteri):** Seçilen mod + hesap/rol matrisi + uygulanabilir
WSTG kontrol listesi yazılı.

**Öncelik / kritiklik:** Yanlış mod seçimi (whitebox'ta blackbox gibi test etmek)
kapsama boşluğu yaratır; N/A işaretlenen her WSTG kategorisinin gerekçesi gerekir.

**Kaynaklar:**
- OWASP WSTG (Latest) — https://owasp.org/www-project-web-security-testing-guide/latest/
- OWASP ASVS — https://owasp.org/www-project-application-security-verification-standard/
- OWASP Top 10 — https://owasp.org/Top10/

### 0.3 Araç envanteri ve ortam kurulumu
**Ne:** Sandbox'ta doğrulanmış araç seti, eksik araçların kurulum yolları, kelime
listeleri ve proxy düzeneği. Amaç: tekrar üretilebilir (reproducible) komut ortamı.

**Tespit — adım adım:**
1. Ön kurulu araçları doğrula (aşağıdaki liste bu ortamda test edilmiştir).
2. Eksik olanları `go install` / `pipx` / `apt` ile tamamla.
3. SecLists kelime listelerini indir (`/usr/share/seclists`).
4. Proxy'yi (Caido) hazırla ve tüm araç trafiğini gözlemlenebilir kıl.
5. Sürümleri kaydet (`versions.txt`) — rapor eklerinde kanıt.

**Ön kurulu ve doğrulanmış araçlar:**
```text
nmap 7.99        subfinder 2.14    httpx (PD)      naabu
katana           ffuf 2.1-dev      dirsearch 1.1.6  arjun
nuclei 3.11      wafw00f           gospider         sqlmap
wapiti           interactsh-client jwt_tool         vulnx (cvemap)
govulncheck      openssl/dig/whois
Yardımcı: /home/pentester/tools/JS-Snooper/js_snooper.sh
          /home/pentester/tools/jsniper.sh/jsniper.sh
```
**Kurulu OLMAYAN, gerektiğinde kurulacaklar:**
```bash
# ProjectDiscovery & topluluk araçları (Go)
export GOPATH=$HOME/go; export PATH=$PATH:$GOPATH/bin
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/gf@latest
go install github.com/OJ/gobuster/v3@latest

# Python araçları
pipx install dirsearch            # zaten var
pipx install wafw00f              # zaten var
pip install linkfinder secretfinder 2>/dev/null || true
sudo apt-get install -y seclists

# LinkFinder / SecretFinder (manual)
git clone https://github.com/GerbenJavado/LinkFinder /opt/LinkFinder
git clone https://github.com/m4ll0k/SecretFinder /opt/SecretFinder
```
**Kelime listeleri (SecLists):**
```bash
sudo apt-get install -y seclists || \
  git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists
# Kritik listeler:
#  Discovery/Web-Content/raft-medium-directories.txt
#  Discovery/Web-Content/common.txt
#  Discovery/DNS/subdomains-top1million-110000.txt
#  Discovery/Web-Content/api/api-endpoints.txt
```
**Proxy / gözlem (Caido):**
```bash
# Caido arka planda çalışır; HTTP(S)_PROXY env zaten ayarlı.
env | grep -i proxy
# Araç trafiğini ayrıca proxy'ye zorlamak için (gerektiğinde):
#   httpx -proxy http://127.0.0.1:48080  (veya aktif Caido portu)
# Her istek list_requests ile ID'lense kanıt olarak saklanabilir.
```

**Teknik notları / tuzaklar:**
- `dirsearch` çalışırken `pkg_resources` deprecation uyarısı basar — zararsız.
- `subfinder` sonuçları API anahtarları yoksa düşük gelir; "düşük sonuç = hedefte
  az subdomain" DEĞİL. `-all -recursive` + provider config ile tekrar dene.
- Sandbox'ta `go` bin yolu `$HOME/go/bin`; PATH'e eklenmezse araç "kurulu değil"
  görünür.
- Kelime listesi yok ise ffuf/gobuster boş döner; hata hedefte değil ortamdadır.

**Doğrulama barı (çıktı kriteri):** `versions.txt` + çalışan proxy + indirilmiş
SecLists; her aracın `--version` çıktısı alınmış.

**Öncelik / kritiklik:** Ortam eksikse sonraki tüm fazlar yanlış-negatif üretir.
Bu adım atlanınca "hedefte bulgu yok" sonucu güvenilmez olur.

**Kaynaklar:**
- SecLists — https://github.com/danielmiessler/SecLists
- ProjectDiscovery Docs — https://docs.projectdiscovery.io/
- HackTricks — harici recon tooling: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html

### 0.4 Kanıt hijyeni ve not alma (evidence hygiene)
**Ne:** Her bulgunun yeniden üretilebilir, zaman damgalı ve redaksiyonlu
saklanması. Amaç: "iddia" ile "kanıt"ı ayırmak ve raporu denetlenebilir kılmak.

**Tespit — adım adım:**
1. Engagement dizin yapısını kur (0.2'deki gibi): `recon/`, `evidence/`, `notes/`.
2. Her kanıt dosyasını UTC timestamp ile kaydet: `YYYYMMDDTHHMMSSZ_<host>_<desc>`.
3. Ham istek/yanıtı sakla (curl `-i` veya proxy export); yalnızca ekran görüntüsü yetmez.
4. PII/secret'ı redakte et (`Authorization`, `Cookie`, token, e-posta gövdesi).
5. Her bulgu için: **ne**, **nerede**, **nasıl tetiklendi**, **kanıt yolu**, **etki**.
6. Tekrar üretimi garanti et: komutu ve payload'ı komut geçmişinden değil, nottan çalıştır.
7. Mükerrer kayıtları dedupe et (aynı kök neden = tek bulgu).

**Araçlar & komutlar:**
```bash
# Zaman damgalı ham kanıt
ts=$(date -u +%Y%m%dT%H%M%SZ)
curl -ski "https://T/endpoint" | tee evidence/${ts}_endpoint.txt

# Yanıtları hash'le (bütünlük / dedup)
sha256sum evidence/*.txt > evidence/checksums.sha256

# Redaksiyon (gönderilecek rapor için)
sed -E 's/(Authorization:).*/\1 [REDACTED]/I; s/(Cookie:).*/\1 [REDACTED]/I' \
  evidence/raw.txt > evidence/raw.redacted.txt

# Not şablonu (her bulgu için bir dosya)
cat > notes/F-001.md <<'EOF'
id: F-001
asset: https://T/...
class: <vuln sınıfı>
status: candidate|confirmed|ruled_out|open_proof_gap
repro: <komut/payload>
evidence: evidence/....txt
impact: <kanıtlanan etki>
cvss: <doğrulandıktan sonra>
EOF
```
**Teknik notları / tuzaklar:**
- Ekran görüntüsü tek başına zayıf kanıttır; ham HTTP + zaman damgası asıldır.
- Proxy request ID'leri kanıt köprüsüdür; bulguyu raporlarken bu ID'ler iliştirilir.
- Rapor metnine internal yol/araç/IP sızdırma; kanıt teknik, anlatım tarafsız olmalı.
- "Bulgu yok" durumu da kaydedilir (negatif kapsam) — neyin test edildiği izlenebilir.

**Doğrulama barı (çıktı kriteri):** Her aday bulgu için `notes/F-XXX.md` + en az bir
ham `evidence/*.txt`; checksum listesi mevcut.

**Yanlış pozitif / tuzaklar:** Kendi test kurulumundan kaynaklanan (self-inflicted)
değişiklikleri kanıt sanmak; oturumları karıştırma; bir kerelik (one-shot) yanıtı
sabit davranış sanmak.

**Öncelik / kritiklik:** Kanıtsız bulgu raporlanamaz; hijyen eksikliği tüm
portföyün güvenilirliğini düşürür.

**Kaynaklar:**
- OWASP WSTG — Reporting: https://owasp.org/www-project-web-security-testing-guide/latest/5-Reporting
- OWASP Cheat Sheets — https://cheatsheetseries.owasp.org/
{% endraw %}

---


[← Web Pentest Methodology](/methodology/)

[Bölüm 1 →](/methodology/01-kesif-enumerasyon/)
