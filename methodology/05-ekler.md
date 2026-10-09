---
layout: page
title: "Bölüm 5 — Ekler"
methodology: true
toc: true
permalink: /methodology/05-ekler/
---

{% raw %}
### 5.1 OWASP WSTG kontrol listesi (checklist eşlemesi)

Aşağıdaki tablo, bu dokümandaki fazları OWASP WSTG v4.2 kategorilerine bağlar.
Her satır bir kategori; ID'ler temsilî ve yüksek-değerli kontrollerdir. Tam
liste: https://owasp.org/www-project-web-security-testing-guide/latest/

| Kategori | WSTG ID aralığı | Öne çıkan kontroller | Faz eşlemesi |
|---|---|---|---|
| INFO — Information Gathering | INFO-01..10 | search-engine leak, metafiles, entry points, framework/app fingerprint, map architecture | BÖLÜM 1 |
| CONF — Configuration & Deployment | CONF-01..14 | platform config, backup/unreferenced files, admin interfaces, HTTP methods, HSTS, subdomain takeover, cloud storage, CSP, path confusion, security headers | BÖLÜM 1, 5.3 |
| IDNT — Identity Management | IDNT-01..05 | role definitions, registration process, provisioning, account enumeration, username policy | BÖLÜM 2.1, 3.1 |
| ATHN — Authentication | ATHN-01..10 | encrypted channel, default creds, lockout, bypass schema, remember-me, cache, password policy, security questions, reset/change, alternative channel | BÖLÜM 2.1/2.5/2.6/2.13 |
| ATHZ — Authorization | ATHZ-01..04 | directory traversal, bypass authz schema, privilege escalation, IDOR | BÖLÜM 2.7/2.8/2.9, 3.2/3.3 |
| SESS — Session Management | SESS-01..10 | session schema, cookie attributes, fixation, exposed vars, CSRF, logout, timeout, puzzling, hijacking, JWT | BÖLÜM 2.2/2.3/2.10, 3.6 |
| INPV — Input Validation | INPV-01..19 | XSS (ref/stored), verb tampering, HPP, SQLi, LDAP, XML, SSI, XPath, IMAP/SMTP, code, command, format string, incubated, splitting/smuggling, incoming, host header, SSTI, SSRF | BÖLÜM 2.14..2.29 |
| ERRH — Error Handling | ERRH-01..02 | improper error handling, stack traces | BÖLÜM 2.45, 5.2 |
| CRYP — Cryptography | CRYP-01..04 | weak TLS, padding oracle, sensitive info unencrypted, weak encryption | BÖLÜM 2.45, 5.2 |
| BUSL — Business Logic | BUSL-01..10 | data validation, forge requests, integrity checks, process timing, function limits, workflow circumvention, misuse defenses, unexpected file types, malicious files, payment | BÖLÜM 2.39/2.40, 3.4 |
| CLNT — Client-side | CLNT-01..13 | DOM XSS, JS execution, HTML injection, URL redirect, CSS injection, resource manipulation, CORS, Flash, clickjacking, WebSockets, Web Messaging, browser storage, XSSI | BÖLÜM 2.29..2.36 |
| APIT — API Testing | APIT-01..02 | GraphQL, REST | BÖLÜM 2.37/2.38/2.41/2.42 |

**Kullanım:** Her kategori için önce "anonim" sütunu, sonra "authed" ve
"admin" sütununu doldur; boş kalan hücreler kapsam boşluğudur. Kapatılmayan
her aday `open_proof_gap` olarak taşınır.

**Kaynaklar:**
- OWASP WSTG — https://owasp.org/www-project-web-security-testing-guide/latest/
- OWASP ASVS — https://owasp.org/www-project-application-security-verification-standard/
- OWASP API Security Top 10 — https://owasp.org/API-Security/

### 5.2 Genel playbook'ların yanlış yaptığı şeyler (dersler / tuzaklar)

Sahada en sık görülen, gerçek engagement'ları bozan yanlışlar. Her birini bir
*kural* ve bir *neden* ile yazıyorum.

1. **WAF 403 / CDN 403'ü "savunmalı" sanmak.** Engelleme = kontrol değil,
   konumdur. Farklı encoding/kaynak/taşıyıcı dene; 403'ü "güvenli" diye
   kapatma. Ayrıca proxy'nin döndüğü hata sayfasını hedef yanıtı sanma.
2. **Tek payload'la karar vermek.** Bir payload engellendi diye "güvenli",
   geçti diye "vuln" demek yanlış. En az iki varyant + negatif kontrol.
3. **Scanner çıktısını doğrulamadan raporlamak.** "nuclei critical dedi"
   kanıt değil. Her hit'i elle yeniden üret.
4. **Rate-limit / enumeration'ı yüksek şiddet saymak.** Kullanıcı/hesap/versiyon
   varlığını doğrulamak `C:L`'dir; çoğu zaman `I:N/A:N`. Yüksek demek için
   zincir göster.
5. **Self-XSS'i rapor etmek.** Kurbanın kendi girdisini kendi tarayıcısında
   çalıştırması gerekiyorsa etki yok; stored/reflected + victim bağlamı ara.
6. **Transport/config hijyenini vuln saymak.** HSTS/CSP/header eksikliği,
   TLS nit'leri tek başına bulgu değil; gerçekçi exploit + doğrudan etki
   gerekir.
7. **Public metadata / source map (secret'siz) için yüksek C vermek.**
   Enumerasyon değeri `C:N`; yalnız gerçek kısıtlı veri `C:L+`.
8. **Sadece `200` görünce IDOR/erişim demek.** Gövdeyi oku; yabancı veri var mı?
   Yoksa sızıntı yok.
9. **Boş dizi/null dönüşünü sızıntı sanmak** (ya da tersini yapıp gerçek
   sızıntıyı "boş döndü" diye kaçırmak). Sahibinin görünümüyle karşılaştır.
10. **Çalınmış sır gerektiren senaryoyu PR:N/AC:L saymak.** Cookie/token/link
    elde etmenin maliyeti vardır; aynı bulgu o sırrı elde etme yolunu
    göstermiyorsa low/medium.
11. **Aynı kök nedeni çok raporlamak.** Deduplication; tek kök = tek rapor;
    yeni bilgi varsa mevcut raporu güncelle.
12. **Güvenli kardeşi delil saymak.** Bir çağrı yerinin korunması diğerini
    temize çıkarmaz.
13. **"Framework halleder" genel güveni.** O çağrının o bağlamdaki davranışını
    doğrula; escaping bağlam-bağımlıdır.
14. **Belirsizliği sessizce kapatmak.** Kanıtlayamadığın ve kontrol
    adlandıramadığın adayı `open_proof_gap` yap; gizleme.
15. **MISSING INFO = SAFE sanmak.** "Caller bulamadım / deploy mu bilmiyorum /
    servisi kaldıramadım" kanıt yokluğudur, güvenlik kanıtı değildir.
16. **Zincirin en güçlü hop'unu tek başına raporlamak** ama baştan-sona
    yürütmemek. Her hop kanıtlı olmalı.
17. **Ortam sızıntısı yapan "ham" kanıt** (sistem yolları, iç adlar, ID'ler).
    Kanıtı hijyenikleştir.
18. **Gerçek müşteri verisini maskelemeden yapıştırmak.**
19. **Test hesabı/kimlik bilgilerini shell geçmişine düşürmek.** Auth vault /
    dosya kullan.
20. **Oturum ile yeniden crawllamayı atlamak.** Anonim crawl yüzeyin küçük
    kısmıdır; en değerli bulgular authed yüzeydedir.
21. **Tek hesap ile authz test etmek.** Yatay/dikey/tenant izolasyonu için
    ≥2 hesap + ≥2 tenant zorunlu.
22. **DB/admin panelini görünce doğrulamadan "critical" demek.** Gerçekten
    yetkisiz erişim var mı, yoksa public mi?
23. **CVSS'i sezgiyle override etmek.** Uyuşmuyorsa metriği düzelt.
24. **Kanıt (HTTP exchange) ID'lerini rapora yazmayı unutmak** veya uydurmak.
    Gerçek ID'leri iliştir.

### 5.3 Araç hızlı referans

| İhtiyaç | Araç | Tipik kullanım |
|---|---|---|
| Subdomain enum | subfinder | `subfinder -d target.tld -all -o subs.txt` |
| Port tarama | naabu / nmap | `naabu -l hosts.txt -top-ports 1000` |
| HTTP probe/fingerprint | httpx | `httpx -l urls.txt -sc -title -tech-detect -o httpx.out` |
| Crawl/URL toplama | katana / gospider | `katana -u URL -jc -d 4 -kf all -o urls.txt` |
| Dizin/route keşfi | ffuf / dirsearch | `ffuf -u URL/FUZZ -w wordlist -mc 200,403` |
| Parametre keşfi | arjun | `arjun -u URL -H 'Cookie: ...' -m GET` |
| Zafiyet tarama (base) | nuclei | `nuclei -l urls.txt -severity medium,high,critical -o nuclei.out` |
| SQLi | sqlmap | `sqlmap -u 'URL?id=1' --batch --level=3 --risk=2` |
| JWT | jwt_tool | `jwt_tool <JWT> -M at -t URL -rh 'Authorization: Bearer <JWT>'` |
| WAF tespiti | wafw00f | `wafw00f https://target.tld` |
| OOB etkileşim | interactsh-client | `interactsh-client -v` |
| Proxy/replay | Caido (proxy araçları) | `list_requests` / `repeat_request` / sitemap |
| Tarayıcı/iki-oturum | agent-browser | `agent-browser --session X open URL` / `state save` |
| SAST (whitebox) | semgrep / ast-grep | `semgrep --config auto .` / `sg run -p '...'` |
| Secret tarama | gitleaks / trufflehog | `gitleaks detect` / `trufflehog filesystem .` |
| SCA / CVE | trivy fs / vulnx | `trivy fs .` / `vulnx search <product>` |
| Cloud metadata (SSRF) | curl | `curl http://169.254.169.254/latest/meta-data/` |
| İki hesap otomasyonu | Python + caido_api | `list_requests` / `repeat_request` |

**Not:** Araç çıktısı = sinyal, bulgu değil. Her sinyali 4.1 PoC barı ile
doğrula.

### 5.4 Kaynak indexi

**Standartlar & metodoloji**
- OWASP WSTG — https://owasp.org/www-project-web-security-testing-guide/latest/
- OWASP ASVS — https://owasp.org/www-project-application-security-verification-standard/
- OWASP Top 10 — https://owasp.org/Top10/
- OWASP API Security Top 10 — https://owasp.org/API-Security/

**Şiddet & sınıflama**
- CVSS v3.1 Specification — https://www.first.org/cvss/v3.1/specification-document
- CVSS v3.1 Calculator — https://www.first.org/cvss/calculator/3.1
- CWE — https://cwe.mitre.org/
- OWASP Risk Rating Methodology — https://owasp.org/www-community/OWASP_Risk_Rating_Methodology

**Öğrenme & payload**
- PortSwigger Web Security Academy — https://portswigger.net/web-security
- PortSwigger Research — https://portswigger.net/research
- OWASP Cheat Sheets — https://cheatsheetseries.owasp.org/
- HackTricks — https://book.hacktricks.wiki/
- HackTricks Cloud — https://cloud.hacktricks.wiki/
- PayloadsAllTheThings — https://github.com/swisskyrepo/PayloadsAllTheThings
- SecLists — https://github.com/danielmiessler/SecLists

**Kritik CWE'ler (en sık karşılaşılanlar)**
- CWE-639 (IDOR / user-controlled key) — https://cwe.mitre.org/data/definitions/639.html
- CWE-862 (Missing Authorization) — https://cwe.mitre.org/data/definitions/862.html
- CWE-863 (Incorrect Authorization) — https://cwe.mitre.org/data/definitions/863.html
- CWE-287 (Improper Authentication) — https://cwe.mitre.org/data/definitions/287.html
- CWE-306 (Missing Auth for Critical Function) — https://cwe.mitre.org/data/definitions/306.html
- CWE-352 (CSRF) — https://cwe.mitre.org/data/definitions/352.html
- CWE-384 (Session Fixation) — https://cwe.mitre.org/data/definitions/384.html
- CWE-613 (Insufficient Session Expiration) — https://cwe.mitre.org/data/definitions/613.html
- CWE-918 (SSRF) — https://cwe.mitre.org/data/definitions/918.html
- CWE-89 (SQL Injection) — https://cwe.mitre.org/data/definitions/89.html
- CWE-79 (XSS) — https://cwe.mitre.org/data/definitions/79.html
- CWE-502 (Insecure Deserialization) — https://cwe.mitre.org/data/definitions/502.html
- CWE-434 (Unrestricted Upload) — https://cwe.mitre.org/data/definitions/434.html
- CWE-840 (Business Logic Errors) — https://cwe.mitre.org/data/definitions/840.html
{% endraw %}

---


[← Web Pentest Methodology](/methodology/)

[← Bölüm 4](/methodology/04-dogrulama-raporlama/)
