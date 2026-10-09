---
layout: page
title: "Bölüm 4 — Doğrulama, Zincirleme ve Raporlama"
methodology: true
toc: true
permalink: /methodology/04-dogrulama-raporlama/
---

{% raw %}
Bu faz bir "kapanış" değil, güvenilirlik fazıdır: ham sinyali kanıta,
kanıtı savunulabilir bir bulguya, bulguları zincire çevirir; sonra ucuz
iddiaları kırar. Kural: **her aday üç durumdan birinde kapanır** —
`confirmed`, `ruled_out` (adı konabilen bir kontrol ile), veya
`open_proof_gap` (kanıtlanamadı ve kontrol de adlandırılamadı). Sessizce
bırakmak yok.

### 4.1 Doğrulama disiplini & PoC barı

**Ne / Amaç:** Bir güvenlik olduğunu iddia ettiğin sonucun *yeniden
üretilebilir*, *minimal* ve *etkisi gösterilmiş* olması. "Olabilir" bir bulgu
değildir.

**Saldırı yüzeyi / nerede:** Tüm bulgular; özellikle scanner çıktıları,
statik izler ve tek istekte alınmış `403/200` gözlemleri.

**Tespit — adım adım:**
1. **Kaynağı izle (source→sink).** Girdi nereden geliyor, hangi ara katmanları
   geçiyor, hangi sink'e varıyor, hangi kontrol atlanıyor. Her hop için bir
   konum adı ver.
2. **Kontrol edilebilirliği kanıtla.** Girdiyi *sen* kontrol ediyorsun ve
   değeri sonuca yansıyor (canary: `MARKER1337`, `/etc/passwd` içeriği, `id`
   çıktısı, çapraz-kullanıcı veri).
3. **Minimal repro yaz.** En az adım, en az yan etki. Prod'da ölçekli exploit
   yapma.
4. **Kontrol/negatif istek ekle.** Zararsız varyant çalışırken payload
   engelleniyor mu → gerçekten kontrol mü var, endpoint mi kırık?
5. **Etkiyi somutla.** "Ne elde ettim?" bir cümleye sığmalı: "başka tenant'ın
   3 müşteri kaydını okudum", "paramı iade etmeden ürünü aldım".
6. **Kalıcılığı teyit et** (state değişikliklerinde): otoriter kaynakta
   (ledger/admin/email) kalıcı mı.

**Araçlar & komutlar:**
```bash
# Yeniden-üretilebilir minimal PoC şablonu (tek dosya, tek çıktı)
cat > poc.sh <<'SH'
set -e
TGT="https://app.target.tld"
echo "[*] baseline (bana ait obje)"; curl -s -b A.txt "$TGT/api/orders/1001" | head -c 300
echo; echo "[*] exploit (yabanci obje)"; curl -s -b A.txt "$TGT/api/orders/1042" | head -c 300
SH
```

**Teknik notları:**
- **Farkı göster, hikâyeyi değil.** Aynı isteğin iki bağlamdaki (sahip vs
  yabancı / anon vs authed / düşük vs yüksek rol) çıktısı yan yana kanıttır.
- Statik iz çalıştırılamadıysa en fazla `confidence: medium` (bkz. 4.5).
- Scanner'ın "sevity: critical" etiketi kanıt değildir; her iddiayı elle
  doğrula.
- Kanıtları proxy'de tut; her bulgu için **tetikleyen istek** ve
  **baseline/kontrol isteğinin** ID'lerini not et (raporlama/kanıt).

**Doğrulama barı (PoC):** Tekrarlanabilir tek-komut/tek-adım repro; canary
değeri/çapraz-veri/`id` çıktısı gibi inkâr edilemez somut çıktı; ve kontrol
isteğinin farklı davranması.

**Yanlış pozitif / tuzaklar:**
- Tek payload'la karar vermek (WAF engeline takılıp "savunmasız" ya da
  "savunmalı" demek) — bkz. BÖLÜM 5.2.
- `200`'i erişim sanmak; gövdeyi okumadan sonuca varmak.
- Ortam farkını görmezden gelmek (test'te çalışıyor, prod'da ölü yol olabilir).

**Şiddet kalibrasyonu:** Bu adımın kendisi şiddet vermez; sonraki iki bölümün
girdisini üretir.

**Kaynaklar:**
- OWASP WSTG (Reporting / Evidence) — https://owasp.org/www-project-web-security-testing-guide/latest/
- PortSwigger Research (metodoloji) — https://portswigger.net/research
- CVSS v3.1 Specification — https://www.first.org/cvss/v3.1/specification-document

### 4.2 Yanlış-pozitif eleme ve counterevidence

**Ne / Amaç:** Bir adayı kapatmadan önce **ona karşı** en güçlü davayı kur.
Amaç yanlış pozitifi kesmek *kadar* yanlış negatifi (vakti gelmemiş gerçek
bulguyu) üretmemek.

**Saldırı yüzeyi / nerede:** Her kapattığın aday; özellikle "güvenli göründü"
diyerek geçtiğin yollar.

**Tespit — adım adım:**
1. **Karşı-kanıtı ara.** Kaçırdığın guard, farklı route, başka caller,
   async/worker yolu, fail-open branch, caller-tarafından-verilen config var mı?
2. **Adı konabilir kontrol testi.** "Şu dosyadaki/servisteki şu kontrol, sink'ten
   *önce*, saldırganın ulaşabildiği *her* yolda çalışıyor" cümlesini
   tamamlayabiliyor musun? Tamamlayamıyorsan `ruled_out` **değildir**.
3. **Negatif kontrol çalıştır.** Varsa yasaklı payload'la güvenli varyantı
   karşılaştır: korumasız input reddediliyor mu, endpoint kırık mı?
4. **Durumu seç:** `confirmed` / `ruled_out` (adı konan kontrol) /
   `open_proof_gap` (kanıtlanamadı ve kontrol adlandırılamadı).
5. **`open_proof_gap`'i görünür bırak.** Takip listesine taşı; "kapattım" diye
   gizleme.

**Araçlar & komutlar:**
```bash
# Negatif kontrol örneği: güvenli girdi vs payload
curl -s "https://app.target.tld/api/q?x=SAFE123" -o safe.out -w 'safe=%{http_code}\n'
curl -s "https://app.target.tld/api/q?x=<unsafe>" -o bad.out -w 'bad=%{http_code}\n'
diff safe.out bad.out   # fark YOKSA "kontrol var" iddiası zayıf
```

**Teknik notları:**
- Güvenli kardeşi (safe sibling) delil sayma: bir çağrı yerinin korunması,
  diğerini temize çıkarmaz — her ulaşılabilir örnek kendi ayakları üzerinde
  durur.
- "Kütüphane halleder / framework escape eder" genel güveni kanıt sayma; o
  çağrının, o bağlamdaki, o argümanlarla davranışını doğrula (HTML escaper JS
  bağlamında işe yaramaz).
- "Ulaşamadım / deploy mu bilmiyorum / build olmadı" = kanıt yokluğu,
  *güvenlik kanıtı değil*. Bunlar `open_proof_gap`'tir.
- Control'ün *yanlış zamanda* çalışması (redirect'ten sonra doğrulama,
  materialize edildikten sonra containment) kontrol değildir.

**Doğrulama barı (PoC):** `ruled_out` için: kontrolü, konumunu ve
saldırgan-ulaşılabilir tüm yollarda sink'ten önce çalıştığını gösterebilme.
Aksi hâlde aday açık kalır.

**Yanlış pozitif / tuzaklar:**
- Belirsizlikten dolayı sessizce kapatmak — en pahalı hata; `needs_follow_up`
  işaretle.
- Çift örnekleri tek adaya indirmek.
- Bir ortamda çalışan payload'ı "her yerde çalışır" sanmak (CDN/WAF bölgesel
  farkı).

**Şiddet kalibrasyonu:** Kapatma kararı şiddeti düşürür *veya* adayı
`open_proof_gap` olarak korur; ikisini karıştırma.

**Kaynaklar:**
- NIST/SANS: False Positive handling (SCA/DAST) — https://owasp.org/www-project-web-security-testing-guide/latest/
- CVSS v3.1 (metric seçimi) — https://www.first.org/cvss/v3.1/specification-document
- CWE (kök neden sınıflaması) — https://cwe.mitre.org/

### 4.3 Zafiyet zincirleme

**Ne / Amaç:** Tekil bug'lar başlangıçtır; gerçek etki çoğu zaman
zincirde yatar. Zincir; bir bulgunun çıktısını (bilgi, ID, kimlik, primitif)
diğerinin girdisine çevirir ve maksimum ayrıcalık/veri/etkiye ulaşır.

**Saldırı yüzeyi / nerede:** Bulgular arası geçiş noktaları: info-leak →
ID'ler; IDOR → yabancı obje; SSRF → iç servis/metadata; XSS → token →
oturum; mass-assignment → rol → admin; file upload → RCE.

**Tespit — adım adım:**
1. **Bulguları düğüm, geçişleri kenar olarak çiz.** Her kenar için: bu
   çıktı hangi yeni girdiyi besliyor?
2. **Klasik zincirleri dene:**
   - info-leak (export/JS/error) → **IDOR** → yabancı veri.
   - **IDOR** → yabancı hesabın API key'i → **kalıcı erişim**.
   - **Mass assignment** → `role=admin` → **BFLA/priv-esc**.
   - **XSS** → token/cookie hırsızlığı → **ATO**.
   - **SSRF** → cloud metadata (IMDS) → **cloud creds** → lateral.
   - **Open redirect** → OAuth `redirect_uri` → **code/token theft**.
   - **Race** → limit aşımı → finansal kazanç.
3. **Zinciri baştan sona gerçekten yürüt.** Her hop ayrı ayrı kanıtlı olsun;
   "sonra şu olsa şöyle olurdu" zincir değildir.
4. **Maksimuma ilerle.** Bir pivot bulunca dur değil, bir sonraki
   bileşene **odaklı alt-ajan** gönder.

**Araçlar & komutlar:**
```bash
# Zincir arşivleme: her hop'un kanıt isteğini proxy'de tut
# 1) info-leak ile ID'leri çıkar
curl -s -b cookieA.txt https://app.target.tld/api/export > exp.json
jq -r '.. .id?' exp.json | sort -u > ids.txt
# 2) IDOR ile yabancı kaydı oku
while read id; do curl -s -b cookieA.txt "https://app.target.tld/api/records/$id"; done < ids.txt
```

**Teknik notları:**
- Zincir için her hop'ta **negatif kontrol** ekle: kendi ID'nle çalış, yabancı
  ID'yle çalışıyorsa gerçek.
- Zincir şiddeti, en zayıf/gerekli en yüksek ayrıcalıklı hop tarafından
  sınırlanır; "erişilebilir olma" tek başına CVSS metriklerini yükseltmez (4.4).
- Bir zinciri **tek rapor** olarak file et; ama her hop'un kanıtını koru.
  Aynı kök nedeni ikinci kez raporlamayın (deduplikasyon).
- Alt-ajanlara her hop'u devret (bir sonraki bileşen/teknoloji için).

**Doğrulama barı (PoC):** Baştan sona yürütülmüş, her hop'u ayrı isteklerle
kanıtlı, uçtan uca etki (ör. low-priv kullanıcı → admin eylemi; anon →
cross-tenant veri).

**Yanlış pozitif / tuzaklar:**
- Doğrulanmamış varsayımsal hop'larla "worst case" zincir anlatmak.
- Zaten kanıtlanmış bir hop'u tekrar kanıtlamadan varsaymak.
- Zincirin etkisini abartıp her hop'u `C:H/I:H` saymak.

**Şiddet kalibrasyonu:** Zincir, uç noktayla değerlendirilir: tam ATO /
cross-tenant mass data / RCE → **critical**; yetki sınırı aşımı (user→admin)
veya başka kullanıcı verisi → **high**.

**Kaynaklar:**
- PortSwigger Research (chaining, exploit techniques) — https://portswigger.net/research
- OWASP WSTG ATHZ-03 (Privilege Escalation) — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation
- HackTricks (attack chains) — https://book.hacktricks.wiki/

### 4.4 CVSS & şiddet kalibrasyonu

**Ne / Amaç:** CVSS 3.1 vektörünü *kanıtlanmış sonuca* göre dürüstçe seç.
Şiddet bir *sonuçtur*, açılış pozisyonu değil. Skoru "güvenli tarafta kalmak
için" şişirmek raporu değersizleştirir.

**Saldırı yüzeyi / nerede:** Her rapor; özellikle authz/oturum bilgi-ifşası
bulguları (en çok abartılan alanlar).

**Tespit — adım adım:**
1. **Vektörü kur (8 metrik):**
   - `AV` Network(N)/Adjacent(A)/Local(L)/Physical(P)
   - `AC` Low(L)/High(H)
   - `PR` None(N)/Low(L)/High(H)
   - `UI` None(N)/Required(R)
   - `S` Unchanged(U)/Changed(C)
   - `C`/`I`/`A` None(N)/Low(L)/High(H)
2. **Her non-`N` etkiyi kanıta bağla.** `C:H` = geniş/sistemik okuma kanıtı;
   tek kayıt/tek kullanıcı = `C:L` (çoğu zaman `I:N`).
3. **Ayrı bir uzlaşımı önvarsayma.** Saldırı çalınmış bir sır (cookie/token/
   link) gerektiriyorsa bu bedava değildir; `PR:N`/`AC:L` yapıp replay'i
   High sayma.
4. **Konum/etkileşimi dürüst modelle.** MITM önkoşulu veya kurban aksiyonu
   varsa `AC:H` / `UI:R` olarak yansıt.
5. **`S:C`'yi nadiren kullan.** Yalnızca farklı güvenlik otoritesine
   (ör. uygulamadan host'a) kanıtlanmış geçişte.
6. **Puanı vektörden türet**; sezgi ile uyuşmuyorsa metriği düzelt, sonucu
   override etme.

**Araçlar & komutlar:**
```text
# Örnek dürüst vektör (cross-user IDOR, tek tenant, kimlikli okuma):
# AV:N / AC:L / PR:L / UI:N / S:U / C:H / I:N / A:N  -> High
# Örnek düşük (cookie flag eksikliği):
# AV:N / AC:H / PR:N / UI:N / S:U / C:L / I:N / A:N  -> Low
```
```bash
# Hesapla / doğrula (offline referans: CVSS v3.1 spec + calculator)
echo "https://www.first.org/cvss/calculator/3.1"
```

**Teknik notları:**
- **Enumerasyon** (`account exists`, versiyon) → `C:L`, çoğu zaman `I:N/A:N`.
- Public metadata / iç görünen isim / adres / kaynak-harita (secret yok) →
  `C:N`.
- Yalnızca transport/config hijyeni (HSTS eksik, server header) → genelde
  `C:N`; gerçekçi saldırgan-exploit + doğrudan etki olmadan vuln değildir.
- **Missing authentication** erişilebilirliği etkiler; tek başına C/I/A
  yaratmaz — ama erişilen veri/eylem varsa onu puanla.
- Self-XSS, clickjacking (hassas olmayan aksiyon), open redirect (tek başına)
  → high/critical **değil**.

**Doğrulama barı (PoC):** Skordaki her metrik, raporda gösterilen somut
kanıta (istek/yanıt kanıtı) tekabül ediyor.

**Yanlış pozitif / tuzaklar:**
- "Chain'lense kritik olurdu" diye yüksek metrik seçmek.
- Rate-limit/enumerasyon'u yüksek şiddet saymak.
- Scope Changed'i aynı uygulama içi sınır aşımı için kullanmak.

**Şiddet kalibrasyonu (özet):**
```text
critical : unauth RCE / forge edilebilir auth / mass cross-tenant veri / imzalama anahtarı
high     : authed RCE / user->admin priv-esc / ölçekli BOLA / gerçek SQLi / metadata'ya SSRF
medium   : sınırlı stored/reflected XSS / anlamlı CSRF / düşük-değer authz / zinciri tam doğrulanmış bilgi ifşası
low/info : eksik header/cookie flag / verbose error / self-XSS / tek başına open redirect / enumerasyon
```
High/critical accept koşulu: saldırı yolu gerçekçi ve kapsam-içi, saldırgan
konumu elde edilebilir, etki kanıtlı (C:H/I:H = geniş/sistemik), karşı-kanıt
geçişi kısıt bulamadı, ulaşılabilirlik varsayım değil.

**Kaynaklar:**
- CVSS v3.1 Specification — https://www.first.org/cvss/v3.1/specification-document
- CVSS v3.1 Calculator — https://www.first.org/cvss/calculator/3.1
- OWASP Risk Rating Methodology — https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
- FIRST CVSS Examples — https://www.first.org/cvss/examples

### 4.5 Rapor yazımı & kanıt hijyeni

**Ne / Amaç:** Bulguyu, bir başkasının **tek başına yeniden üretebileceği** ve
yöneticinin **iş etkisini anlayacağı** biçimde yaz. Aynı anda: sistem/ortam
detayı sızdırma, gizli veri sızdırma.

**Saldırı yüzeyi / nerede:** Tüm rapor; kanıt blokları; PoC kod; CVSS
gerekçesi.

**Tespit — adım adım:**
1. **Standart yapıyı kur:** (1) özet (`description`), (2) şiddet & CVSS
   (`cvss_breakdown`), (3) etkilenen varlık (`target`/`endpoint`), (4) teknik
   detay (`technical_analysis`), (5) PoC (`poc_description` + `poc_script_code`),
   (6) etki (`impact`), (7) kanıt (`evidence`), (8) remediation
   (`remediation_steps`).
2. **PoC adımları kod içermez** (kod `poc_script_code`'a); remediation düzyazı
   (kod/diff `code_locations`'ta).
3. **Kanıtı ham tut:** tetikleyen istek + kontrol/baseline isteği; durum kodu,
   gövde kesiti, zaman. Kanıt ID'lerini rapora iliştir.
4. **Kanıt hijyeni:** `/workspace` gibi sistem yolları, ajan/araç/sandbox/
   model adları, iç stack trace, iç istek ID'leri **rapora girmez**; üçüncü
   kişi tonu, hedef/ürün-nötr dil.
5. **Minimal repro** ve **gerçekçi etki** tek yerde; abartılı gelecek-senaryo
   yok.
6. **Fix'i raporda ver:** kök nedeni düzelt (defense-in-depth değil), kaynak
   varsa `code_locations` ile `fix_before`/`fix_after` + doğrulama.

**Araçlar & komutlar:**
```bash
# Kanıt isteğini proxy'den seç ve ham al/response'u rapora taşı (ID ile)
# (Caido: tetikleyen istek + kontrol isteği; gövdeyi redakte et)
```
```text
# Kanıt hijyeni kontrol listesi (raporda OLMAMALI):
# - /workspace, /home, /tmp gibi ortam yolları
# - ajan/orchestrator/model/sandbox adları, promptlar
# - ic istek/report ID'leri, ic host adlari
# - gercek musteri PII'si (maskele: a***@example.com)
# - baska kullanicilarin sirlari/anahtarlari (yalniz varligini kanitla)
```

**Teknik notları:**
- Her bulguyu **bir** kök nedenle eşle; aynı kök neden ikinci kez raporlanmaz
  (deduplication).
- Kanıt isteği (HTTP exchange) ID'lerini rapora iliştir; bunları kanıt
  metnine yazma — ayrı alan.
- Bilgi ifşası bulgusunda, ifşa edilen şeyin *hassasiyetini* ve erişimin
  sınırını (kullanıcı/tenant/ortam) açıkça yaz.
- Fix'i, bulguyu yazan ajan **aynı geçişte** üretir (ayrı "fix ajani" yok).

**Doğrulama barı (PoC):** Bağımsız bir okuyucu, raporu ve PoC'yi kullanarak
bulguyu yeniden üretiyor; raporda iç/ortam sızıntısı yok.

**Yanlış pozitif / tuzaklar:**
- Sistem/iç detay sızdıran "ham" kanıt (ortam hijyeni ihlali).
- Gerçek musteri verisini maskelemeden yapıştırmak.
- Scanner etiketini severity olarak kopyalamak.
- "Approach / QUICK / Techniques" gibi runbook-başlıklarıyla son kullanıcı
  raporu yazmak; resmi/nesnel ton kullan.

**Şiddet kalibrasyonu:** Rapor metni, CVSS vektörü ve PoC **aynı** sonucu
anlatmalı; çelişki varsa metrik düşür veya doğrulamayı derinleştir.

**Kaynaklar:**
- OWASP WSTG (Raporlama) — https://owasp.org/www-project-web-security-testing-guide/latest/
- OWASP Cheat Sheets (Remediation örnekleri) — https://cheatsheetseries.owasp.org/
- CVSS v3.1 — https://www.first.org/cvss/v3.1/specification-document
- CWE (kök neden) — https://cwe.mitre.org/

---
{% endraw %}

---


[← Web Pentest Methodology](/methodology/)

[← Bölüm 3](/methodology/03-kimlik-dogrulamali-test/)

[Bölüm 5 →](/methodology/05-ekler/)
