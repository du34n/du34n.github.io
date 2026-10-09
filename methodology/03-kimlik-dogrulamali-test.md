---
layout: page
title: "Bölüm 3 — Kimlik Doğrulamalı (Authenticated) Test"
methodology: true
toc: true
permalink: /methodology/03-kimlik-dogrulamali-test/
---

{% raw %}
Kimlik doğrulamalı faz, anonim keşifte görünmeyen yüzeyi açar: dashboard, ayarlar,
API key yönetimi, entegrasyonlar, rol/tenant sınırları ve iş akışları. Bu fazın
tek kuralı şudur: **her endpoint'i, her rol ile, her tenant ile, her transport
ile çapraz test et** ve farkı kanıtla. Tek hesapla yapılan test yatay/dikey erişim
ve tenant izolasyonunu ispatlayamaz — bu nedenle bu fazın girişi *en az iki hesap
+ en az iki tenant*'tır.

> Önkoşul: BÖLÜM 0.4 (kanıt hijyeni), BÖLÜM 1 (anonim envanter) ve BÖLÜM 2'nin
> auth/oturum/JWT/OAuth bölümleri tamamlanmış olmalı. Bu faz, BÖLÜM 2'deki
> sınıfların *kimlikli bağlamdaki* tekrarı ve derinleştirilmesidir.

### 3.1 Hesap edinme & rol/tenant matrisi

**Ne / Amaç:** Testin yakıtı hesaplardır. Amaç; anon, düşük-yetkili kullanıcı,
ikinci kullanıcı (yatay), yüksek-yetkili/admin (dikey) ve mümkünse support/
impersonation hesabı dahil bir *aktör kümesi* ile en az iki *tenant* edinmek.

**Saldırı yüzeyi / nerede:** `/register`, `/signup`, davet (`/invite`, davet
token'ı, org daveti), SSO ile self-provision, ücretsiz deneme (free trial),
API ile programatik kayıt, dokümantasyondaki seed/demo hesaplar, `.env`/JS/
git sızıntısından düşen default kimlik bilgileri.

**Tespit — adım adım:**
1. **Registration akışını haritala.** Hangi alanlar var, hangi alanlar
   *client-side* gizli (ör. `role`, `is_admin`, `plan`)? Kayıt sonrası
   hangi varsayılan rol atanıyor?
2. **Self-register et.** Elden geldiğince ayrı e-posta adresleriyle otomatik
   kayıt ol (disposable inbox veya catch-all domain). Kayıt akışını *başlı
   başına* bir saldırı yüzeyi olarak da test et: user enumeration
   (var olan e-posta farklı yanıt verir mi?), zayıf parola politikası,
   CAPTCHA/e-posta doğrulama atlanabiliyor mu?
3. **Rol türet.** Kayıt olunan hesabın rolünü ve yetkilerini API yanıtlarından,
   JWT claim'lerinden, UI'daki gizli butonlardan oku.
4. **Düşük-yetkili hesap** oluştur (ücretsiz plan). Mümkünse **ikinci bir
   düşük-yetkili hesap** daha oluştur (farklı tenant/org için).
5. **Davet akışı varsa** kendi hesabınla ikinci hesabı davet et; davet
   token'ının yeniden kullanılabilirliğini, e-posta bağlamasını ve davet-sonrası
   rol atamasını incele.
6. **Seed/default creds dene** (güvenli, yıkıcı olmayan küçük küme):
   `admin/admin`, `admin/password`, `test/test`, ürün adı + yıl, vb. Yalnızca
   yıkıcı olmayan read istekleri ile doğrula.
7. **Yüksek-yetkili/admin hesabı** greybox'ta istemciden; blackbox'ta mümkünse
   org-owner self-provision (ücretsiz org açtığında tenant-admin olabilirsin)
   üzerinden edin. Edinemiyorsan bunu bir `open_proof_gap` olarak kaydet —
   dikey erişimi test etmeden "yetki yok" sonucuna varma.
8. **Rol×tenant matrisini yaz.** Aşağıdaki gibi bir tablo; her hücre daha sonra
   çapraz testte doldurulur.

| Aktör | Tenant A | Tenant B | Not |
|---|---|---|---|
| anon | — | — | auth gerektiren yüzey |
| user-A1 (low) | üye | — | self-register |
| user-A2 (low) | üye | — | yatay IDOR için |
| org-admin A | admin | — | self-provision |
| org-member B | — | üye | cross-tenant |
| support/impersonation | ? | ? | varsa en değerli |

**Araçlar & komutlar:**
```bash
# Oturumları agent-browser'da ayrı session'larda tut (birbirini bozmasın)
agent-browser --session userA open https://app.target.tld/login
agent-browser --session userB open https://app.target.tld/login

# Kimlik bilgilerini shell geçmişine düşürmeden auth vault ile sakla
agent-browser auth save target-userA --url https://app.target.tld/login \
  --username userA@mail.tld --password-stdin
agent-browser auth login target-userA

# Oturum durumunu diske al (crawl/fuzz için cookie jar olarak da kullanılır)
agent-browser --session userA state save ./sess-userA.json
```
```bash
# Kayıt akışını otomatikleştir; yanıt farkından user enumeration çıkar
ffuf -u https://app.target.tld/api/register -X POST \
  -H 'Content-Type: application/json' \
  -d '{"email":"FUZZ@mail.tld","password":"Passw0rd!x9"}' \
  -w emails.txt -mc all -fr 'already exists'
```

**Teknik notları:**
- Hesap edinme kendisi bir zafiyet sınıfıdır (BÖLÜM 2.1/2.6/2.13): enumeration,
  zayıf parola, doğrulama atlama. Bulduğunu hemen kaydet.
- Kimlik bilgilerini paylaşılan bir *credential inventory* içinde tut (rol,
  tenant, plan, elde ediliş yolu) — çok ajanlı çalışmada tekrar üretmeyi önler.
- SSO/self-provision varsa, farklı IdP kullanıcılarıyla rol farkı oluşabilir;
  bu, cross-tenant testin anahtarıdır.

**Doğrulama barı (PoC):** Edindiğin her hesap, auth gerektiren bir korumalı
sayfada `200` + beklenen kişisel veriyle açılıyor; ikinci hesap *aynı* sayfada
*farklı* veriyi gösteriyor.

**Yanlış pozitif / tuzaklar:**
- "Kayıt oldum, demek ki herkes olabilir" — kayıt kapatılmış/onaylı olabilir;
  asıl soru *kayıt sonrası ne yapabildiğindir*.
- Kayıt yanıtındaki `200`'i başarı sanmak; e-posta doğrulaması gelmeden hesabın
  kullanılamadığını fark etmemek.
- Ücretsiz deneme hesabına özel kısıtları (feature-gate) genelleyip yanlış
  dikey erişim sonucu çıkarmak.

**Şiddet kalibrasyonu:** Hesap edinmenin kendisi normaldir; fakat
**kimlik-doğrulama olmadan hesap elde etme** veya **kayıttan admin rolü
ataması** (mass assignment) high/critical olabilir. User enumeration tek başına
low'dur (bkz. BÖLÜM 5.2).

**Kaynaklar:**
- OWASP WSTG IDNT-02 (Test User Registration Process) — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/02-Testing_for_User_Registration_Process
- OWASP WSTG IDNT-04 (Account Enumeration) — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account
- OWASP WSTG ATHN-02 (Default Credentials) — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials
- PortSwigger Academy: Authentication — https://portswigger.net/web-security/authentication
- CWE-522 (Insufficiently Protected Credentials) — https://cwe.mitre.org/data/definitions/522.html

### 3.2 Yetkilendirme matrisi çıkarımı

**Ne / Amaç:** Kim neyi, hangi kaynak üstünde, hangi transport ile yapabiliyor?
Bu matris (Actor × Action × Resource × Transport) yetki eksiklerinin haritasıdır.
Authorization'ı UI'a değil, **servise** sorarak çıkar.

**Saldırı yüzeyi / nerede:** UI'daki gizli/disabled butonlar (feature-gate
client-side), JS bundle içindeki rol/flag anahtarları, API yanıtındaki `role`/
`permissions` alanları, `OPTIONS`/`Allow` header'ları, farklı transport
(REST vs GraphQL vs gRPC vs WebSocket) middleware farkları, legacy vs v2 route
çiftleri.

**Tespit — adım adım:**
1. Authenticated crawl + JS'ten **tüm endpoint envanterini** çıkar (3.5 ile
   birlikte). Anonim envanterle diff al: yalnızca-auth görünen yolları işaretle.
2. Her endpoint için **izinli HTTP metodlarını** çıkar:
   `OPTIONS`, `Allow`, ve UI'ın kullanmadığı `PUT/PATCH/DELETE` denemeleri.
3. **Rol matrisini doldur.** Her endpoint × her oturum için istek at; durum
   kodu, yanıt uzunluğu ve gövde hash'ini kaydet. Fark = ipucu.
4. **Fonksiyon-seviyesi (BFLA) kontrolleri:** Admin/staff'a özel görünen
   endpoint'leri düşük-yetkili token ile çağır. UI'da buton yok diye endpoint
   yok değildir.
5. **Transport drift:** Aynı eylemi REST, GraphQL mutation, gRPC metodu ve
   WebSocket mesajı üzerinden dene; enforcement transport'a göre değişiyorsa
   bu bir bulgudur.
6. **Route drift:** `/api/v1/admin/...` vs `/api/v2/admin/...`, `/admin` vs
   `/admin/legacy`, query ile `?admin=1` gibi alternatif yolları dene.

**Araçlar & komutlar:**
```bash
# Endpoint × oturum matrisini otomatik çıkar (iki farklı cookie/ Authorization)
python3 - <<'PY'
import json, subprocess, hashlib
eps = [l.strip() for l in open("endpoints.txt") if l.strip()]
sessions = {"anon": {}, "userA": {"Cookie": open("cookieA.txt").read().strip()},
            "admin": {"Cookie": open("cookieAdmin.txt").read().strip()}}
rows = []
for ep in eps:
    for name, hdr in sessions.items():
        args = ["curl", "-s", "-o", "-", "-w", "%{http_code} %{size_download}", "-X", "GET", ep]
        for h, v in hdr.items(): args += ["-H", f"{h}: {v}"]
        out = subprocess.run(args, capture_output=True, text=True).stdout
        code_size, _, body = out.partition("\n")
        rows.append((ep, name, code_size.strip(), hashlib.md5(body.encode()).hexdigest()[:8]))
for r in rows: print(r)
PY
```
```bash
# HTTP metod keşfi
for m in GET POST PUT PATCH DELETE OPTIONS; do
  printf '%s -> ' "$m"; curl -s -o /dev/null -w '%{http_code}\n' -X "$m" \
    -b cookieA.txt https://app.target.tld/api/users/123
done
```

**Teknik notları:**
- Durum kodu `401` = kimlik yok, `403` = kimlik var yetki yok, `404` = kaynak
  yok *veya* varlığı gizleniyor, `200` = dikkat. `404`'ü "yok" sanma; aynı
  kaynağı başka metod/route ile dene.
- `X-HTTP-Method-Override`, `_method=PATCH` ve GET ile state-change gibi
  tünelleme yollarını test et.
- Yanıt gövdesindeki `role`, `permissions`, `scopes`, `features` alanları hem
  mevcut yetkiyi hem de **mass assignment** hedefini gösterir (BÖLÜM 2.38).
- Middleware zinciri farkını ara: legacy route'lar sıklıkla yeni guard'dan
  muaftır.

**Doğrulama barı (PoC):** Düşük-yetkili token ile admin-only eylemin
**gerçekten** gerçekleşmesi (yanıtta yeni durum, kalıcı state değişikliği) ve
aynı isteğin uygun yetkiyle de başarılı olması — yani "endpoint kırık" değil,
"yetki eksik" olduğunun kanıtı.

**Yanlış pozitif / tuzaklar:**
- `403`'ü "güvenli" saymak. WAF/CDN 403'ü ile uygulama 403'ü farklıdır;
  gövde ve davranışla ayırt et (BÖLÜM 5.2).
- UI'da buton görünmüyor → endpoint yok varsayımı (yanlış).
- Aynı kaynağın farklı roller için *farklı alanlar* dönmesini "erişim yok"
  sanmak; alan-seti farkını da kaydet.

**Şiddet kalibrasyonu:** BFLA ile bir admin eylemi (rol değiştirme, refund,
impersonation, veri silme) düşük-yetkili token ile çalışıyorsa **high**;
birden çok role/tenant'ı etkiliyorsa ve internetten erişilebiliyorsa
**critical**. Salt okunur bir eşik aşımı **medium**'dur.

**Kaynaklar:**
- OWASP WSTG ATHZ-02 (Bypassing Authorization Schema) — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema
- OWASP API Security Top 10 — API5:2023 Broken Function Level Authorization — https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- PortSwigger Academy: Access control — https://portswigger.net/web-security/access-control
- CWE-862 (Missing Authorization) — https://cwe.mitre.org/data/definitions/862.html
- CWE-863 (Incorrect Authorization) — https://cwe.mitre.org/data/definitions/863.html

### 3.3 Yatay/dikey erişim & tenant izolasyonu

**Ne / Amaç:** Kimlik doğrulamalı fazın kalbi. **Yatay** = aynı seviye
kullanıcı→kullanıcı (A başkasının objesine erişir). **Dikey** = kullanıcı→admin.
**Tenant izolasyonu** = bir org'un verisine başka org'dan erişim. Her üçü de
*nesne bağlamasının* (subject ↔ action ↔ object) eksikliğidir.

**Saldırı yüzeyi / nerede:** Path/query/body/cookie/header içindeki tüm
referanslar (`id`, `user_id`, `account_id`, `org`, `tenant`), JWT claim'leri,
GraphQL argümanları, batch/bulk endpoint'ler, export/backup/job ID'leri,
file/object storage anahtarları, share/signed URL'ler.

**Tespit — adım adım:**
1. **İki hesap, iki ID seti topla.** Her oturum için list/search/export
   endpoint'lerinden en az bir geçerli obje ID'si al (bunlar ID madenidir).
2. **Token sabit, ID değiştir (yatay).** A oturumuyla B'nin ID'sini dene: path,
   body, query — her taşıyıcıda. Durum kodu, uzunluk, içerik farkını kaydet.
3. **Rol değiştir, ID sabit (dikey).** Aynı isteği düşük-yetkili/admin
   token'larıyla tekrarla.
4. **Tenant sınırını sınırla.** Tenant selector'ü (subdomain, path prefix,
   `X-Tenant-ID`, JWT `org`/`tid` claim'i, cookie) A token'i ile B değerine
   çevir. **Karıştır:** token tenant A, istekteki kaynak tenant B.
5. **Format ve taşıyıcı varyasyonları:** `{"id":123}` vs `"123"`, dizi vs
   skaler, `id=1&id=2` param pollution, duplicate JSON key, `null/0/-1/MAX`,
   content-type değişimi (JSON↔form↔multipart), UUID↔numeric.
6. **Toplu işlemleri kötüye kullan.** Bulk update/delete içinde ilk eleman
   yerine *dizinin ortasına* yabancı ID koy; yalnızca ilk elemanı doğrulayanlar
   ele verir.
7. **İkincil IDOR:** Notification/email/export/webhook çıktılarından başka
   kullanıcıların ID'lerini toplayıp doğrudan çağır.
8. **GraphQL:** global node/base64 ID çöz ve takas et; resolver-seviyesi kontrol
   var mı yok mu mutlaka dene.
9. **Header trust:** `X-User-Id`, `X-Role`, `X-Organization-Id` gibi gateway
   inject header'ları override et/ekle/kaldır.

**Araçlar & komutlar:**
```bash
# İki kullanıcının oturumlarıyla aynı objeyi karşılaştır (diff harness)
curl -s -b cookieA.txt https://app.target.tld/api/users/1001/orders > A.txt
curl -s -b cookieB.txt https://app.target.tld/api/users/1001/orders > B.txt
diff -u A.txt B.txt   # A: kendi verisi, B: A'nın ID'sini istiyor
```
```bash
# Caido ile yakalanan isteği replay et + ID takasla (modifications ile)
python3 - <<'PY'
import asyncio
from caido_api import repeat_request
async def main():
    r = await repeat_request("<REQ_ID>", {"url": "https://app.target.tld/api/orders/1042"})
    print(r)
asyncio.run(main())
PY
```
```bash
# Param pollution / format bypass
IDA=1001; IDB=1042
curl -s -b cookieA.txt "https://app.target.tld/api/orders?ids=$IDA&ids=$IDB"
curl -s -b cookieA.txt "https://app.target.tld/api/orders/$IDB"   # yol üzerinden
curl -s -b cookieA.txt -H 'Content-Type: application/json' \
  -d "{\"id\":$IDA,\"id\":$IDB}" https://app.target.tld/api/save
```

**Teknik notları:**
- Her `200` kazanç değildir: fark, **içeriğin başka bir özneye ait olmasıdır**.
  Boş dizi / `null` dönüşü bir yetki kontrolü olabilir (bkz. yanlış pozitif).
- `fields`/`include`/`expand`/`populate` gibi projection knob'ları sıklıkla
  nested authorization'ı atlar — genişlet ve diğer kullanıcı verisini çek.
- Cache key'e `Authorization`/tenant girmediği için CDN üzerinden başka
  kullanıcının yanıtını alma ihtimalini test et (Vary başlığı).
- Tenant bölünmesi subdomain ile ise `Host`/`X-Forwarded-Host` confusion'ı da
  dene (BÖLÜM 2.25).

**Doğrulama barı (PoC):** Sahibinin *olmadığın* bir objeye ait hassas içerik/
metadata okunması **veya** üzerinde yetkisiz state değişikliği; ve düzeltilmiş
istekle (kendi ID'n) aynı çağrının başarılı olduğunun gösterilmesi (endpoint'in
çalıştığının kontrolü). Cross-tenant ise iki farklı tenant token'i ile
kanıtlanır.

**Yanlış pozitif / tuzaklar:**
- **Zaten herkese açık** kaynak (public profil, public doküman) IDOR değildir.
- Başka kullanıcı için **boş dizi/null** dönmesi = uygulanan yetki (silent
  enforcement), sızıntı değil. Sahibinin görünümüyle karşılaştırarak teyit et.
- Sadece kod/uzunluk farkıyla "veri sızdı" demek; gövdeyi gösteremiyorsan
  kanıt yoktur.
- UUID'yi "tahmin edilemez, güvenli" sanmak — dağıtılmış UUID'ler
  (log/export/JS) saldırganın elindedir.

**Şiddet kalibrasyonu:** Cross-user/cross-tenant hassas veri (PII/PHI/PCI) veya
yetkisiz yazma → **high**; ölçek/geniş kapsam/cross-tenant → **critical**.
Tek bir kayıt, düşük hassasiyet, salt-okuma → **medium/low**.

**Kaynaklar:**
- OWASP WSTG ATHZ-01 (Directory Traversal/File Include) — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include
- OWASP WSTG ATHZ-04 (IDOR) — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization — https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- PortSwigger Academy: IDOR / Access control — https://portswigger.net/web-security/access-control/idor
- CWE-639 (Authorization Bypass Through User-Controlled Key) — https://cwe.mitre.org/data/definitions/639.html

### 3.4 Kullanıcı-içi iş akışları & business logic (authed)

**Ne / Amaç:** Sistemin *kurallarını* (invariant'larını) kimlikli bağlamda
kır. Kimlik doğrulamalı business-logic, çoğu zaman *anonim* değil *giriş yapmış*
aktörün elindeki bir akışı sömürür: fiyat/kota/credits/approval/workflow.

**Saldırı yüzeyi / nerede:** Cart/pricing, kupon/indirim, ödeme
(authorize/capture/void/refund), kredi/gift-card, abonelik/proration/seat,
kota ve kullanım sayaçları, onay (approval) akışları, çok-adımlı
wizard'lar, finalize/confirm endpoint'leri, webhook/job tetikleyicileri.

**Tespit — adım adım:**
1. **Durum makinesini çıkar.** Her kritik akış için state × transition ve
   geçişlerin pre/post-condition'ları. Invariant'ları yaz: değer korunumu
   (ledger), teklik (idempotency), monotonluk (sayaç azalmaz), ayrıcalık
   (bir aktif abonelik).
2. **Adım atla/sırala/tekrarla.** Finalize'ı doğrulamadan önce çağır; approve'ı
   create'ten önce çağır; aynı adımı eski/başka parametreyle tekrar gönder.
3. **Client hesabını yok say.** Total/tax/discount client'ta hesaplanıyorsa,
   sunucu yeniden hesaplıyor mu? Manipüle edilmiş toplamı gönder.
4. **Sınır/eşik değerleri:** negatif tutar, sıfır fiyat, ücretsiz kargo eşiği,
   `min/max`, bilimsel gösterim, çok büyük tamsayı, para birimi karışımı.
5. **Tekrar/kota:** Aynı kupon/kredi/promosyon'u ikinci kez kullan; kupon
   stack'le; kullanım kotasını T-1s ve T+1s'de dene.
6. **Race window:** Aynı işlemi paralel N istekle gönder (double-spend,
   çift refund, çift kupon). Ayrıntı: `race_conditions` skill.
7. **Idempotency abuse:** Idempotency key path'e mi principal'a mı bağlı?
   Başka kullanıcının key'ini tekrar kullan. Key yalnız cache'te mi tutuluyor?
8. **Refund/iptal:** Refund toplamı capture'ı aşıyor mu; benefit tüketilmişken
   refund; UI + destek aracından çift refund.
9. **İki hesap ile paralel** (3.6 tekniği): bir aktör kaynağı tüketirken diğeri
   aynı invariant'ı ihlal etmeyi dener.

**Araçlar & komutlar:**
```bash
# Eşzamanlı ikileme (race) penceresi — tek host, N paralel istek
seq 1 40 | xargs -P40 -I{} curl -s -b cookieA.txt -X POST \
  -H 'Content-Type: application/json' \
  -d '{"coupon":"WELCOME10","cart":"c_1"}' \
  https://app.target.tld/api/checkout/apply > race.out
grep -c '"applied":true' race.out   # 1 beklenir; >1 ise invariant ihlali
```
```bash
# sqlmap - sadece otomatik tespit için son adım; akış parametreleri için değil
sqlmap -u 'https://app.target.tld/api/orders?status=1' \
  -H 'Cookie: <authed>' --batch --level=2 --risk=2
```

**Teknik notları:**
- Gerçek para/state değiştiren testleri **minimal** ve **geri alınabilir**
  tut; prod'da ölçekli exploit yapma (ROE, BÖLÜM 0.1).
- İş kuralı açığı çoğu zaman *iki* sonuçtur: (a) istenen etki (kâr/limit aşımı),
  (b) kalıcılık (ledger/admin görünümü/email ile teyit).
- Arka plan worker/cron'lar sıklıkla request-time yetkisini ve kuralı atlar;
  ayrı test et.
- Content-type switching aynı işlem için farklı kod yoluna (daha zayıfına)
  götürebilir.

**Doğrulama barı (PoC):** Invariant'ın somut ihlali (iki refund tek bir
charge'a, negatif stok, limit aşımı, ücretsiz alınan ürün) **ve** istenen vs
kötüye kullanılan akışın aynı principal ile yan yana kanıtı **ve** durumun
otoriter kaynakta (ledger, admin, email) kalıcı gözlenmesi.

**Yanlış pozitif / tuzaklar:**
- Politikayla açıkça izin verilen davranış (dokümante trial, goodwill kredi).
- Yalnızca görsel tutarsızlık, kalıcı state değişimi yok → bulgu değil.
- Admin'in zaten yapabildiği bir şeyi low-priv kullanıcının yapması = asıl
  bulgu; ama admin aracı zaten admin'e açıksa tuzak değil, sadece kapsam.

**Şiddet kalibrasyonu:** Doğrudan finansal kayıp/arbitraj/çift-refund →
**high**; ölçekli ve otomatikleştirilebilirse **critical**. Görsel/teorik
iş kuralı → **low/medium**.

**Kaynaklar:**
- OWASP WSTG BUSL (Business Logic Testing, BUSL-01..10) — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
- PortSwigger Academy: Business logic vulnerabilities — https://portswigger.net/web-security/logic-flaws
- PortSwigger Academy: Race conditions — https://portswigger.net/web-security/race-conditions
- OWASP Cheat Sheet: Transactions / Idempotency — https://cheatsheetseries.owasp.org/
- CWE-840 (Business Logic Errors) — https://cwe.mitre.org/data/definitions/840.html

### 3.5 Post-auth saldırı yüzeyi taraması

**Ne / Amaç:** Giriş sonrası ortaya çıkan yüzeyi sistematik tara: anonim
crawl'da görünmeyen dashboard, ayarlar, API key yönetimi, entegrasyonlar, admin
panelleri ve export/upload/job yüzeyleri. Bu, yeni IDOR/BFLA/info-leak
adaylarının ana kaynağıdır.

**Saldırı yüzeyi / nerede:**
- **Dashboard/ayarlar:** profil, e-posta/telefon değiştirme, parola değiştirme,
  2FA yönetimi, oturum/cihaz listesi, API token'ları.
- **API key yönetimi:** list/create/rotate/revoke — key ID'leri IDOR/BFLA
  hedefi; dönen secret'lar info-leak.
- **Entegrasyonlar/webhooks:** URL alanları (SSRF), imza secret'ları, test/retry
  butonları (server-side istek tetikler), event replay.
- **Admin panelleri:** kullanıcı yönetimi, impersonation, refund/credit, audit
  log, feature flag.
- **Veri hareketi:** export (CSV/PDF/ZIP), import, bulk, file upload/download,
  job results.
- **Arama/notification/e-posta** ve **GraphQL mutation**'ları.

**Tespit — adım adım:**
1. **Oturumla yeniden crawlla.** Anonim crawlda görünmeyen yolları çıkar ve
   anonim↔authed envanterini diff'le.
2. **Authed JS analizi.** Bundle'daki rol/flag anahtarları, gizli route'lar,
   feature-gate isimleri (admin/dahili yolları açığa çıkarır).
3. **Parametre genişlet.** Authed endpoint'lerde gizli parametreleri ara
   (`arjun`). Ör. `?include_deleted=1`, `?as_user=`, `?owner_id=`.
4. **Her yüzeye yetki testi uygula** (3.2/3.3): export/job/key ID'lerinde IDOR,
   admin/setting uçlarında BFLA.
5. **SSRF/webhook.** URL alanlarına iç hedef/metadata adresi ver; DNS/HTTP
   callback dinle.
6. **Export'ları incele.** Başka kullanıcı/tenant verisi içeriyor mu; alanlar
   gereğinden fazla mı (over-fetching).
7. **Feature-gate bypass.** Client-side gizlenen admin/özellik endpoint'lerini
   doğrudan çağır.
8. **Audit/log yüzeyi.** Permission/rol değişimleri loglanıyor mu (yokluğu da
   bir bulgu olabilir - BÖLÜM 5.2).

**Araçlar & komutlar:**
```bash
# Oturumla crawl (cookie ile) - authed route envanteri
katana -u https://app.target.tld -H 'Cookie: <authed-cookie>' \
  -jc -d 4 -kf all -o authed_urls.txt
gospider -s https://app.target.tld -c 'session=<value>' \
  -d 3 --sitemap -o authed_spider

# Anonim ve authed envanterini diff'le
comm -13 <(sort anon_urls.txt) <(sort authed_urls.txt) > authed_only.txt
```
```bash
# Authed endpoint'lerde gizli parametre keşfi
arjun -u https://app.target.tld/api/account -H 'Cookie: <authed-cookie>' -m GET
arjun -u https://app.target.tld/api/account -H 'Cookie: <authed-cookie>' -m POST \
  -w /home/pentester/tools/wordlists/params.txt
```
```bash
# Webhook/entegrasyon URL ICERISINDE SSRF ve OOB etkilesim testi
interactsh-client -v &   # callback alani adresini al
curl -s -b cookieA.txt -X POST -H 'Content-Type: application/json' \
  -d '{"webhook_url":"http://<callback-id>.oast.fun/x"}' \
  https://app.target.tld/api/integrations
```

**Teknik notları:**
- Oturumla crawl, anonim crawldan **her zaman** daha geniş çıkar; asıl yüzey
  orada başlar.
- `arjun` çıktısı seni yanıltmasın: gizli parametre = saldırı yüzeyi, bulgu
  değil; etkisini 3.2/3.3 ile doğrula.
- Webhook test/retry butonları, "URL doğrulama" alanları ve avatar-from-URL
  özellikleri SSRF klasikleridir (BÖLÜM 2.22).
- Export/job ID'lerini list endpoint'inden topla; sonra doğrudan çağır.

**Doğrulama barı (PoC):** Authed-only yüzeyde, ikinci hesap/tenant ile
erişilemeyecek veri veya eylem; ya da server-side tetiklenen istek (SSRF) için
gerçek callback; ya da başka kullanıcıya ait export/key/job içeriği.

**Yanlış pozitif / tuzaklar:**
- Oturumla crawl'da bulunan her yolu "gizli" saymak — bazıları her oturumda
  görünür ve zaten herkese açıktır.
- Rate-limit/enumerasyon çıktısını yüksek şiddet saymak (BÖLÜM 5.2).
- Sadece source map/metadata gibi public artefaktları vuln saymak (BÖLÜM 5.2).

**Şiddet kalibrasyonu:** Post-auth IDOR/BFLA aynı kalibrasyonu izler (3.3).
İmza secret'ı/API key sızıntısı eyleme geçirilebilirse **high**; erişim
kanıtlanamayan "iç görünen isim" **info/low**.

**Kaynaklar:**
- OWASP WSTG CONF-05 (Enumerate Admin Interfaces) — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces
- OWASP WSTG INFO-06/07 (Entry Points, Execution Paths) — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points
- OWASP API Security Top 10 — API3:2023 Broken Object Property Level Authorization — https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- PortSwigger Academy: SSRF — https://portswigger.net/web-security/ssrf
- CWE-918 (Server-Side Request Forgery) — https://cwe.mitre.org/data/definitions/918.html

### 3.6 Oturum yaşam döngüsü (logout, refresh, impersonation)

**Ne / Amaç:** Kimlik doğrulamanın *yaşam boyu* güvenliği: login'den sonra
token/cookie nasıl yaşar, ne zaman ölür, kim iptal edebilir. Zayıf oturum
yaşam döngüsü, çalınmış (XSS/network) bir sırrın *kalıcı* erişime dönüşmesidir.

**Saldırı yüzeyi / nerede:** `Set-Cookie`, `Authorization: Bearer`, refresh
token endpoint'i, `/logout`, `/revoke`, session/device listesi, "remember me",
parola/e-posta değişimi sonrası invalidation, JWT `exp`/`nbf`/`jti`, ve
impersonation/support (admin kullanıcı olarak davranma) akışları.

**Tespit — adım adım:**
1. **Logout invalidation.** Logout öncesi cookie/token'ı kaydet; logout sonrası
   aynı değerle korumalı endpoint'i çağır. Hâlâ çalışıyorsa session
   invalidate edilmiyor demektir. Refresh token için de tekrarla.
2. **Refresh token rotation & reuse.** Refresh'i iki kez kullan; rotasyon var mı,
   eski token tekrar kullanılınca tüm aile iptal ediliyor mu (reuse detection)?
3. **Timeout.** Idle timeout ve absolute timeout'u test et; süre aşıldığında
   reddediliyor mu.
4. **Concurrent sessions.** Aynı hesapla çok oturum; birinde parola değiştir →
   diğer oturumlar düşüyor mu.
5. **Parola/e-posta/2FA değişimi.** Bu hassas değişikliklerden sonra *diğer*
   oturumlar ve token'lar geçersiz oluyor mu; re-auth isteniyor mu.
6. **Session fixation.** Login öncesi verilen session ID login sonrası
   korunuyor mu (kullanıcı kontrolündeki ID ile oturum sabitleme).
7. **Cookie güvenliği.** `Secure/HttpOnly/SameSite/Domain/Path` doğru mu;
   `Domain=.target.tld` ile subdomain'e ve `__Host-` eksikliğiyle başka
   subdomain'e sızabilir misin.
8. **JWT revocation/expiry.** `alg`/`kid`/`jku`/`x5u`/`jwk` manipülasyonları,
   `exp` uzatma, imzasız token; ayrıntı: `authentication_jwt` skill + BÖLÜM 2.3.
9. **Impersonation/support.** Kim kimi taklit edebilir (BFLA); taklit oturumu
   nasıl açılıyor/kapanıyor; taklit edilen kişinin oturumu/IP'si nasıl görünüyor;
   taklit için onay/audit var mı; taklit oturumu *hedefin* normal oturumuna
   dönüşebiliyor mu. Bu, kritik bir dikey erişim yoludur.
10. **Token konumları.** Access/refresh/ID token'ların localStorage/URL/log
    sızıntısı; `Referer` ile 3. partiye gitmesi.

**Araçlar & komutlar:**
```bash
# Logout-sonrası replay (invalidation testi)
curl -s -c jar.txt -X POST -d 'u=userA&p=Pass' https://app.target.tld/login
BEFORE=$(curl -s -b jar.txt -o /dev/null -w '%{http_code}' https://app.target.tld/api/me)
curl -s -b jar.txt -c jar.txt -X POST https://app.target.tld/logout
AFTER=$(curl -s -b jar.txt -o /dev/null -w '%{http_code}' https://app.target.tld/api/me)
echo "before=$BEFORE after=$AFTER"   # after hala 200 ise invalidation YOK
```
```bash
# Refresh token reuse / rotation
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<RT>"}' https://app.target.tld/api/token | tee r1.json
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<RT>"}' https://app.target.tld/api/token | tee r2.json
# RT iki kez calistiysa ve aile iptal edilmediyse -> reuse detection YOK
```
```bash
# JWT saldiri matrisi (alg=none, RS->HS, kid injection, claim edit)
jwt_tool <JWT> -M at -t https://app.target.tld/api/me -rh 'Authorization: Bearer <JWT>'
jwt_tool <JWT> -C -d /home/pentester/tools/wordlists/jwt-secrets.txt
```
```bash
# İki-hesap / iki-tarayıcı: agent-browser farklı --session ile paralel oturum
agent-browser --session userA open https://app.target.tld/account
agent-browser --session userB open https://app.target.tld/account
agent-browser --session userA state save ./A.json
agent-browser --session userB state save ./B.json
# CSRF / clickjacking / cross-user akışları iki session ile yürüt; Caido yakalar
```

**Teknik notları:**
- **İki-hesap tekniği** bu fazın omurgasıdır: `userA` ve `userB` ayrı
  `agent-browser --session` (izole cookie/localStorage). CSRF, yatay erişim,
  race window ve impersonation akışlarını iki gerçek oturumla yürüt. Her session
  ayrı Chromium'dur; iş bitince `agent-browser --session <ad> close`.
- Stateless JWT'de "logout" sunucu tarafında iptal etmez; `jti` denylist veya
  kısa `exp` + refresh yoksa bu tasarım bulgusudur.
- Oturum invalidation eksikliği *tek başına* genelde low/medium'dur; yükselmesi
  için o sırrın **nasıl çalınacağının** (XSS, network, log) da gösterilmesi
  gerekir (bkz. 4.4 dürüst metrik seçimi).
- Impersonation endpoint'i varsa mutlaka test et: çoğu sistemde en yüksek
  etkili dikey erişim yoludur.

**Doğrulama barı (PoC):** Logout/parola değişimi/expiry sonrası **aynı** eski
sır ile korumalı kaynağa erişim sürüyor; veya bir kullanıcı kimliğiyle başka
bir kullanıcı olarak davranma (impersonation) kanıtı.

**Yanlış pozitif / tuzaklar:**
- Sadece `Secure`/`HttpOnly` eksikliği → genelde low/info; erişim/etki
  gösterilmedikçe yüksek şiddet değil.
- "Logout sonrası cookie tarayıcıda duruyor" ≠ invalidation yok; sunucu
  reddediyorsa sorun yoktur — sunucu davranışını ölç.
- Client-side logout (yalnız localStorage temizliği) tek başına yeterli değil,
  ama token geçerliliğini sunucu test etmiyorsa bulgudur.
- Çalınmış token gerektiren senaryoyu "düşük karmaşıklık" sayma; o sırrın
  elde edilmesi bedava değildir (4.4).

**Şiddet kalibrasyonu:** İmzasız/forge edilebilir token veya session
invalidation'ın tamamen yokluğu + oturum çalma yolu → **critical/high**.
Salt cookie flag eksikliği → **low/info**. Impersonation yetkisiz kullanılabiliyor
ve audit yoksa → **high/critical**.

**Kaynaklar:**
- OWASP WSTG SESS (SESS-01..10) — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/
- OWASP WSTG SESS-06 (Logout) — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality
- OWASP WSTG SESS-03 (Session Fixation) — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation
- PortSwigger Academy: JWT — https://portswigger.net/web-security/jwt
- CWE-613 (Insufficient Session Expiration) — https://cwe.mitre.org/data/definitions/613.html
- CWE-384 (Session Fixation) — https://cwe.mitre.org/data/definitions/384.html

---
{% endraw %}

---


[← Web Pentest Methodology](/methodology/)

[← Bölüm 2](/methodology/02-zafiyet-siniflari/)

[Bölüm 4 →](/methodology/04-dogrulama-raporlama/)
