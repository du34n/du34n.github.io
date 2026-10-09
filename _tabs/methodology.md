---
title: Methodology
icon: fas fa-shield-halved
order: 5
---

# Web Pentest Methodology

Sıralı, uçtan uca sızma testi metodolojisi: **keşif/enumerasyon (blackbox) → kimlik doğrulamasız
zafiyet sınıfları → kimlik doğrulamalı (kullanıcılı) test → doğrulama, zincirleme ve raporlama.**

Her zafiyet sınıfı için: ne olduğu, nasıl tespit edileceği, araç/komutlar, adım adım kontrol
prosedürü, doğrulama (PoC) barı, yanlış pozitif tuzakları ve kanonik kaynak linkleri.

> Üstteki arama çubuğundan (sağ üstteki 🔍) tüm metodoloji içinde arama yapabilirsin.

## Bölümler

- [**Bölüm 0 — Hazırlık, Kapsam ve Kurulum**](/methodology/00-hazirlik/) — ROE/yetki, test tipleri ve OWASP WSTG eşlemesi, araç envanteri, kanıt hijyeni.
- [**Bölüm 1 — Keşif & Enumerasyon (Blackbox)**](/methodology/01-kesif-enumerasyon/) — Pasif OSINT, subdomain enum, DNS/port/servis, fingerprint, içerik/crawl/JS, param/vhost/API keşfi, ilk tarama ve threat model.
- [**Bölüm 2 — Zafiyet Sınıfları (2.1–2.47)**](/methodology/02-zafiyet-siniflari/) — Auth & erişim, injection (DB/kod), server-side istek/dosya, client-side, API & business logic, advanced/emerging sınıfların tespit-doğrulama prosedürleri.
- [**Bölüm 3 — Kimlik Doğrulamalı (Authenticated) Test**](/methodology/03-kimlik-dogrulamali-test/) — Hesap/rol/tenant matrisi, yatay-dikey erişim, tenant izolasyonu, post-auth yüzey, oturum yaşam döngüsü.
- [**Bölüm 4 — Doğrulama, Zincirleme ve Raporlama**](/methodology/04-dogrulama-raporlama/) — PoC barı, counterevidence/yanlış-pozitif eleme, zafiyet zincirleme, CVSS kalibrasyonu, rapor yazımı ve kanıt hijyeni.
- [**Bölüm 5 — Ekler**](/methodology/05-ekler/) — OWASP WSTG checklist, genel playbook'ların yanlış yaptığı şeyler, araç hızlı referansı, kaynak indexi.

## Kapsam

Web uygulamaları ve HTTP API'leri (blackbox + greybox + whitebox). Mobil/AD/cloud playbook'ları
ayrı ele alınır.

## Sürüm

Stage 2 — sürekli geliştirilir. Sahada öğrenilenler **Bölüm 5.2**'ye eklenir.
