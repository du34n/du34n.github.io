# du34n.github.io

Selahattin Duman'ın kişisel güvenlik notları sitesi — **OSCP / sızma testi** için
uçtan uca saha notları ve **web sızma testi metodolojisi**.

🌐 Canlı: <https://du34n.github.io>

## İçerik

- **OSCP Notları** (`/oscp/`) — port tarama ve enumerasyondan Active Directory
  saldırılarına, yetki yükseltmeden pivoting ve post-exploitation'a kadar 17 bölümlük
  komut-odaklı saha kitabı. HackTricks tarzı: her teknik için kısa tanım, tespit komutu
  ve sömürme adımları.
- **Metodoloji** (`/methodology/`) — blackbox web sızma testi metodolojisi: hazırlık,
  keşif, zafiyet sınıfları, doğrulama ve raporlama.

## Hızlı filter

Herhangi bir sayfada **`/`** tuşuna bas (veya sağ alttaki **⌕ Ara** düğmesine tıkla),
teknik/komut/bölüm yaz (`kerberoast`, `SUID`, `chisel` …) ve **Enter** ile doğrudan
ilgili bölüme atla. İndeks başlık metnine göre eşleşir; üreteç:

```shell
python3 tools/gen_search_index.py   # -> assets/data/oscp-index.json
```

## Yapı

```text
.
├── _posts/        # OSCP bölümleri (oscp: true, /oscp/NN-slug/ permalink)
├── methodology/   # web metodolojisi sayfaları
├── _tabs/         # OSCP ve Metodoloji sekme indeksleri, Hakkında
├── assets/        # filter CSS/JS + arama indeksi (oscp-index.json)
├── _includes/     # metadata-hook (filter enjeksiyonu), footer override
└── tools/         # gen_search_index.py
```

OSCP bölümleri Jekyll `_posts` içinde tutulur; bu sayede **Categories / Tags / Archives**
ve ana sayfa akışı otomatik dolar. `permalink` ile `/oscp/NN-slug/` URL'leri sabittir.

## Yerelde çalıştırma

```shell
bundle install
bundle exec jekyll serve
```

## Teknik

[Jekyll](https://jekyllrb.com) + [Chirpy](https://github.com/cotes2020/jekyll-theme-chirpy)
teması üzerine kuruludur; GitHub Actions ile GitHub Pages'e otomatik dağıtılır.

## Lisans

Kod [MIT](LICENSE) ile; yazılar aksi belirtilmedikçe CC BY 4.0 ile lisanslıdır.

> ⚠️ Bu notlar lab/sınav ortamı için genelleştirilmiş tekniklerdir. Herhangi bir sistem
> üzerinde yalnızca **yazılı yetkin olduğunda** kullan.
