#!/usr/bin/env python3
"""OSCP + Methodology başlıklarından site-geneli filter indeksi üretir.
Çıktı: assets/data/oscp-index.json  ->  [{t,p,u,k}]
  t: başlık metni (görünen)        p: bölüm (sayfa) başlığı
  u: sayfa permalink'i             k: derin bağlantı için jump anahtarı (=t)
Başlıklar kramdown id'sine bağımlı DEĞİL; hedef sayfada metin eşleşmesiyle atlanır.
Yeniden üretmek için:  python3 tools/gen_search_index.py
"""
import json, re, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
# OSCP notlari _posts/ icinde (oscp: true) yasar; metodoloji hala methodology/ klasorunde.
OUT = ROOT / "assets" / "data" / "oscp-index.json"
oscp_flag_re = re.compile(r"^oscp:\s*true\s*$", re.M)

fm_re = re.compile(r"^---\s*$")
title_re = re.compile(r'^title:\s*"?(.*?)"?\s*$')
perma_re = re.compile(r"^permalink:\s*(\S+)\s*$")
head_re = re.compile(r"^(#{2,4})\s+(.*?)\s*$")


def clean(text: str) -> str:
    text = re.sub(r"\{#[^}]+\}\s*$", "", text)   # kramdown {#id}
    text = text.replace("`", "")                  # inline code
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)  # [a](b) -> a
    text = re.sub(r"[*_]{1,3}", "", text)          # emphasis
    return re.sub(r"\s+", " ", text).strip()


def parse(md: pathlib.Path):
    lines = md.read_text(encoding="utf-8").splitlines()
    i, fm = 0, []
    if lines and fm_re.match(lines[0]):
        i = 1
        while i < len(lines) and not fm_re.match(lines[i]):
            fm.append(lines[i]); i += 1
        i += 1
    title, perma = None, None
    for f in fm:
        m = title_re.match(f);  title = m.group(1) if m else title
        m = perma_re.match(f);  perma = m.group(1) if m else perma
    if not perma:
        return []
    out, in_fence = [], False
    for ln in lines[i:]:
        s = ln.strip()
        if s.startswith("```") or s.startswith("~~~"):
            in_fence = not in_fence; continue
        if in_fence:
            continue
        m = head_re.match(ln)
        if m:
            t = clean(m.group(2))
            if t:
                out.append({"t": t, "u": perma})
    return title, perma, out


def collect(mds, label, index):
    for md in mds:
        res = parse(md)
        if not res:
            continue
        title, perma, heads = res
        page_title = title or md.stem
        # sayfanın kendisi de bir giriş (başlığa atla)
        index.append({"t": page_title, "p": label, "u": perma, "k": ""})
        for h in heads:
            index.append({"t": h["t"], "p": f"{label} · {page_title}",
                          "u": perma, "k": h["t"]})


def main():
    index = []
    # OSCP: _posts/ icinde oscp: true isaretli yazilar (dosya adi tarih-NN... -> bolum sirali)
    posts = ROOT / "_posts"
    if posts.is_dir():
        oscp_mds = [md for md in sorted(posts.glob("*.md"))
                    if oscp_flag_re.search(md.read_text(encoding="utf-8"))]
        collect(oscp_mds, "OSCP", index)
    # Metodoloji: hala methodology/ klasorunde
    meth = ROOT / "methodology"
    if meth.is_dir():
        collect(sorted(meth.glob("*.md")), "Metodoloji", index)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(index, ensure_ascii=False, separators=(",", ":")),
                   encoding="utf-8")
    print(f"{len(index)} giriş yazıldı -> {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
