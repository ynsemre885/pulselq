from flask import Flask, render_template, request, redirect, url_for, Response, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
from datetime import date, datetime, timedelta
import re
import csv
from io import StringIO 

app = Flask(__name__)
app.secret_key = "hbys-secret-key-change-me" 

DB_NAME = "hbys.db"


# ---------------------------
# DB helpers
# --------------------------- 

def migrate_hash_passwords():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT id, sifre FROM kullanicilar")
    rows = cur.fetchall()

    for r in rows:
        pw = r["sifre"] or ""
        # werkzeug hashleri genelde "pbkdf2:" veya "scrypt:" ile başlar
        if pw.startswith("pbkdf2:") or pw.startswith("scrypt:"):
            continue
        # düz şifreyi hashle
        new_pw = generate_password_hash(pw)
        cur.execute("UPDATE kullanicilar SET sifre = ? WHERE id = ?", (new_pw, r["id"]))

    conn.commit()
    conn.close() 

def get_conn():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # dict gibi erişim
    return conn

def run_safe_migrations():
    conn = get_conn()
    cur = conn.cursor()

    # 🔹 Hastalar - dogum_yili
    if not column_exists("hastalar", "dogum_yili"):
        cur.execute("ALTER TABLE hastalar ADD COLUMN dogum_yili INTEGER")

    # 🔹 Hastalar - cinsiyet
    if not column_exists("hastalar", "cinsiyet"):
        cur.execute("ALTER TABLE hastalar ADD COLUMN cinsiyet TEXT")

    # 🔹 Randevular - sikayet
    if not column_exists("randevular", "sikayet"):
        cur.execute("ALTER TABLE randevular ADD COLUMN sikayet TEXT")

    # 🔹 Randevular - aciliyet
    if not column_exists("randevular", "aciliyet"):
        cur.execute("ALTER TABLE randevular ADD COLUMN aciliyet TEXT")

    # 🔹 Randevular - risk_skor
    if not column_exists("randevular", "risk_skor"):
        cur.execute("ALTER TABLE randevular ADD COLUMN risk_skor INTEGER")

    # 🔹 Randevular - klinik_not
    if not column_exists("randevular", "klinik_not"):
        cur.execute("ALTER TABLE randevular ADD COLUMN klinik_not TEXT")

    conn.commit()
    conn.close() 

def column_exists(table_name: str, column_name: str) -> bool:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table_name})")
    columns = [row["name"] for row in cur.fetchall()]
    conn.close()
    return column_name in columns 

def kolon_var_mi(cur, tablo, kolon):
    cur.execute(f"PRAGMA table_info({tablo})")
    kolonlar = [r["name"] for r in cur.fetchall()]
    return kolon in kolonlar


def migrate_klinik_alanlari():
    conn = get_conn()
    cur = conn.cursor()

    hedef_tablo = "randevular"

    yeni_kolonlar = [
        ("yas", "INTEGER"),
        ("ates", "REAL"),
        ("nabiz", "INTEGER"),
        ("sistolik", "INTEGER"),
        ("diyastolik", "INTEGER"),
        ("spo2", "INTEGER"),
        ("kronik_hastalik", "TEXT"),
        ("alerji", "TEXT"),
        ("kkds_risk", "TEXT"),
        ("kkds_oneri", "TEXT"),
        ("kkds_tetkik", "TEXT"),
        ("kkds_kirmizi_bayrak", "TEXT")
    ]

    for kolon_adi, kolon_tipi in yeni_kolonlar:
        if not kolon_var_mi(cur, hedef_tablo, kolon_adi):
            cur.execute(f"ALTER TABLE {hedef_tablo} ADD COLUMN {kolon_adi} {kolon_tipi}")

    conn.commit()
    conn.close() 

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # Kullanıcılar
    cur.execute("""
    CREATE TABLE IF NOT EXISTS kullanicilar (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kullanici_adi TEXT UNIQUE,
        sifre TEXT,
        yetki TEXT
    )
    """)

    # Hastalar
    cur.execute("""
    CREATE TABLE IF NOT EXISTS hastalar (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ad TEXT,
    soyad TEXT,
    tc TEXT,
    dogum_yili INTEGER,
    cinsiyet TEXT
)
    """) 

    # Doktorlar
    cur.execute("""
    CREATE TABLE IF NOT EXISTS doktorlar (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ad TEXT,
        soyad TEXT,
        brans TEXT
    )
    """)

    # Randevular (HBYS 2.0)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS randevular (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hasta_id INTEGER,
        doktor_id INTEGER,
        tarih TEXT,
        saat TEXT,
        sikayet TEXT,
        aciliyet TEXT,
        risk_skor INTEGER,
        klinik_not TEXT
    )
    """) 

    conn.commit()
    conn.close()

def migrate_add_audit_logs():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        action TEXT,
        entity TEXT,
        entity_id INTEGER,
        detail TEXT
    )
    """)
    conn.commit()
    conn.close()

from typing import Optional

def audit_log(action: str, entity: str, entity_id: Optional[int], detail: str = ""): 
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO audit_logs (ts, action, entity, entity_id, detail)
        VALUES (?, ?, ?, ?, ?)
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), action, entity, entity_id, detail))
    conn.commit()
    conn.close()

def seed_admin_once():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM kullanicilar")
    if cur.fetchone()["c"] == 0:
        cur.execute("""
        INSERT INTO kullanicilar (kullanici_adi, sifre, yetki)
        VALUES (?, ?, ?)
        """, ("admin", generate_password_hash("1234"), "admin"))
        conn.commit()
    conn.close() 

def seed_user_once():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM kullanicilar WHERE kullanici_adi = ?", ("user",))
    if cur.fetchone()["c"] == 0:
        cur.execute("""
        INSERT INTO kullanicilar (kullanici_adi, sifre, yetki)
        VALUES (?, ?, ?)
        """, ("user", generate_password_hash("1234"), "user"))
        conn.commit()
    conn.close() 


def seed_doctors_once():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM doktorlar")
    if cur.fetchone()["c"] == 0:
        doctors = [
            ("Ahmet", "Demir", "Dahiliye"),
            ("Elif", "Yılmaz", "Kardiyoloji"),
            ("Mert", "Kaya", "Nöroloji"),
            ("Zeynep", "Aydın", "Ortopedi"),
            ("Deniz", "Koç", "Gastroenteroloji"),
            ("Sena", "Arslan", "Dermatoloji"),
        ]
        cur.executemany("INSERT INTO doktorlar (ad, soyad, brans) VALUES (?, ?, ?)", doctors)
        conn.commit()
    conn.close()


# ---------------------------
# AI branş motoru (puan + güven)
# ---------------------------

def normalize_text(s: str) -> str:
    s = (s or "").lower()
    # türkçe karakterleri sadeleştir (eşleşmeler stabil olsun)
    s = (s.replace("ı", "i").replace("ğ", "g").replace("ü", "u")
           .replace("ş", "s").replace("ö", "o").replace("ç", "c"))
    s = re.sub(r"\s+", " ", s).strip()
    return s

NEGATIONS = ["yok", "degil", "değil", "olmuyor", "hissetmiyorum", "yoktur", "olmadi", "olmadı"]

def is_negated(text: str, keyword: str, window: int = 18) -> bool:
    """
    keyword geçiyorsa, çevresinde 'yok/değil' var mı bakar.
    window: keyword çevresinde kaç karakter taransın.
    """
    t = normalize_text(text)
    k = normalize_text(keyword)

    idx = t.find(k)
    if idx == -1:
        return False

    left = max(0, idx - window)
    right = min(len(t), idx + len(k) + window)
    around = t[left:right]

    # NEGATIONS da normalize edildiği için hem degil hem değil yakalanır
    return any(normalize_text(n) in around for n in NEGATIONS)

SYNONYMS = {

# -----------------------
# Kardiyoloji
# -----------------------

"gogus agrisi": [
"gogsum agriyor",
"gogusum agriyor",
"gogusumde baski",
"gogus sikismasi",
"gogus yanmasi"
],

"carpinti": [
"kalbim hizli atiyor",
"kalbim kut kut",
"kalp carpintisi",
"ritim bozuklugu"
],

"nefes darligi": [
"nefes alamiyorum",
"nefesim kesiliyor",
"soluk alamiyorum",
"nefesim daraliyor"
],

"terleme": [
"soguk terleme",
"asiri terleme"
],

# -----------------------
# Nöroloji
# -----------------------

"bas agrisi": [
"basim agriyor",
"migren",
"zonklama",
"basim catliyor"
],

"bas donmesi": [
"vertigo",
"denge kaybi",
"basim donuyor"
],

"uyusma": [
"kol uyusmasi",
"bacak uyusmasi",
"yuz uyusmasi"
],

"gorme kaybi": [
"bulanık goruyorum",
"cift goruyorum",
"gorme bozuklugu"
],

"konusma bozuk": [
"konusamiyorum",
"dilim dolaniyor",
"kelimeleri soyleyemiyorum"
],

# -----------------------
# Solunum
# -----------------------

"oksuruk": [
"balgam",
"kuru oksuruk",
"surekli oksuruk"
],

"hirlti": [
"hirilti",
"nefeste ses"
],

"bogulma hissi": [
"boguluyorum",
"nefesim tikanıyor"
],

# -----------------------
# Enfeksiyon
# -----------------------

"ates": [
"yuksek ates",
"titreme",
"usume"
],

"halsizlik": [
"yorgunluk",
"bitkinlik",
"enerji yok"
],

# -----------------------
# Gastroenteroloji
# -----------------------

"karin agrisi": [
"karnim agriyor",
"mide agrisi",
"kramp"
],

"bulanti": [
"mide bulantisi",
"kusacak gibi"
],

"kusma": [
"istifra",
"mide bosalmasi"
],

"ishal": [
"sulu diski",
"ishalim var"
],

"kabiz": [
"tuvalete cikamiyorum"
],

# -----------------------
# Üroloji
# -----------------------

"idrar yanmasi": [
"idrar yaparken yanma",
"idrar agrisi"
],

"sik idrar": [
"sik idrara cikiyorum"
],

"idrarda kan": [
"kirmizi idrar"
],

# -----------------------
# Ortopedi
# -----------------------

"bel agrisi": [
"belim agriyor",
"bel tutulmasi"
],

"boyun agrisi": [
"boynum tutuldu"
],

"diz agrisi": [
"dizim agriyor"
],

"eklem agrisi": [
"eklemlerim agriyor"
],

# -----------------------
# Dermatoloji
# -----------------------

"kasinti": [
"cildim kasiniyor"
],

"dokuntu": [
"kizariklik",
"deride leke",
"kabarcik"
]

} 


BRANS_RULES = {
    "Kardiyoloji": {
        "gogus agrisi": 3,
        "nefes darligi": 3,
        "carpinti": 2,
        "tansiyon": 1,
        "kalp": 1,
    },

    "Dahiliye": {
        "ates": 2,
        "bogaz agrisi": 1,
        "halsizlik": 1,
        "yorgunluk": 1,
        "grip": 1,
        "usume": 1,
        "titreme": 1,
    },
    "Nöroloji": {
        "bas agrisi": 2,
        "bas donmesi": 2,
        "uyusma": 2,
        "unutkanlik": 1,
        "bayil": 2,
        "kol": 1,
        "konusma bozuk": 4,
        "yuz kaymasi": 4,
        "inme": 4,
        "felc": 4,
    }, 
    "Ortopedi": {
        "bel agrisi": 2,
        "boyun agrisi": 2,
        "diz": 1,
        "omuz": 1,
        "burkulma": 2,
        "kemik": 1,
    },
    "Gastroenteroloji": {
        "karin agrisi": 2,
        "bulanti": 1,
        "kusma": 1,
        "ishal": 1,
        "kabiz": 1,
        "reflu": 2,
        "mide yanmasi": 2,
    },
    "Dermatoloji": {
        "kasinti": 2,
        "dokuntu": 2,
        "sivilce": 1,
        "egzama": 2,
        "cilt": 1,
    },
} 

# Klinik öncelik boost sistemi
CLINICAL_BOOST = {
    "Nöroloji": ["felc", "uyusma", "konusma bozuk", "yuz kaymasi"],
    "Kardiyoloji": ["gogus agrisi", "nefes darligi", "carpinti"],
    "Gastroenteroloji": ["kan kus", "siddetli karin agrisi"],
}

def expand_with_synonyms(text: str) -> str:
    t = normalize_text(text)

    extra = []
    for canonical, variants in SYNONYMS.items():
        canon_hit = canonical in t

        variant_hit = False
        for v in variants:
            v_norm = normalize_text(v)
            if v_norm and v_norm in t:
                variant_hit = True
                break

        if canon_hit or variant_hit:
            extra.append(canonical)

    return t + " " + " ".join(extra) 


def brans_belirle(sikayet: str):
    s = expand_with_synonyms(sikayet)

    skorlar = {}

    for brans, rules in BRANS_RULES.items():
        skor = 0

        # Temel kelime puanlama
        for key, w in rules.items():
            if key in s:
                if is_negated(sikayet, key):
                    skor -= w
                else:
                    skor += w

        # 🔥 Klinik boost
        if brans in CLINICAL_BOOST:
            for kritik_kelime in CLINICAL_BOOST[brans]:
                if kritik_kelime in s and not is_negated(sikayet, kritik_kelime):
                    skor += 3  # boost puanı

        skorlar[brans] = max(0, skor)

    toplam = sum(skorlar.values())
    if toplam == 0:
        return ("Genel Muayene", 0), []

    sirali = sorted(skorlar.items(), key=lambda x: x[1], reverse=True)

    en_iyi, en_yuksek = sirali[0]
    ikinci_skor = sirali[1][1] if len(sirali) > 1 else 0

    # Güven hesapla (tek branş puan aldıysa %100'ü kırp)
    if ikinci_skor == 0:
        guven = min(85, int((en_yuksek / max(1, toplam)) * 100))
    else:
        guven = int((en_yuksek / max(1, toplam)) * 100)

    # Top-2 olasılık listesi
    top2 = []
    for br, sc in sirali[:2]:
        pct = int((sc / max(1, toplam)) * 100)
        top2.append((br, pct))

    return (en_iyi, guven), top2

def aciliyet_belirle(sikayet: str):
    s = expand_with_synonyms(sikayet) 

    # 🔴 KRİTİK belirtiler: varsa direkt ACİL (negasyon yoksa)
    KRITIK = [
        "bilinc kaybi", "felc", "inme", "kanama", "kan kus",
        "anafilaksi", "nobet", "gogus agr", "nefes darl"
    ]
    if any(k in s and not is_negated(sikayet, k) for k in KRITIK):
        return "ACIL", 98, "🔴 Kritik belirti olabilir. Acil değerlendirme önerilir."

    # 🟡 Tek taraf uyuşma -> öncelikli (negasyon yoksa)
    if (("sol" in s) or ("sag" in s)) and ("uyusma" in s) and not is_negated(sikayet, "uyusma"):
        return "ONCELIKLI", 80, "🟡 Tek taraf uyuşma önemli olabilir. Kısa sürede değerlendirme önerilir."

    # 🔴 ACİL anahtar kelimeler (normalize edilmiş)
    acil = [
        "gogus agr", "nefes darl", "bayil", "felc", "inme", "kanama", "kan kus",
        "siddetli", "bilinc kayb", "nobet", "intihar", "zehirlen", "anafilaksi",
        "carpinti", "konusma bozuk", "yuz kaymasi"
    ]

    # 🟡 ÖNCELİKLİ (normalize edilmiş)
    oncelikli = [
        "ates", "yuksek ates", "kusma", "ishal", "bas don", "siddetli bas agr",
        "karin agr", "idrar yan", "dokuntu", "enfeksiyon", "migren"
    ]

    if any(k in s and not is_negated(sikayet, k) for k in acil):
        return "ACIL", 95, "🔴 Acil belirti olabilir. En yakın zamanda değerlendirme önerilir."

    if any(k in s and not is_negated(sikayet, k) for k in oncelikli):
        return "ONCELIKLI", 75, "🟡 Öncelikli değerlendirme önerilir."

    return "NORMAL", 50, "🟢 Normal öncelik."

def tani_tahmini(sikayet):

    s = normalize_text(sikayet)

    tanilar = []

    if "gogus agr" in s and "nefes darl" in s:
        tanilar.append("Akut Koroner Sendrom")
        tanilar.append("Pulmoner Emboli")
        tanilar.append("Anksiyete")

    if "konusma bozuk" in s or "yuz kaymasi" in s:
        tanilar.append("İnme (Stroke)")
        tanilar.append("TIA")

    if "ates" in s and "oksuruk" in s:
        tanilar.append("Pnömoni")
        tanilar.append("Üst Solunum Yolu Enfeksiyonu")

    if "karin agr" in s and "kusma" in s:
        tanilar.append("Akut Gastroenterit")
        tanilar.append("Apandisit")

    if "bas agr" in s and "bulanti" in s:
        tanilar.append("Migren")
        tanilar.append("Hipertansiyon")

    return tanilar[:3] 

def alarm_kategorisi(sikayet):
    s = normalize_text(sikayet)

    kategoriler = []

    if "gogus agr" in s or "carpinti" in s:
        kategoriler.append("Kardiyak Alarm")

    if "konusma bozuk" in s or "yuz kaymasi" in s or "felc" in s:
        kategoriler.append("Nörolojik Alarm")

    if "nefes darl" in s:
        kategoriler.append("Solunum Alarmı")

    if "ates" in s:
        kategoriler.append("Enfeksiyon Alarmı")

    return kategoriler 

def semptom_kombinasyon_analizi(sikayet):
    s = expand_with_synonyms(sikayet)

    kombinasyonlar = []

    # Kardiyak kritik kombinasyon
    if "gogus agr" in s and "nefes darl" in s and "terleme" in s:
        kombinasyonlar.append("🚨 Akut Koroner Sendrom Şüphesi")

    elif "gogus agr" in s and "nefes darl" in s:
        kombinasyonlar.append("⚠ Kardiyak / Solunumsal Acil Durum Şüphesi")

    # Nörolojik kritik kombinasyon
    if ("konusma bozuk" in s and "yuz kaymasi" in s) or \
       ("konusma bozuk" in s and "uyusma" in s) or \
       ("yuz kaymasi" in s and "uyusma" in s):
        kombinasyonlar.append("🚨 İnme (Stroke) Şüphesi")

    # Solunum / enfeksiyon kombinasyonu
    if "ates" in s and "oksuruk" in s and "nefes darl" in s:
        kombinasyonlar.append("⚠ Pnömoni / Ciddi Solunum Yolu Enfeksiyonu Şüphesi")

    # Gastro kritik kombinasyon
    if "karin agr" in s and "kusma" in s and "ates" in s:
        kombinasyonlar.append("⚠ Akut Batın / Apandisit Şüphesi")

    # Hemodinamik risk
    if "bayil" in s and ("gogus agr" in s or "carpinti" in s):
        kombinasyonlar.append("🚨 Kardiyak Senkop Riski")

    return kombinasyonlar 

def gercek_triage_motoru(
    sikayet,
    yas=None,
    ates=None,
    nabiz=None,
    sistolik=None,
    diyastolik=None,
    spo2=None,
    kronik_hastalik=None
):
    s = expand_with_synonyms(sikayet)
    kronik = normalize_text(kronik_hastalik or "")

    skor = 0
    kararlar = []
    aciklamalar = []

    # -------------------
    # Vital bulgular
    # -------------------
    if spo2 is not None:
        if spo2 < 90:
            skor += 40
            kararlar.append("ACIL SERVISE YONLENDIR")
            aciklamalar.append("SpO2 %90 altı: ciddi hipoksemi riski.")
        elif spo2 < 94:
            skor += 20
            aciklamalar.append("SpO2 düşük: solunumsal risk olabilir.")

    if nabiz is not None:
        if nabiz >= 130:
            skor += 25
            aciklamalar.append("Nabız çok yüksek: ciddi kardiyak/hemodinamik risk.")
        elif nabiz >= 110:
            skor += 15
            aciklamalar.append("Taşikardi mevcut.")

    if sistolik is not None:
        if sistolik < 90:
            skor += 30
            kararlar.append("ACIL SERVISE YONLENDIR")
            aciklamalar.append("Sistolik tansiyon 90 altı: hipotansiyon.")
        elif sistolik >= 180:
            skor += 25
            aciklamalar.append("Sistolik tansiyon çok yüksek.")

    if ates is not None:
        if ates >= 39:
            skor += 20
            aciklamalar.append("39°C üzeri ateş.")
        elif ates >= 38:
            skor += 10
            aciklamalar.append("Ateş mevcut.")

    # -------------------
    # Semptom kombinasyonları
    # -------------------
    if "gogus agr" in s and "nefes darl" in s:
        skor += 30
        kararlar.append("ACIL KARDIYOLOJI / ACIL SERVIS")
        aciklamalar.append("Göğüs ağrısı + nefes darlığı.")

    if "konusma bozuk" in s or "yuz kaymasi" in s or "felc" in s:
        skor += 35
        kararlar.append("ACIL NOROLOJI / ACIL SERVIS")
        aciklamalar.append("İnme ile uyumlu nörolojik bulgu.")

    if "ates" in s and "oksuruk" in s and "nefes darl" in s:
        skor += 25
        aciklamalar.append("Pnömoni / ciddi enfeksiyon olasılığı.")

    if "karin agr" in s and "kusma" in s and "ates" in s:
        skor += 20
        aciklamalar.append("Akut batın olasılığı.")

    if "bayil" in s and ("carpinti" in s or "gogus agr" in s):
        skor += 30
        kararlar.append("ACIL DEGERLENDIRME")
        aciklamalar.append("Bayılma + kardiyak semptom birlikteliği.")

    # -------------------
    # Yaş ve kronik hastalık
    # -------------------
    if yas is not None:
        if yas >= 75:
            skor += 20
            aciklamalar.append("İleri yaş (75+).")
        elif yas >= 65:
            skor += 10
            aciklamalar.append("Yaş 65+.")

    if "diyabet" in kronik:
        skor += 8
        aciklamalar.append("Diyabet öyküsü.")
    if "hipertansiyon" in kronik:
        skor += 8
        aciklamalar.append("Hipertansiyon öyküsü.")
    if "kalp" in kronik:
        skor += 12
        aciklamalar.append("Kardiyak hastalık öyküsü.")
    if "koah" in kronik or "astim" in kronik or "astım" in kronik:
        skor += 10
        aciklamalar.append("Solunum sistemi kronik hastalığı.")

    # -------------------
    # Triage seviyesi
    # -------------------
    if skor >= 70:
        seviye = "KRITIK"
        yonlendirme = "ACIL"
    elif skor >= 40:
        seviye = "YUKSEK"
        yonlendirme = "AYNI GUN"
    elif skor >= 20:
        seviye = "ORTA"
        yonlendirme = "24 SAAT ICINDE"
    else:
        seviye = "DUSUK"
        yonlendirme = "POLIKLINIK"

    # Tekrarlı kararları temizle
    kararlar = list(dict.fromkeys(kararlar))
    aciklamalar = list(dict.fromkeys(aciklamalar))

    if not kararlar:
        if yonlendirme == "POLIKLINIK":
            kararlar = ["POLIKLINIK TAKIBI UYGUN"]
        elif yonlendirme == "24 SAAT ICINDE":
            kararlar = ["24 SAAT ICINDE DEGERLENDIR"]
        elif yonlendirme == "AYNI GUN":
            kararlar = ["AYNI GUN UZMAN DEGERLENDIRMESI"]
        else:
            kararlar = ["ACIL SERVISE YONLENDIR"]

    return {
        "skor": skor,
        "seviye": seviye,
        "yonlendirme": yonlendirme,
        "kararlar": kararlar,
        "aciklamalar": aciklamalar
    } 

def hesapla_yas(dogum_yili):
    try:
        return date.today().year - int(dogum_yili)
    except:
        return None

def klinik_risk_analizi(sikayet: str, dogum_yili=None, cinsiyet=None):
    s = expand_with_synonyms(sikayet)

    yas = hesapla_yas(dogum_yili)

    risk = 0
    notlar = []

    # Yaş bazlı temel risk
    if yas is not None:
        if yas >= 65:
            risk += 20
            notlar.append("Yaş ≥ 65: komorbidite ve komplikasyon riski artar.")
        elif yas >= 50:
            risk += 10
            notlar.append("Yaş ≥ 50: kardiyak/nöro risk ihtimali artar.")

    # Kritik semptomlar (senin aciliyet motoruna paralel)
    kritik = [
        ("gogus agr", 35, "Göğüs ağrısı: kardiyak risk dışlanmalı."),
        ("nefes darl", 30, "Nefes darlığı: kardiyak/solunumsal acil olabilir."),
        ("konusma bozuk", 40, "Konuşma bozukluğu: inme şüphesi."),
        ("yuz kaymasi", 40, "Yüz kayması: inme şüphesi."),
        ("felc", 45, "Felç bulgusu: acil nörolojik değerlendirme."),
        ("bayil", 25, "Bayılma: senkop nedenleri değerlendirilmeli."),
        ("kan kus", 35, "Kan kusma: ciddi GI kanama riski."),
        ("siddetli", 15, "Şiddetli belirti ifadesi: öncelik artar."),
    ]

    for key, puan, msg in kritik:
        if key in s and not is_negated(sikayet, key):
            risk += puan
            notlar.append(msg)

    # Cinsiyet bazlı küçük ayarlama (çok agresif yapmıyoruz)
    if (cinsiyet or "").upper() == "E" and yas is not None and yas >= 45:
        if ("gogus agr" in s or "nefes darl" in s) and not is_negated(sikayet, "gogus agr"):
            risk += 5
            notlar.append("Erkek + yaş: kardiyak risk faktörü artabilir.")

    # Clamp 0-100
    risk = max(0, min(100, risk))

    if risk >= 75:
        seviye = "YUKSEK"
    elif risk >= 45:
        seviye = "ORTA"
    else:
        seviye = "DUSUK"

    klinik_not = f"Risk Seviyesi: {seviye}. " + (" ".join(notlar) if notlar else "Belirgin risk sinyali saptanmadı.")
    return risk, seviye, klinik_not 

def klinik_karar_destek(sikayet, yas=None, ates=None, nabiz=None, sistolik=None, diyastolik=None, spo2=None, kronik_hastalik=None): 
    sikayet = (sikayet or "").lower()
    kronik_hastalik = (kronik_hastalik or "").lower()
 
    riskler = []
    oneriler = []
    tetkikler = []
    kirmizi_bayrak = []
 
    # ---------------------------
    # Genel vital değerlendirme
    # ---------------------------
    if ates is not None: 
        if ates >= 39:
            riskler.append("Yüksek ateş")
            kirmizi_bayrak.append("39°C ve üzeri ateş")
        elif ates >= 38:
            riskler.append("Ateş mevcut")

    if nabiz is not None:
        if nabiz >= 120:
            riskler.append("Taşikardi")
            kirmizi_bayrak.append("Nabız 120 üzeri")
        elif nabiz <= 45:
            riskler.append("Ciddi bradikardi")
            kirmizi_bayrak.append("Nabız 45 altı")

    if sistolik is not None:
        if sistolik >= 180:
            riskler.append("Ciddi hipertansiyon")
            kirmizi_bayrak.append("Sistolik tansiyon 180 üzeri")
        elif sistolik < 90:
            riskler.append("Hipotansiyon")
            kirmizi_bayrak.append("Sistolik tansiyon 90 altı")

    if spo2 is not None:
        if spo2 < 90:
            riskler.append("Ciddi oksijen düşüklüğü")
            kirmizi_bayrak.append("SpO2 %90 altı")
        elif spo2 < 94:
            riskler.append("Oksijen satürasyonu düşük")

    if yas is not None and yas >= 65:
        riskler.append("İleri yaş hasta")

    if "diyabet" in kronik_hastalik:
        riskler.append("Diyabet öyküsü")
    if "hipertansiyon" in kronik_hastalik:
        riskler.append("Hipertansiyon öyküsü")
    if "kalp" in kronik_hastalik:
        riskler.append("Kardiyak hastalık öyküsü")
    if "astım" in kronik_hastalik or "koah" in kronik_hastalik:
        riskler.append("Solunum sistemi kronik hastalığı")

    # ---------------------------
    # Şikayete göre değerlendirme
    # ---------------------------
    if any(x in sikayet for x in ["göğüs ağrısı", "gogus agrisi", "kalp çarpıntısı", "kalp carpintisi"]):
        oneriler.append("Kardiyoloji / Acil değerlendirmesi önerilir")
        tetkikler.extend(["EKG", "Troponin", "Tansiyon takibi"])
        if yas and yas >= 40:
            riskler.append("Kardiyak olay açısından dikkat")
        if "nefes darlığı" in sikayet or "nefes darligi" in sikayet:
            kirmizi_bayrak.append("Göğüs ağrısı ile birlikte nefes darlığı")

    if any(x in sikayet for x in ["nefes darlığı", "nefes darligi", "öksürük", "oksuruk"]):
        oneriler.append("Göğüs hastalıkları değerlendirmesi önerilir")
        tetkikler.extend(["SpO2 takibi", "Akciğer grafisi", "Hemogram"])
        if ates is not None and ates >= 38:
            riskler.append("Enfeksiyon/pnömoni olasılığı")

    if any(x in sikayet for x in ["karın ağrısı", "karin agrisi", "mide bulantısı", "mide bulantisi", "kusma"]):
        oneriler.append("Genel cerrahi / Dahiliye değerlendirmesi önerilir")
        tetkikler.extend(["Hemogram", "CRP", "Batın USG"])
        if ates is not None and ates >= 38:
            riskler.append("Akut abdominal enfeksiyon açısından dikkat")

    if any(x in sikayet for x in ["baş ağrısı", "bas agrisi", "baş dönmesi", "bas donmesi", "bayılma", "bayilma"]):
        oneriler.append("Nöroloji / Acil değerlendirmesi düşünülebilir")
        tetkikler.extend(["Nörolojik muayene", "Tansiyon ölçümü"])
        if sistolik is not None and sistolik >= 180:
            kirmizi_bayrak.append("Şiddetli baş ağrısı + çok yüksek tansiyon")

    if any(x in sikayet for x in ["idrar yaparken yanma", "sık idrara çıkma", "idrar", "bel ağrısı", "bel agrisi"]):
        oneriler.append("Üroloji / Dahiliye değerlendirmesi önerilir")
        tetkikler.extend(["Tam idrar tahlili", "İdrar kültürü", "Hemogram"])

    if any(x in sikayet for x in ["boğaz ağrısı", "bogaz agrisi", "burun akıntısı", "burun akintisi", "halsizlik"]):
        oneriler.append("Üst solunum yolu enfeksiyonu açısından değerlendirme yapılabilir")
        tetkikler.extend(["Hemogram", "CRP"])

    # ---------------------------
    # Özel kırmızı bayrak kombinasyonları
    # ---------------------------
    if ("göğüs ağrısı" in sikayet or "gogus agrisi" in sikayet) and (spo2 is not None and spo2 < 94):
        kirmizi_bayrak.append("Göğüs ağrısı + düşük oksijen satürasyonu")

    if ("nefes darlığı" in sikayet or "nefes darligi" in sikayet) and (spo2 is not None and spo2 < 90):
        kirmizi_bayrak.append("Şiddetli solunum sıkıntısı riski")

    if ("bayılma" in sikayet or "bayilma" in sikayet) and (sistolik is not None and sistolik < 90):
        kirmizi_bayrak.append("Bayılma + düşük tansiyon")

    # Tekrarlı verileri temizle
    riskler = list(dict.fromkeys(riskler))
    oneriler = list(dict.fromkeys(oneriler))
    tetkikler = list(dict.fromkeys(tetkikler))
    kirmizi_bayrak = list(dict.fromkeys(kirmizi_bayrak))

    if not oneriler:
        oneriler.append("Hekim muayenesi sonrası ileri değerlendirme önerilir")

    sonuc = {
        "risk": ", ".join(riskler) if riskler else "Belirgin ek risk saptanmadı",
        "oneri": ", ".join(oneriler),
        "tetkik": ", ".join(tetkikler) if tetkikler else "Gerekirse temel laboratuvar",
        "kirmizi_bayrak": ", ".join(kirmizi_bayrak) if kirmizi_bayrak else "Yok"
    }

    return sonuc 

def erken_uyari_belirle(sikayet, risk_skor, aciliyet):
    sikayet = (sikayet or "").lower()

    uyarilar = []

    if "göğüs" in sikayet or "gogus" in sikayet:
        uyarilar.append("⚠ Olası Kalp Krizi")

    if "nefes" in sikayet:
        uyarilar.append("⚠ Kritik Solunum Problemi")

    if "uyuşma" in sikayet or "uyusma" in sikayet or "konuşma" in sikayet or "konusma" in sikayet:
        uyarilar.append("⚠ Olası İnme")

    if "bayıl" in sikayet or "bayil" in sikayet or "bilinç" in sikayet or "bilinc" in sikayet:
        uyarilar.append("⚠ Bilinç Kaybı Riski")

    if (risk_skor or 0) >= 80:
        uyarilar.append("⚠ Yüksek Risk Skoru")

    if aciliyet == "ACIL":
        uyarilar.append("⚠ Acil Müdahale Gerekiyor")

    return uyarilar 

def hasta_risk_tahmin_motoru(hasta_id):
    conn = get_conn()
    cur = conn.cursor()

    # Hasta temel bilgi
    cur.execute("""
        SELECT id, ad, soyad, tc, dogum_yili, cinsiyet
        FROM hastalar
        WHERE id = ?
    """, (hasta_id,))
    hasta = cur.fetchone()

    if not hasta:
        conn.close()
        return None

    yas = hesapla_yas(hasta["dogum_yili"])

    # Son 30 gün başvuruları
    cur.execute("""
        SELECT sikayet, aciliyet, risk_skor, tarih, kronik_hastalik
        FROM randevular
        WHERE hasta_id = ?
          AND tarih >= date('now', '-30 day')
        ORDER BY tarih DESC
    """, (hasta_id,))
    basvurular = cur.fetchall()

    toplam_basvuru = len(basvurular)
    acil_sayisi = sum(1 for r in basvurular if (r["aciliyet"] or "") == "ACIL")
    max_risk = max([(r["risk_skor"] or 0) for r in basvurular], default=0)

    puan = 0
    nedenler = []

    # Başvuru sıklığı
    if toplam_basvuru >= 5:
        puan += 25
        nedenler.append(f"Son 30 günde {toplam_basvuru} başvuru")
    elif toplam_basvuru >= 3:
        puan += 15
        nedenler.append(f"Son 30 günde {toplam_basvuru} başvuru")

    # Acil başvuru
    if acil_sayisi >= 3:
        puan += 30
        nedenler.append(f"{acil_sayisi} acil başvuru")
    elif acil_sayisi >= 1:
        puan += 15
        nedenler.append(f"{acil_sayisi} acil başvuru")

    # Geçmiş risk skoru
    if max_risk >= 85:
        puan += 25
        nedenler.append(f"Geçmişte çok yüksek risk skoru ({max_risk})")
    elif max_risk >= 60:
        puan += 15
        nedenler.append(f"Geçmişte yüksek risk skoru ({max_risk})")

    # Şikayet tekrar analizi
    sikayetler_text = " | ".join([normalize_text(r["sikayet"] or "") for r in basvurular])

    kritik_tekrarlar = {
        "gogus agr": "Tekrarlayan göğüs ağrısı",
        "nefes darl": "Tekrarlayan nefes darlığı",
        "uyusma": "Tekrarlayan uyuşma",
        "konusma bozuk": "Tekrarlayan konuşma bozukluğu",
        "yuz kaymasi": "Tekrarlayan yüz kayması",
        "ates": "Tekrarlayan ateş",
        "bayil": "Tekrarlayan bayılma",
    }

    for anahtar, mesaj in kritik_tekrarlar.items():
        if sikayetler_text.count(anahtar) >= 2:
            puan += 20
            nedenler.append(mesaj)

    # Yaş etkisi
    if yas is not None:
        if yas >= 75:
            puan += 20
            nedenler.append("İleri yaş (75+)")
        elif yas >= 65:
            puan += 10
            nedenler.append("Yaş 65+")

    # Kronik hastalık analizi
    kronik_text = " ".join([normalize_text(r["kronik_hastalik"] or "") for r in basvurular])

    if "kalp" in kronik_text:
        puan += 15
        nedenler.append("Kardiyak kronik hastalık öyküsü")
    if "diyabet" in kronik_text:
        puan += 10
        nedenler.append("Diyabet öyküsü")
    if "hipertansiyon" in kronik_text:
        puan += 10
        nedenler.append("Hipertansiyon öyküsü")
    if "koah" in kronik_text or "astim" in kronik_text or "astım" in kronik_text:
        puan += 12
        nedenler.append("Kronik solunum hastalığı")

    # Nihai seviye
    if puan >= 80:
        seviye = "KRITIK"
        mesaj = "🚨 Bu hasta yüksek riskli hasta"
    elif puan >= 55:
        seviye = "YUKSEK"
        mesaj = "⚠ Bu hasta yakın takip gerektiriyor"
    elif puan >= 30:
        seviye = "ORTA"
        mesaj = "🟡 Bu hasta orta risk grubunda"
    else:
        seviye = "DUSUK"
        mesaj = "🟢 Bu hasta düşük risk grubunda"

    conn.close()

    return {
        "hasta_id": hasta["id"],
        "ad": hasta["ad"],
        "soyad": hasta["soyad"],
        "tc": hasta["tc"],
        "puan": puan,
        "seviye": seviye,
        "mesaj": mesaj,
        "nedenler": nedenler,
        "toplam_basvuru": toplam_basvuru,
        "acil_sayisi": acil_sayisi,
        "max_risk": max_risk
    } 

def en_yakin_bos_slot(cur, doktor_id: int, tarih: str, aciliyet: str = "NORMAL"):
    # ACİL: en erken slotlar
    slots_acil = ["09:00","09:30","10:00","10:30","11:00","11:30"]
    # ÖNCELİKLİ: erken + orta
    slots_oncelikli = ["10:00","10:30","11:00","11:30","13:00","13:30","14:00"]
    # NORMAL: tüm gün
    slots_normal = ["09:00","09:30","10:00","10:30","11:00","11:30",
                    "13:00","13:30","14:00","14:30","15:00","15:30","16:00","16:30"]

    if aciliyet == "ACIL":
        saatler = slots_acil + [s for s in slots_normal if s not in slots_acil]
    elif aciliyet == "ONCELIKLI":
        saatler = slots_oncelikli + [s for s in slots_normal if s not in slots_oncelikli]
    else:
        saatler = slots_normal

    for s in saatler:
        cur.execute("""
            SELECT 1 FROM randevular
            WHERE doktor_id = ? AND tarih = ? AND saat = ?
            LIMIT 1
        """, (doktor_id, tarih, s))
        if not cur.fetchone():
            return s
    return None 

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect("/?hata=Önce giriş yapmalısın.")
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect("/?hata=Önce giriş yapmalısın.")
        if session.get("yetki") != "admin":
            return "Yetkisiz erişim", 403
        return f(*args, **kwargs)
    return decorated 

# ---------------------------
# Routes
# ---------------------------

@app.route("/logout")
def logout():
    uid = session.get("user_id")
    uname = session.get("kullanici_adi")
    yetki = session.get("yetki")

    if uid:
        audit_log(
            action="LOGOUT",
            entity="kullanici",
            entity_id=uid,
            detail=f"Çıkış: {uname} yetki={yetki}"
        )

    session.clear()
    return redirect("/?hata=Çikiş yapildi.") 

@app.route("/routes")
def routes():
    return "<pre>" + str(app.url_map) + "</pre>"


@app.route("/", methods=["GET", "POST"])
def login():
    hata = request.args.get("hata")

    if request.method == "POST":
        kullanici_adi = request.form.get("kullanici_adi", "").strip()
        sifre = request.form.get("sifre", "")

        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM kullanicilar WHERE kullanici_adi = ?", (kullanici_adi,))
        user = cur.fetchone()
        conn.close()

        # ✅ Başarılı giriş
        if user and check_password_hash(user["sifre"], sifre):
            session["user_id"] = user["id"]
            session["kullanici_adi"] = user["kullanici_adi"]
            session["yetki"] = user["yetki"]

            audit_log(
                action="LOGIN",
                entity="kullanici",
                entity_id=user["id"],
                detail=f"Başarılı giriş: {user['kullanici_adi']} yetki={user['yetki']}"
            )
            return redirect("/panel")

        # ❌ Başarısız giriş
        audit_log(
            action="LOGIN_FAIL",
            entity="kullanici",
            entity_id=None,
            detail=f"Başarısız giriş denemesi: {kullanici_adi}"
        )
        return render_template("login.html", hata="Hatalı giriş")

    # ✅ GET isteği
    return render_template("login.html", hata=hata)  


@app.route("/panel")
@login_required
def panel():
    
    hasta_ara = request.args.get("hasta_ara", "")
    tc_ara = request.args.get("tc_ara", "")
    msg = request.args.get("msg")
    hata = request.args.get("hata")
    risk_filtre = request.args.get("risk_filtre", "") 

    bugun = date.today().strftime("%Y-%m-%d")
    secili_tarih = request.args.get("tarih") or bugun 
    
    conn = get_conn()
    cur = conn.cursor() 

    query = "SELECT * FROM hastalar WHERE 1=1"
    params = []

    if hasta_ara:
       query += " AND (ad LIKE ? OR soyad LIKE ?)"
       params.append(f"%{hasta_ara}%")
       params.append(f"%{hasta_ara}%")

    if tc_ara:
       query += " AND tc LIKE ?"
       params.append(f"%{tc_ara}%")
 
    cur.execute(query, params)
    hastalar = cur.fetchall()

    cur.execute("""
SELECT
    r.id as rid,
    r.hasta_id as hasta_id,
    r.sikayet as sikayet,
    h.ad as had, h.soyad as hsoyad,
    d.ad as dad, d.soyad as dsoyad, d.brans as dbrans,
    r.tarih, r.saat,
    r.aciliyet,
    r.risk_skor,
    r.klinik_not
FROM randevular r 
LEFT JOIN hastalar h ON r.hasta_id = h.id
LEFT JOIN doktorlar d ON r.doktor_id = d.id
WHERE r.tarih = ?
ORDER BY
  CASE r.aciliyet
    WHEN 'ACIL' THEN 1
    WHEN 'ONCELIKLI' THEN 2
    ELSE 3
  END,
  r.tarih DESC,
  r.saat DESC
""", (secili_tarih,)) 
    
    randevular = cur.fetchall()
    randevular = [dict(r) for r in randevular]

    for r in randevular:
        r["uyarilar"] = erken_uyari_belirle(
        r["sikayet"],
        r["risk_skor"],
        r["aciliyet"]
    )
        r["tani_tahmini"] = tani_tahmini(r["sikayet"])
        r["alarm_kategorileri"] = alarm_kategorisi(r["sikayet"]) 
        r["kombinasyon_uyarilari"] = semptom_kombinasyon_analizi(r["sikayet"]) 
    
    kritik_randevular = [] 
    kalp_riski_sayisi = 0
    inme_riski_sayisi = 0
    solunum_riski_sayisi = 0

    for r in randevular:
        if r["uyarilar"] or r["kombinasyon_uyarilari"]:
            kritik_randevular.append(r)

        if any("Kalp Krizi" in u for u in r["uyarilar"]):
            kalp_riski_sayisi += 1

        if any("İnme" in u for u in r["uyarilar"]):
            inme_riski_sayisi += 1
 
        if any("Solunum" in u for u in r["uyarilar"]):
            solunum_riski_sayisi += 1

    toplam_kritik_sayi = len(kritik_randevular) 

    cur.execute("SELECT * FROM randevular WHERE tarih = ?", (secili_tarih,))
    bugunku_randevular = cur.fetchall()

    cur.execute("""
    SELECT saat, COUNT(*) as adet
    FROM randevular
    WHERE tarih = ?
    GROUP BY saat
    ORDER BY adet DESC
    LIMIT 1
    """, (secili_tarih,))
    en_yogun = cur.fetchone()
    
        # Seçili gün için saat bazlı randevu dağılımı
    cur.execute("""
        SELECT saat, COUNT(*) as adet
        FROM randevular
        WHERE tarih = ?
        GROUP BY saat
        ORDER BY saat ASC
    """, (secili_tarih,))
    saat_dagilimi_rows = cur.fetchall()

    saat_etiketler = [r["saat"] for r in saat_dagilimi_rows]
    saat_degerler = [r["adet"] for r in saat_dagilimi_rows]

    # Seçili gün için branş bazlı dağılım
    cur.execute("""
        SELECT d.brans as brans, COUNT(*) as adet
        FROM randevular r
        LEFT JOIN doktorlar d ON r.doktor_id = d.id
        WHERE r.tarih = ?
        GROUP BY d.brans
        ORDER BY adet DESC
    """, (secili_tarih,))
    brans_rows = cur.fetchall()

    brans_etiketler = [r["brans"] if r["brans"] else "Bilinmiyor" for r in brans_rows]
    brans_degerler = [r["adet"] for r in brans_rows]

    # Seçili gün için aciliyet dağılımı
    cur.execute("""
        SELECT COALESCE(aciliyet, 'NORMAL') as aciliyet, COUNT(*) as adet
        FROM randevular
        WHERE tarih = ?
        GROUP BY COALESCE(aciliyet, 'NORMAL')
        ORDER BY adet DESC
    """, (secili_tarih,))
    aciliyet_rows = cur.fetchall()

    aciliyet_etiketler = [r["aciliyet"] for r in aciliyet_rows]
    aciliyet_degerler = [r["adet"] for r in aciliyet_rows] 

# Riskli hastalar paneli 
    cur.execute("""
    SELECT
        h.id as hasta_id,
        h.ad,
        h.soyad,
        h.tc,
        COALESCE(MAX(CASE
            WHEN r.tarih >= date('now', '-30 day') THEN r.risk_skor
            ELSE 0
        END), 0) as max_risk,
        COALESCE(SUM(CASE
            WHEN r.tarih >= date('now', '-30 day') AND r.aciliyet = 'ACIL' THEN 1
            ELSE 0
        END), 0) as acil_sayisi,
        COALESCE(SUM(CASE
            WHEN r.tarih >= date('now', '-30 day') THEN 1
            ELSE 0
        END), 0) as toplam_basvuru,
        COALESCE(SUM(CASE
            WHEN r.tarih >= date('now', '-30 day') AND r.sikayet LIKE '%göğüs%'
            THEN 1 ELSE 0
        END), 0) as gogus_sayisi
    FROM hastalar h
    LEFT JOIN randevular r ON h.id = r.hasta_id
    GROUP BY h.id, h.ad, h.soyad, h.tc
    ORDER BY max_risk DESC, acil_sayisi DESC, toplam_basvuru DESC
    LIMIT 10
    """)
    riskli_hastalar_raw = cur.fetchall()

    riskli_hastalar = []
    for r in riskli_hastalar_raw:
        puan = (r["max_risk"] or 0) + (r["acil_sayisi"] or 0) * 10 + (r["toplam_basvuru"] or 0) * 2

        if puan >= 120:
            seviye = "KRITIK"
            mesaj = "🚨 Bu hasta yüksek riskli hasta"
        elif puan >= 90:
            seviye = "YUKSEK"
            mesaj = "⚠ Bu hasta yakın takip edilmeli"
        elif puan >= 50:
            seviye = "ORTA"
            mesaj = "🟡 Bu hasta izlem gerektiriyor"
        else:
            seviye = "DUSUK"
            mesaj = "🟢 Bu hasta düşük riskli"

        riskli_hastalar.append({
            "hasta_id": r["hasta_id"],
            "ad": r["ad"],
            "soyad": r["soyad"],
            "tc": r["tc"],
            "max_risk": r["max_risk"] or 0,
            "acil_sayisi": r["acil_sayisi"] or 0,
            "toplam_basvuru": r["toplam_basvuru"] or 0,
            "puan": puan,
            "seviye": seviye,
            "mesaj": mesaj
        })

    if risk_filtre in ["KRITIK", "YUKSEK", "ORTA", "DUSUK"]:
        riskli_hastalar = [h for h in riskli_hastalar if h["seviye"] == risk_filtre]

    risk_dusuk = 0
    risk_orta = 0
    risk_yuksek = 0
    risk_kritik = 0

    for h in riskli_hastalar:
        if h["seviye"] == "KRITIK":
            risk_kritik += 1
        elif h["seviye"] == "YUKSEK":
            risk_yuksek += 1
        elif h["seviye"] == "ORTA":
            risk_orta += 1
        else:
            risk_dusuk += 1

    risk_grafik_etiketler = ["Düşük", "Orta", "Yüksek", "Kritik"]
    risk_grafik_degerler = [risk_dusuk, risk_orta, risk_yuksek, risk_kritik]

    toplam_hasta = len(hastalar)
    toplam_randevu = len(randevular)
    bugunku_randevu = len(bugunku_randevular)

    cur.execute("SELECT COUNT(*) as sayi FROM doktorlar")
    toplam_doktor = cur.fetchone()["sayi"]

    # Son 24 saatte acil / öncelikli başvuru
    cur.execute("""
        SELECT COUNT(*) as sayi
        FROM randevular
        WHERE tarih >= date('now', '-1 day')
          AND COALESCE(aciliyet, 'NORMAL') IN ('ACIL', 'ONCELIKLI')
    """)
    acil_basvuru_24s = cur.fetchone()["sayi"]

    # Ortalama risk skoru
    cur.execute("""
        SELECT ROUND(AVG(risk_skor), 1) as ortalama
        FROM randevular
        WHERE tarih = ?
          AND risk_skor IS NOT NULL
    """, (secili_tarih,))
    sonuc = cur.fetchone()
    ortalama_risk_skoru = sonuc["ortalama"] if sonuc and sonuc["ortalama"] is not None else 0

    # Panelde göstermek için en riskli 5 hasta/randevu
    cur.execute("""
        SELECT
            r.id as rid,
            r.hasta_id as hasta_id,
            h.ad as ad,
            h.soyad as soyad,
            r.tarih,
            r.saat,
            r.sikayet,
            r.risk_skor,
            r.aciliyet,
            r.kkds_kirmizi_bayrak,
            d.brans as brans
        FROM randevular r
        LEFT JOIN hastalar h ON r.hasta_id = h.id
        LEFT JOIN doktorlar d ON r.doktor_id = d.id
        WHERE r.risk_skor IS NOT NULL
        ORDER BY r.risk_skor DESC, r.tarih DESC, r.saat DESC
        LIMIT 5
    """)
    en_riskli_hastalar = cur.fetchall() 

    conn.close()

    return render_template(
        "panel.html",
        hastalar=hastalar,
        randevular=randevular,
        hasta_ara=hasta_ara,
        tc_ara=tc_ara,
        bugunku_randevular=bugunku_randevular,
        en_yogun=en_yogun,
        msg=msg,
        hata=hata,
        secili_tarih=secili_tarih,
        saat_etiketler=saat_etiketler,
        saat_degerler=saat_degerler,
        brans_etiketler=brans_etiketler,
        brans_degerler=brans_degerler,
        aciliyet_etiketler=aciliyet_etiketler,
        aciliyet_degerler=aciliyet_degerler,
        riskli_hastalar=riskli_hastalar,
        risk_grafik_etiketler=risk_grafik_etiketler,
        risk_grafik_degerler=risk_grafik_degerler,
        risk_filtre=risk_filtre,
        kritik_randevular=kritik_randevular,
        toplam_kritik_sayi=toplam_kritik_sayi,
        kalp_riski_sayisi=kalp_riski_sayisi,
        inme_riski_sayisi=inme_riski_sayisi,
        solunum_riski_sayisi=solunum_riski_sayisi,
        toplam_hasta=toplam_hasta,
        toplam_doktor=toplam_doktor,
        toplam_randevu=toplam_randevu,
        bugunku_randevu=bugunku_randevu,
        acil_basvuru_24s=acil_basvuru_24s,
        ortalama_risk_skoru=ortalama_risk_skoru,
        en_riskli_hastalar=en_riskli_hastalar,
    ) 


@app.route("/hasta_ekle", methods=["GET", "POST"])
@login_required
def hasta_ekle():
    if request.method == "POST":
        ad = request.form["ad"]
        soyad = request.form["soyad"]
        tc = request.form["tc"]
        dogum_yili = request.form.get("dogum_yili") or None
        cinsiyet = (request.form.get("cinsiyet") or "").strip() or None

        conn = get_conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO hastalar (ad, soyad, tc, dogum_yili, cinsiyet) VALUES (?, ?, ?, ?, ?)", (ad, soyad, tc, int(dogum_yili) if dogum_yili else None, cinsiyet))
        conn.commit()
        conn.close()
        return redirect("/panel")

    return render_template("hasta_ekle.html")


@app.route("/hasta_sil/<int:id>")
@login_required
def hasta_sil(id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM hastalar WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return redirect("/panel")


@app.route("/hasta_guncelle/<int:id>", methods=["GET", "POST"])
@login_required
def hasta_guncelle(id):
    conn = get_conn() 
    cur = conn.cursor()

    if request.method == "POST":
        ad = request.form["ad"]
        soyad = request.form["soyad"]
        tc = request.form["tc"]
        dogum_yili = request.form.get("dogum_yili") or None
        cinsiyet = (request.form.get("cinsiyet") or "").strip() or None

        cur.execute("""
        UPDATE hastalar
        SET ad = ?, soyad = ?, tc = ?, dogum_yili = ?, cinsiyet = ?
        WHERE id = ?
        """, (ad, soyad, tc, 
             int(dogum_yili) if dogum_yili else None,
             cinsiyet,
             id))

        conn.commit()
        conn.close()
        return redirect("/panel")

    cur.execute("SELECT * FROM hastalar WHERE id = ?", (id,))
    hasta = cur.fetchone()
    conn.close()
    return render_template("hasta_guncelle.html", hasta=hasta)

@app.route("/hasta/<int:id>")
@login_required
def hasta_detay(id):
    conn = get_conn()
    cur = conn.cursor()

    # Hasta bilgisi
    cur.execute("SELECT * FROM hastalar WHERE id = ?", (id,))
    hasta = cur.fetchone()

    if not hasta:
        conn.close()
        return redirect("/panel")

    # Hastanın randevuları
    cur.execute("""
    SELECT r.id as rid,
           r.tarih,
           r.saat,
           r.sikayet,
           r.aciliyet,
           r.risk_skor,
           r.klinik_not,
           r.kkds_kirmizi_bayrak,
           d.ad as dad,
           d.soyad as dsoyad,
           d.brans as dbrans
    FROM randevular r
    LEFT JOIN doktorlar d ON r.doktor_id = d.id
    WHERE r.hasta_id = ?
    ORDER BY r.tarih DESC, r.saat DESC
""", (id,)) 
    randevular = cur.fetchall()

     # Son 30 gündeki başvuru sayısı
    cur.execute("""
        SELECT COUNT(*) as adet
        FROM randevular
        WHERE hasta_id = ?
          AND tarih >= date('now', '-30 day')
    """, (id,))
    son30 = cur.fetchone()["adet"]

    # Aynı şikayet benzerliği için son 5 şikayet
    cur.execute("""
        SELECT sikayet, tarih, aciliyet, risk_skor
        FROM randevular
        WHERE hasta_id = ?
        ORDER BY tarih DESC, saat DESC
        LIMIT 5
    """, (id,))
    son_basvurular = cur.fetchall() 

    hasta_uyarilari = []

    if son30 >= 3:
        hasta_uyarilari.append(f"Bu hasta son 30 günde {son30} kez başvurdu. Sık başvuran hasta olabilir.")

    kritik_kelimeler = {
        "gogus agrisi": "Tekrarlayan göğüs ağrısı başvuruları mevcut.",
        "nefes darligi": "Tekrarlayan nefes darlığı başvuruları mevcut.",
        "uyusma": "Tekrarlayan uyuşma şikayeti mevcut.",
        "konusma bozuk": "Tekrarlayan konuşma bozukluğu şikayeti mevcut.",
        "yuz kaymasi": "Tekrarlayan yüz kayması şikayeti mevcut.",
        "ates": "Tekrarlayan ateş başvuruları mevcut."
    }

    son_sikayetler_text = " | ".join([normalize_text(r["sikayet"] or "") for r in son_basvurular])

    for anahtar, mesaj in kritik_kelimeler.items():
        if son_sikayetler_text.count(anahtar) >= 2:
            hasta_uyarilari.append(mesaj) 

   
    hasta_risk_ozeti = hasta_risk_tahmin_motoru(id)

    conn.close()

    return render_template("hasta_detay.html", hasta=hasta, randevular=randevular, son30=son30, son_basvurular=son_basvurular, hasta_uyarilari=hasta_uyarilari, hasta_risk_ozeti=hasta_risk_ozeti) 

@app.route("/randevu_ekle", methods=["GET", "POST"])
@login_required
def randevu_ekle():
    conn = get_conn()
    cur = conn.cursor()

    # Doktor listesi (GET ve POST’ta lazım)
    cur.execute("SELECT id, ad, soyad, brans FROM doktorlar ORDER BY brans, ad")
    doktorlar = cur.fetchall()

    # Varsayılanlar
    ai_brans = None
    ai_guven = None
    aciliyet = None
    acil_skor = None
    acil_mesaj = None

    onerilen_doktor_id = None
    onerilen_doktor = None
    onerilen_saat = None
    ai_top2 = []
    ai_uyari = None
    ai_brans_uyusmazlik = None 
    triage_sonuc = None 

    if request.method == "POST":
        action = request.form.get("action", "save")  # ai / ai_save / save
        hasta_id = request.form.get("hasta_id")
        doktor_id = request.form.get("doktor_id")
        tarih = request.form.get("tarih")
        saat = request.form.get("saat")
        
        sikayet = (request.form.get("sikayet") or "").strip()

        ates = request.form.get("ates")
        nabiz = request.form.get("nabiz")
        sistolik = request.form.get("sistolik")
        diyastolik = request.form.get("diyastolik")
        spo2 = request.form.get("spo2")
        kronik_hastalik = request.form.get("kronik_hastalik")
        alerji = request.form.get("alerji")

        ates = float(ates) if ates else None
        nabiz = int(nabiz) if nabiz else None
        sistolik = int(sistolik) if sistolik else None
        diyastolik = int(diyastolik) if diyastolik else None
        spo2 = int(spo2) if spo2 else None

        # Boş şikayet kontrolü 
        if not sikayet:
            conn.close()
            return render_template("randevu_ekle.html", doktorlar=doktorlar, hata="Şikayet alanı boş olamaz.", triage_sonuc=None)

        # AI branş ve aciliyet
        (ai_brans, ai_guven), ai_top2 = brans_belirle(sikayet)

        if ai_guven < 55:
            ai_uyari = "AI emin değil. Genel Muayene / Dahiliye ile başlamak daha doğru olabilir."

        aciliyet, acil_skor, acil_mesaj = aciliyet_belirle(sikayet) 

        kkds = klinik_karar_destek(
        sikayet=sikayet,
        ates=ates,
        nabiz=nabiz,
        sistolik=sistolik,
        diyastolik=diyastolik,
        spo2=spo2,
        kronik_hastalik=kronik_hastalik 
        ) 

        if kkds["kirmizi_bayrak"] != "Yok":
            aciliyet = "ACIL"
            acil_skor = max(acil_skor, 99) if acil_skor is not None else 99
            acil_mesaj = f"🔴 KKDS kritik bulgu saptadı: {kkds['kirmizi_bayrak']}. Acil değerlendirme önerilir."
        

        s_norm = normalize_text(sikayet)

        if ("gogus agrisi" in s_norm or "nefes darligi" in s_norm) and kkds["kirmizi_bayrak"] != "Yok":
            ai_brans = "Kardiyoloji"

        if ("konusma bozuk" in s_norm or "yuz kaymasi" in s_norm or "felc" in s_norm):
            ai_brans = "Nöroloji"

        # AI branşa göre en az yoğun doktor (o gün için) + fallback
        row = None
        fallback_used = False

        if tarih and ai_brans:
            # 1) Branşta doktor var mı?
            cur.execute("""
                SELECT COUNT(*) AS c
                FROM doktorlar
                WHERE LOWER(TRIM(brans)) = LOWER(TRIM(?))
            """, (ai_brans,))
            brans_doktor_sayisi = cur.fetchone()["c"]

            if brans_doktor_sayisi > 0:
                # 2) Branşta en az yoğun doktor
                cur.execute("""
                    SELECT d.id, COUNT(r.id) AS adet
                    FROM doktorlar d
                    LEFT JOIN randevular r
                        ON d.id = r.doktor_id AND r.tarih = ?
                    WHERE LOWER(TRIM(d.brans)) = LOWER(TRIM(?))
                    GROUP BY d.id
                    ORDER BY adet ASC
                    LIMIT 1
                """, (tarih, ai_brans))
                row = cur.fetchone()
            else:
                fallback_used = True

        # 3) Branş yoksa veya row bulunamadıysa -> tüm doktorlardan en az yoğun
        if tarih and not row:
            fallback_used = True
            cur.execute("""
                SELECT d.id, COUNT(r.id) AS adet
                FROM doktorlar d
                LEFT JOIN randevular r
                    ON d.id = r.doktor_id AND r.tarih = ?
                GROUP BY d.id
                ORDER BY adet ASC
                LIMIT 1
            """, (tarih,))
            row = cur.fetchone()

        if row:
            onerilen_doktor_id = row["id"]
            cur.execute("SELECT id, ad, soyad, brans FROM doktorlar WHERE id = ?", (onerilen_doktor_id,))
            onerilen_doktor = cur.fetchone()

            # ✅ fallback uyarısı (mevcut uyarıyı silme, üzerine ekle)
            if fallback_used:
                fallback_msg = f"⚠ {ai_brans} branşında doktor bulunamadı. En az yoğun doktora yönlendirildi."
                ai_uyari = (ai_uyari + " " + fallback_msg) if ai_uyari else fallback_msg

            # ACİL ise aynı doktora en yakın boş saati bul
            if aciliyet == "ACIL":
                onerilen_saat = en_yakin_bos_slot(cur, int(onerilen_doktor_id), tarih, aciliyet)

        # ACİL değilse de saat öner (ilk boş slot)
        if onerilen_doktor_id and tarih and not onerilen_saat:
            onerilen_saat = en_yakin_bos_slot(cur, int(onerilen_doktor_id), tarih, aciliyet)

        # AI branşa göre doktorları üste taşı
        if ai_brans:
            doktorlar = sorted(doktorlar, key=lambda d: 0 if d["brans"] == ai_brans else 1)

                # 1) SADECE AI ÖNER (kayıt yok)
        if action == "ai":
            conn.close()
            return render_template(
                "randevu_ekle.html",
                doktorlar=doktorlar,
                ai_brans=ai_brans,
                ai_guven=ai_guven,
                aciliyet=aciliyet,
                acil_skor=acil_skor,
                acil_mesaj=acil_mesaj,
                onerilen_doktor_id=onerilen_doktor_id,
                onerilen_doktor=onerilen_doktor,
                onerilen_saat=onerilen_saat,
                ai_top2=ai_top2,
                ai_uyari=ai_uyari,
                ai_brans_uyusmazlik=ai_brans_uyusmazlik,
                kkds=kkds,
                triage_sonuc=triage_sonuc
            )

        # 2) ✅ AI ile Kaydet (tek tık)
        if action == "ai_save":
            if not hasta_id or not tarih:
                conn.close()
                return render_template(
                    "randevu_ekle.html",
                    doktorlar=doktorlar,
                    hata="Hasta ve tarih seçmelisiniz (AI ile Kaydet).",
                    ai_brans=ai_brans,
                    ai_guven=ai_guven,
                    aciliyet=aciliyet,
                    acil_skor=acil_skor,
                    acil_mesaj=acil_mesaj,
                    onerilen_doktor_id=onerilen_doktor_id,
                    onerilen_doktor=onerilen_doktor,
                    onerilen_saat=onerilen_saat,
                    ai_top2=ai_top2,
                    ai_uyari=ai_uyari,
                    ai_brans_uyusmazlik=ai_brans_uyusmazlik,
                    kkds=kkds,
                    triage_sonuc=None 
                )

            if not onerilen_doktor_id or not onerilen_saat:
                conn.close()
                return render_template(
                    "randevu_ekle.html",
                    doktorlar=doktorlar,
                    hata="AI doktor veya saat öneremedi.",
                    ai_brans=ai_brans,
                    ai_guven=ai_guven,
                    aciliyet=aciliyet,
                    acil_skor=acil_skor,
                    acil_mesaj=acil_mesaj,
                    onerilen_doktor_id=onerilen_doktor_id,
                    onerilen_doktor=onerilen_doktor,
                    onerilen_saat=onerilen_saat,
                    ai_top2=ai_top2,
                    ai_uyari=ai_uyari,
                    ai_brans_uyusmazlik=ai_brans_uyusmazlik,
                    kkds=kkds,
                    triage_sonuc=None
                )

            cur.execute("SELECT dogum_yili, cinsiyet FROM hastalar WHERE id = ?", (hasta_id,))
            h = cur.fetchone()
            dogum_yili = h["dogum_yili"] if h else None
            cinsiyet = h["cinsiyet"] if h else None
            yas = hesapla_yas(dogum_yili) 

            risk_skor, risk_seviye, klinik_not = klinik_risk_analizi(
                sikayet, dogum_yili, cinsiyet
            )

            triage_sonuc = gercek_triage_motoru(
                sikayet=sikayet,
                yas=yas,
                ates=ates,
                nabiz=nabiz,
                sistolik=sistolik,
                diyastolik=diyastolik,
                spo2=spo2,
                kronik_hastalik=kronik_hastalik
            )

            try:
                cur.execute("""
                    INSERT INTO randevular (
                        hasta_id,
                        doktor_id,
                        tarih,
                        saat,
                        sikayet,
                        aciliyet,
                        risk_skor,
                        klinik_not,
                        kkds_risk,
                        kkds_oneri,
                        kkds_tetkik,
                        kkds_kirmizi_bayrak
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    hasta_id,
                    int(onerilen_doktor_id),
                    tarih,
                    onerilen_saat,
                    sikayet,
                    aciliyet,
                    risk_skor,
                    klinik_not,
                    kkds["risk"],
                    kkds["oneri"],
                    kkds["tetkik"],
                    kkds["kirmizi_bayrak"]
                ))
                conn.commit()

                rid = cur.lastrowid
                audit_log(
                    action="CREATE",
                    entity="randevu",
                    entity_id=rid,
                    detail=f"AI_SAVE hasta_id={hasta_id} doktor_id={int(onerilen_doktor_id)} tarih={tarih} saat={onerilen_saat} aciliyet={aciliyet}"
                )

                conn.close()
                return redirect("/panel")

            except sqlite3.IntegrityError:
                conn.close()
                return render_template(
                    "randevu_ekle.html",
                    doktorlar=doktorlar,
                    hata="AI’nin seçtiği slot dolu.",
                    ai_brans=ai_brans,
                    ai_guven=ai_guven,
                    aciliyet=aciliyet,
                    acil_skor=acil_skor,
                    acil_mesaj=acil_mesaj,
                    onerilen_doktor_id=onerilen_doktor_id,
                    onerilen_doktor=onerilen_doktor,
                    onerilen_saat=onerilen_saat,
                    ai_top2=ai_top2,
                    ai_uyari=ai_uyari,
                    ai_brans_uyusmazlik=ai_brans_uyusmazlik,
                    kkds=kkds,
                    triage_sonuc=triage_sonuc
                ) 
        # 3) KAYDET (manuel) - sadece action save iken
        if action == "save":
            if not doktor_id:
                conn.close()
                return render_template(
                    "randevu_ekle.html",
                    doktorlar=doktorlar,
                    hata="Doktor seçmelisiniz.",
                    ai_brans=ai_brans,
                    ai_guven=ai_guven,
                    aciliyet=aciliyet,
                    acil_skor=acil_skor,
                    acil_mesaj=acil_mesaj,
                    onerilen_doktor_id=onerilen_doktor_id,
                    onerilen_doktor=onerilen_doktor,
                    onerilen_saat=onerilen_saat,
                    ai_top2=ai_top2,
                    ai_uyari=ai_uyari,
                    ai_brans_uyusmazlik=ai_brans_uyusmazlik,
                    triage_sonuc=None
                )

            cur.execute("SELECT brans FROM doktorlar WHERE id = ?", (doktor_id,))
            secilen_brans = cur.fetchone()

            if secilen_brans and (secilen_brans["brans"] or "").strip().lower() != (ai_brans or "").strip().lower():
                ai_brans_uyusmazlik = (
                    f"⚠ Seçilen doktorun branşı ({secilen_brans['brans']}) "
                    f"AI önerisi ({ai_brans}) ile uyuşmuyor."
                )
                conn.close()
                return render_template(
                    "randevu_ekle.html",
                    doktorlar=doktorlar,
                    hata="Branş uyuşmazlığı var. Lütfen AI önerisine uygun doktor seçin.",
                    ai_brans=ai_brans,
                    ai_guven=ai_guven,
                    aciliyet=aciliyet,
                    acil_skor=acil_skor,
                    acil_mesaj=acil_mesaj,
                    onerilen_doktor_id=onerilen_doktor_id,
                    onerilen_doktor=onerilen_doktor,
                    onerilen_saat=onerilen_saat,
                    ai_top2=ai_top2,
                    ai_uyari=ai_uyari,
                    ai_brans_uyusmazlik=ai_brans_uyusmazlik,
                    triage_sonuc=None 
                )

            doktor_id_int = int(doktor_id)
            
            # 🔹 Hastanın demografisini çek
            cur.execute("SELECT dogum_yili, cinsiyet FROM hastalar WHERE id = ?", (hasta_id,))
            h = cur.fetchone()
            dogum_yili = h["dogum_yili"] if h else None
            cinsiyet = h["cinsiyet"] if h else None
            yas = hesapla_yas(dogum_yili) 

            # 🔹 Klinik risk analizi
            risk_skor, risk_seviye, klinik_not = klinik_risk_analizi(
                sikayet, dogum_yili, cinsiyet
            )

            triage_sonuc = gercek_triage_motoru(
                sikayet=sikayet,
                yas=yas,
                ates=ates,
                nabiz=nabiz,
                sistolik=sistolik,
                diyastolik=diyastolik,
                spo2=spo2,
                kronik_hastalik=kronik_hastalik
            ) 
      

            try:
                cur.execute("""
                    INSERT INTO randevular (
                        hasta_id, 
                        doktor_id, 
                        tarih, saat, 
                        sikayet, 
                        aciliyet, 
                        risk_skor, 
                        klinik_not, 
                        kkds_risk, 
                        kkds_oneri, 
                        kkds_tetkik, 
                        kkds_kirmizi_bayrak
                        )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
                """, (
                    hasta_id, 
                    doktor_id_int, 
                    tarih, saat, 
                    sikayet, 
                    aciliyet, 
                    risk_skor, 
                    klinik_not, 
                    kkds["risk"], 
                    kkds["oneri"], 
                    kkds["tetkik"], 
                    kkds["kirmizi_bayrak"] 
                )) 
                conn.commit()
                
                rid = cur.lastrowid
                audit_log(
                    action="KLINIK_ANALIZ", 
                    entity="randevu",
                    entity_id=rid,
                    detail=f"risk_skor={risk_skor} seviye={risk_seviye}" 
    )
 
                conn.close()
                return redirect("/panel")
            except sqlite3.IntegrityError:
                conn.close()
                return render_template(
                    "randevu_ekle.html",
                    doktorlar=doktorlar,
                    hata="❌ Bu doktor için seçtiğiniz tarih/saat dolu. (DB engelledi)",
                    ai_brans=ai_brans,
                    ai_guven=ai_guven,
                    aciliyet=aciliyet,
                    acil_skor=acil_skor,
                    acil_mesaj=acil_mesaj,
                    onerilen_doktor_id=onerilen_doktor_id,
                    onerilen_doktor=onerilen_doktor,
                    onerilen_saat=onerilen_saat,
                    ai_top2=ai_top2,
                    ai_uyari=ai_uyari,
                    ai_brans_uyusmazlik=ai_brans_uyusmazlik,
                    triage_sonuc=triage_sonuc
                )
    varsayilan_tarih = request.args.get("tarih") or date.today().strftime("%Y-%m-%d") 
    varsayilan_saat = request.args.get("saat") or "" 
    varsayilan_doktor_id = request.args.get("doktor_id") or "" 
    conn.close()
    return render_template(
        "randevu_ekle.html",
        doktorlar=doktorlar,
        ai_brans=None,
        ai_guven=None,
        ai_top2=[],
        ai_uyari=None,
        aciliyet=None,
        acil_skor=None,
        acil_mesaj=None,
        onerilen_doktor_id=None,
        onerilen_doktor=None,
        onerilen_saat=None,
        ai_brans_uyusmazlik=None,
        varsayilan_tarih=varsayilan_tarih,
        varsayilan_saat=varsayilan_saat,
        varsayilan_doktor_id=varsayilan_doktor_id,
        triage_sonuc=None
    )    
def migrate_add_sikayet():
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("ALTER TABLE randevular ADD COLUMN sikayet TEXT")
        conn.commit()
    except:
        pass
    conn.close()

def migrate_add_hasta_demografi():
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("ALTER TABLE hastalar ADD COLUMN dogum_yili INTEGER")
        conn.commit()
    except:
        pass
    try:
        cur.execute("ALTER TABLE hastalar ADD COLUMN cinsiyet TEXT")
        conn.commit()
    except:
        pass
    conn.close() 

def migrate_add_aciliyet():
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("ALTER TABLE randevular ADD COLUMN aciliyet TEXT")
        conn.commit()
    except:
        pass
    conn.close()

def migrate_unique_doktor_slot():
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS ux_randevu_doktor_slot
        ON randevular(doktor_id, tarih, saat)
        """)
        conn.commit()
    except:
        pass
    conn.close()

def migrate_add_klinik_fields():
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("ALTER TABLE randevular ADD COLUMN risk_skor INTEGER")
        conn.commit()
    except:
        pass
    try:
        cur.execute("ALTER TABLE randevular ADD COLUMN klinik_not TEXT")
        conn.commit()
    except:
        pass
    conn.close() 

# ---------------------------
# Boot
# ---------------------------

@app.route("/randevu_guncelle/<int:rid>", methods=["GET", "POST"])
@login_required
def randevu_guncelle(rid):
    conn = get_conn()
    cur = conn.cursor()

    # doktor listesi
    cur.execute("SELECT id, ad, soyad, brans FROM doktorlar ORDER BY brans, ad")
    doktorlar = cur.fetchall()

    # mevcut randevu
    cur.execute("""
        SELECT *
        FROM randevular
        WHERE id = ?
    """, (rid,))
    randevu = cur.fetchone()

    if not randevu:
        conn.close()
        return redirect("/panel?hata=Randevu bulunamadı.")

    if request.method == "POST":
        hasta_id = request.form.get("hasta_id")
        doktor_id = request.form.get("doktor_id")
        tarih = request.form.get("tarih")
        saat = request.form.get("saat")
        sikayet = (request.form.get("sikayet") or "").strip()

        if not hasta_id or not doktor_id or not tarih or not saat or not sikayet:
            conn.close()
            return render_template(
                "randevu_guncelle.html",
                randevu=randevu,
                doktorlar=doktorlar,
                hata="Tüm alanları doldurmalısınız."
            )

        # hastanın demografisi
        cur.execute("SELECT dogum_yili, cinsiyet FROM hastalar WHERE id = ?", (hasta_id,))
        h = cur.fetchone()
        dogum_yili = h["dogum_yili"] if h else None
        cinsiyet = h["cinsiyet"] if h else None
        yas = hesapla_yas(dogum_yili) 

        # mevcut analizleri yeniden üret
        aciliyet, acil_skor, acil_mesaj = aciliyet_belirle(sikayet)
        risk_skor, risk_seviye, klinik_not = klinik_risk_analizi(sikayet, dogum_yili, cinsiyet)

        try:
            cur.execute("""
                UPDATE randevular
                SET hasta_id = ?, doktor_id = ?, tarih = ?, saat = ?, sikayet = ?,
                    aciliyet = ?, risk_skor = ?, klinik_not = ?
                WHERE id = ?
            """, (
                int(hasta_id),
                int(doktor_id),
                tarih,
                saat,
                sikayet,
                aciliyet,
                risk_skor,
                klinik_not,
                rid
            ))
            conn.commit()

            audit_log(
                action="UPDATE",
                entity="randevu",
                entity_id=rid,
                detail=f"Randevu güncellendi: doktor_id={doktor_id} tarih={tarih} saat={saat} aciliyet={aciliyet}"
            )

            conn.close()
            return redirect("/panel?msg=Randevu güncellendi.")
        except sqlite3.IntegrityError:
            conn.close()
            return render_template(
                "randevu_guncelle.html",
                randevu=randevu,
                doktorlar=doktorlar,
                hata="Bu doktor için seçilen tarih/saat dolu."
            )

    conn.close()
    return render_template("randevu_guncelle.html", randevu=randevu, doktorlar=doktorlar) 

@app.route("/randevu_sil/<int:rid>", methods=["POST"])
@login_required
def randevu_sil(rid):
    conn = get_conn()
    cur = conn.cursor()

    # var mı kontrol
    cur.execute("SELECT id FROM randevular WHERE id = ?", (rid,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return redirect("/panel?hata=Randevu bulunamadı.")

    cur.execute("DELETE FROM randevular WHERE id = ?", (rid,))
    conn.commit()

    audit_log(
        action="DELETE",
        entity="randevu",
        entity_id=rid,
        detail="Panel üzerinden randevu silindi"
    )

    conn.close()
    return redirect("/panel?msg=Randevu silindi.") 

@app.route("/doktorlar")
@login_required
def doktorlar_sayfa():
    msg = request.args.get("msg")
    hata = request.args.get("hata")

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM doktorlar ORDER BY brans, ad")
    doktorlar = cur.fetchall()
    conn.close()

    return render_template("doktorlar.html", doktorlar=doktorlar, msg=msg, hata=hata)

@app.route("/doktor_programi", methods=["GET"])
@login_required
def doktor_programi():
    conn = get_conn()
    cur = conn.cursor()

    secili_doktor_id = request.args.get("doktor_id")
    secili_tarih = request.args.get("tarih") or date.today().strftime("%Y-%m-%d")

    cur.execute("SELECT id, ad, soyad, brans FROM doktorlar ORDER BY brans, ad")
    doktorlar = cur.fetchall()

    secili_doktor = None
    randevular = []
    tum_slotlar = ["09:00","09:30","10:00","10:30","11:00","11:30",
                   "13:00","13:30","14:00","14:30","15:00","15:30","16:00","16:30"]

    dolu_slotlar = []
    slot_durumu = []

    if secili_doktor_id:
        cur.execute("SELECT id, ad, soyad, brans FROM doktorlar WHERE id = ?", (secili_doktor_id,))
        secili_doktor = cur.fetchone()

        cur.execute("""
            SELECT r.id as rid,
                   r.hasta_id as hasta_id,
                   r.tarih,
                   r.saat,
                   r.sikayet,
                   r.aciliyet,
                   h.ad as had,
                   h.soyad as hsoyad
            FROM randevular r
            LEFT JOIN hastalar h ON r.hasta_id = h.id
            WHERE r.doktor_id = ? AND r.tarih = ?
            ORDER BY r.saat ASC
        """, (secili_doktor_id, secili_tarih))
        randevular = cur.fetchall()

        dolu_slotlar = [r["saat"] for r in randevular]

    for saat in tum_slotlar:
        kayit = next((r for r in randevular if r["saat"] == saat), None)
        slot_durumu.append({
            "saat": saat,
            "dolu": kayit is not None,
            "kayit": kayit
        })

    conn.close()
    return render_template(
        "doktor_programi.html",
        doktorlar=doktorlar,
        secili_doktor_id=secili_doktor_id,
        secili_tarih=secili_tarih,
        secili_doktor=secili_doktor,
        randevular=randevular,
        slot_durumu=slot_durumu
    ) 

@app.route("/doktor_ekle", methods=["GET", "POST"])
@login_required
def doktor_ekle():
    if request.method == "POST":
        ad = request.form["ad"].strip()
        soyad = request.form["soyad"].strip()
        brans = request.form["brans"].strip()

        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO doktorlar (ad, soyad, brans) VALUES (?, ?, ?)",
            (ad, soyad, brans)
        )
        conn.commit()
        conn.close()
        return redirect("/doktorlar")

    return render_template("doktor_ekle.html")

@app.route("/doktor_sil/<int:id>", methods=["POST"])
@login_required
def doktor_sil(id):
    conn = get_conn()
    cur = conn.cursor()

    # Önce doktoru çek (log için gerekli)
    cur.execute("SELECT ad, soyad, brans FROM doktorlar WHERE id = ?", (id,))
    doktor = cur.fetchone()

    if not doktor:
        conn.close()
        return redirect("/doktorlar?hata=Doktor bulunamadı.")

    # Doktorun randevusu var mı? (varsa silmeyelim)
    cur.execute("SELECT COUNT(*) AS c FROM randevular WHERE doktor_id = ?", (id,))
    if cur.fetchone()["c"] > 0:
        conn.close()
        return redirect("/doktorlar?hata=Bu doktorun randevuları var. Önce randevuları silmelisin.")

    # Silme işlemi
    cur.execute("DELETE FROM doktorlar WHERE id = ?", (id,))
    conn.commit()

    # ✅ Gelişmiş Audit Log
    audit_log(
        action="DELETE",
        entity="doktor",
        entity_id=id,
        detail=f"Doktor silindi: {doktor['ad']} {doktor['soyad']} ({doktor['brans']})"
    )

    conn.close()
    return redirect("/doktorlar?msg=Doktor silindi.") 

@app.route("/audit")
@admin_required
def audit_page():
    q = (request.args.get("q") or "").strip()
    action = (request.args.get("action") or "").strip()
    entity = (request.args.get("entity") or "").strip()
    entity_id = (request.args.get("entity_id") or "").strip()
    date_from = (request.args.get("from") or "").strip()
    date_to = (request.args.get("to") or "").strip()

    page = int(request.args.get("page", 1))
    per_page = 20
    offset = (page - 1) * per_page

    filters = {
        "q": q,
        "action": action,
        "entity": entity,
        "entity_id": entity_id,
        "from": date_from,
        "to": date_to,
    }

    conn = get_conn()
    cur = conn.cursor()

    base_sql = " FROM audit_logs WHERE 1=1 "
    params = []

    if action:
        base_sql += " AND action = ?"
        params.append(action)

    if entity:
        base_sql += " AND entity = ?"
        params.append(entity)

    if entity_id:
        base_sql += " AND entity_id = ?"
        params.append(int(entity_id))

    if q:
        base_sql += " AND detail LIKE ?"
        params.append(f"%{q}%")

    if date_from:
        base_sql += " AND substr(ts,1,10) >= ?"
        params.append(date_from)

    if date_to:
        base_sql += " AND substr(ts,1,10) <= ?"
        params.append(date_to)

    cur.execute("SELECT COUNT(*) as c " + base_sql, params)
    total_count = cur.fetchone()["c"]

    page_count = (total_count + per_page - 1) // per_page

    sql = "SELECT * " + base_sql + " ORDER BY id DESC LIMIT ? OFFSET ?"
    cur.execute(sql, params + [per_page, offset])
    logs = cur.fetchall()

    conn.close()

    return render_template(
        "audit.html",
        logs=logs,
        filters=filters,
        page=page,
        page_count=page_count,
        total_count=total_count
    ) 

@app.route("/audit/export.csv")
@admin_required
def audit_export_csv():
    q = (request.args.get("q") or "").strip()
    action = (request.args.get("action") or "").strip()
    entity = (request.args.get("entity") or "").strip()
    entity_id = (request.args.get("entity_id") or "").strip()
    date_from = (request.args.get("from") or "").strip()
    date_to = (request.args.get("to") or "").strip()

    where = " WHERE 1=1 "
    params = []

    if action:
        where += " AND action = ? "
        params.append(action)
    if entity:
        where += " AND entity = ? "
        params.append(entity)
    if entity_id:
        where += " AND entity_id = ? "
        params.append(int(entity_id))
    if date_from:
        where += " AND ts >= ? "
        params.append(date_from + " 00:00:00")
    if date_to:
        where += " AND ts <= ? "
        params.append(date_to + " 23:59:59")
    if q:
        where += " AND detail LIKE ? "
        params.append(f"%{q}%")

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT ts, action, entity, entity_id, detail
        FROM audit_logs
    """ + where + " ORDER BY id DESC LIMIT 5000", params)
    rows = cur.fetchall()
    conn.close()

    output = StringIO() 
    writer = csv.writer(output)
    writer.writerow(["ts", "action", "entity", "entity_id", "detail"])
    for r in rows:
        writer.writerow([r["ts"], r["action"], r["entity"], r["entity_id"], r["detail"]])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_export.csv"},
    )  

def migrate_audit_indexes():
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit_logs(ts)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_audit_action ON audit_logs(action)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_audit_entity ON audit_logs(entity)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_audit_entity_id ON audit_logs(entity, entity_id)")
    except:
        pass
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    run_safe_migrations() 
    migrate_klinik_alanlari()

    migrate_add_audit_logs()
    migrate_audit_indexes()

    migrate_unique_doktor_slot() 

    migrate_hash_passwords()  
    
    seed_admin_once()
    seed_user_once() 
    seed_doctors_once()

    app.run(host='0.0.0.0', port=5000, debug=True) 