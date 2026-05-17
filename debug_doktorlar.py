import os
import importlib.util

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SITE_PATH = os.path.join(BASE_DIR, "site.py")  # hbys/site.py

spec = importlib.util.spec_from_file_location("hbys_app", SITE_PATH)
hbys_app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hbys_app)

print("✅ site.py yüklendi:", SITE_PATH)

if not hasattr(hbys_app, "get_conn"):
    raise AttributeError("site.py içinde get_conn() bulunamadı. Fonksiyon adını kontrol et.")

conn = hbys_app.get_conn()
cur = conn.cursor()

cur.execute("SELECT id, ad, soyad, brans FROM doktorlar ORDER BY id")
rows = cur.fetchall()

print("\n--- Doktorlar ---")
for r in rows:
    try:
        print(dict(r))
    except Exception:
        print(r)

cur.execute("SELECT DISTINCT brans FROM doktorlar ORDER BY brans")
branslar = cur.fetchall()
print("\n--- Branşlar (distinct) ---")
for b in branslar:
    try:
        print(b["brans"])
    except Exception:
        print(b)

conn.close()
print("\n✅ Bitti")