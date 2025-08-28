import io
P='/root/cabinet/app/routes/api.py'
with io.open(P,'r',encoding='utf-8') as f:
    lines=f.readlines()
keep=[]
skip_subs=(
    'if not uk and key_id:',
    'uk = UserKey.query.get(key_id)',
    "key_value = key_value or getattr(uk,'key', None)",
)
for line in lines:
    if any(sub in line for sub in skip_subs):
        continue
    keep.append(line)
with io.open(P,'w',encoding='utf-8') as f:
    f.writelines(keep)
print('Removed key_id fallback and backfill lines')
