import io
P='/root/cabinet/app/routes/api.py'
with io.open(P,'r',encoding='utf-8') as f:
    s=f.read()
old = "if uk:\n            user_key_id = uk.id\n            user_id = uk.user_id\n"
new = "if uk:\n            user_key_id = uk.id\n            user_id = uk.user_id\n            key_value = key_value or getattr(uk,'key', None)\n"
s = s.replace(old, new)
with io.open(P,'w',encoding='utf-8') as f:
    f.write(s)
print('Backfilled key_value assignment when uk resolved')
