import re
p='/root/cabinet/app/routes/api.py'
with open(p,'r',encoding='utf-8') as f:
    s=f.read()
pat=r"SupportTicket\(\n\s*user_id=user_id,\n\s*user_key_id=user_key_id,\n\s*subject=subject,\n\s*message=message,\n"
if re.search(pat,s):
    s=re.sub(pat, lambda m: m.group(0)+"            key_value=key_value,\n", s, count=1)
    with open(p,'w',encoding='utf-8') as f:
        f.write(s)
    print('Inserted key_value in ticket creation')
else:
    print('Pattern not found')
