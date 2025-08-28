import io
P='/root/cabinet/app/routes/api.py'
with io.open(P,'r',encoding='utf-8') as f:
    s=f.read()
# 1) Ensure import current_app present (best effort)
s=s.replace('from flask import Blueprint, request, jsonify, session','from flask import Blueprint, request, jsonify, session, current_app')
# 2) Replace resolve block to rely only on key_value
start_marker = 'uk = None\n'
idx = s.find(start_marker)
if idx != -1:
    # Find the end of the resolve section up to 'ticket = SupportTicket('
    j = s.find('\n        ticket = SupportTicket(', idx)
    if j != -1:
        new_block = (
            "uk = None\n"
            "        if key_value:\n"
            "            uk = UserKey.query.filter_by(key=key_value).first()\n"
            "        if uk:\n"
            "            user_key_id = uk.id\n"
            "            user_id = uk.user_id\n\n"
        )
        s = s[:idx] + new_block + s[j:]
# 3) Remove any backfill line that sets key_value from uk
s = s.replace("key_value = key_value or getattr(uk,'key', None)\n", '')
with io.open(P,'w',encoding='utf-8') as f:
    f.write(s)
print('Patched server: resolve only by key string; no key_id fallback')
