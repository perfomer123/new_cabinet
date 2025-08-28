import re
p='/root/cabinet/app/routes/api.py'
with open(p,'r',encoding='utf-8') as f:
    s=f.read()
# Remove @auth_required directly above create_support_ticket
s=re.sub(r"(@api_bp\.route\('/helpdesk/tickets',\s*methods=\['POST'\]\)\n)@auth_required\n(\s*def create_support_ticket\(\):)", r"\1\2", s, count=1)
# Set user_id None instead of current_user
s=re.sub(r"user_id\s*=\s*request\.current_user\.id[^\n]*\n\s*user_key_id\s*=\s*None", "user_id = None\n        user_key_id = None", s, count=1)
# Replace key resolution block to not depend on user_id
pat=r"# Resolve by key:[\s\S]*?if uk:\n\s*user_key_id = uk.id\n"
repl=(
    "# Resolve by key: prefer text key; fallback to id; derive user_id from key\n"
    "        uk = None\n"
    "        if key_value:\n"
    "            uk = UserKey.query.filter_by(key=key_value).first()\n"
    "        if not uk and key_id:\n"
    "            uk = UserKey.query.get(key_id)\n"
    "        if uk:\n"
    "            user_key_id = uk.id\n"
    "            user_id = uk.user_id\n"
)
s=re.sub(pat, repl, s, count=1)
with open(p,'w',encoding='utf-8') as f:
    f.write(s)
print('Patched to no-auth, key-based resolution')
