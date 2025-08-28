#!/usr/bin/env python3
import re, sys
P = '/root/cabinet/app/routes/api.py'

def main():
    with open(P, 'r', encoding='utf-8') as f:
        txt = f.read()
    orig = txt

    # 1) add @auth_required
    pat = r"(@api_bp\.route\('/helpdesk/tickets',\s*methods=\['POST'\]\)\n)(\s*def create_support_ticket\(\):)"
    txt, _ = re.subn(pat, r"\1@auth_required\n\2", txt, count=1)

    # 2) set user_id from request.current_user
    pat2 = r"user_id\s*=\s*None\s*\n\s*user_key_id\s*=\s*None"
    repl2 = "user_id = request.current_user.id if hasattr(request, 'current_user') else None\n        user_key_id = None"
    txt, _ = re.subn(pat2, repl2, txt, count=1)

    # 3) comment out explicit user_id and cookie token block
    start = txt.find('# Явно принимаем user_id')
    end = txt.find('# Resolve by key:')
    if start != -1 and end != -1 and end > start:
        block = txt[start:end]
        commented = '\n'.join(('        # ' + line) if not line.startswith('        #') else line for line in block.splitlines())
        txt = txt[:start] + commented + txt[end:]

    # 4) replace key resolution block
    pat3 = r"# Resolve by key:[\s\S]*?if uk:\n\s*user_key_id = uk.id\n\s*user_id = user_id or uk.user_id\n"
    repl3 = (
        "# Resolve by key: use text key limited to current user_id; validate key_id owner\n"
        "        uk = None\n"
        "        if key_value and user_id:\n"
        "            uk = UserKey.query.filter_by(key=key_value, user_id=user_id).first()\n"
        "        if not uk and key_id:\n"
        "            uk = UserKey.query.get(key_id)\n"
        "            if uk and user_id and uk.user_id != user_id:\n"
        "                uk = None\n"
        "        if uk:\n"
        "            user_key_id = uk.id\n"
    )
    txt, _ = re.subn(pat3, repl3, txt, count=1)

    if txt == orig:
        print('No changes made', file=sys.stderr)
    with open(P, 'w', encoding='utf-8') as f:
        f.write(txt)
    print('Patched successfully')

if __name__ == '__main__':
    main()

