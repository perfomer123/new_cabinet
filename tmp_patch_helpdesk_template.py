#!/usr/bin/env python3
import io,sys
P = '/root/cabinet/app/templates/admin/helpdesk.html'
old = (
    '              <td>\n'
    '                {% if t.user_phone %}<a href="/client/{{ t.user_phone }}" target="_blank">ID {{ t.ext_user_id or t.user_phone }}</a>{% else %}—{% endif %}\n'
    '              </td>\n'
)
new = (
    '              <td>\n'
    '                {% if t.identifier %}<a href="/client/{{ t.identifier }}" target="_blank">{{ t.ext_user_id or t.identifier }}</a>{% else %}—{% endif %}\n'
    '              </td>\n'
)
def main():
    with open(P,'r',encoding='utf-8') as f:
        s=f.read()
    if old in s:
        s=s.replace(old,new)
        with open(P,'w',encoding='utf-8') as f:
            f.write(s)
        print('Template patched')
    else:
        print('Pattern not found', file=sys.stderr)
if __name__=='__main__':
    main()

