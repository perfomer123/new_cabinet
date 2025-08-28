#!/usr/bin/env python3
import io

P = '/root/cabinet/app/routes/api.py'

def main():
  with io.open(P, 'r', encoding='utf-8') as f:
    s = f.read()

  s = s.replace(
    'from flask import Blueprint, request, jsonify, session',
    'from flask import Blueprint, request, jsonify, session, current_app'
  )

  needle = "data = request.get_json(silent=True) or {}\n        subject"
  insert = (
    "data = request.get_json(silent=True) or {}\n"
    "        try:\n"
    "            current_app.logger.info('[helpdesk] create_ticket payload: %s', data)\n"
    "        except Exception:\n"
    "            pass\n"
    "        subject"
  )
  s = s.replace(needle, insert)

  needle2 = (
    "if uk:\n"
    "            user_key_id = uk.id\n"
    "            user_id = uk.user_id\n\n"
    "        ticket = SupportTicket("
  )
  insert2 = (
    "if uk:\n"
    "            user_key_id = uk.id\n"
    "            user_id = uk.user_id\n\n"
    "        try:\n"
    "            current_app.logger.info('[helpdesk] resolved user_key_id=%s user_id=%s key_value=%s', user_key_id, user_id, key_value)\n"
    "        except Exception:\n"
    "            pass\n\n"
    "        ticket = SupportTicket("
  )
  s = s.replace(needle2, insert2)

  with io.open(P, 'w', encoding='utf-8') as f:
    f.write(s)
  print('Patched logging in api')

if __name__ == '__main__':
  main()

