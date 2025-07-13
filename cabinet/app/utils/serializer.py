from __future__ import annotations

import datetime as _dt
import enum
import numbers
import uuid
from typing import Any, Dict

from apscheduler.triggers.base import BaseTrigger
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from flask import current_app

def _serialize_trigger(trigger: BaseTrigger) -> Dict[str, Any]:
    """Преобразуем APScheduler‑триггеры в структурированный dict."""
    if isinstance(trigger, CronTrigger):
        return {
            "type": "cron",
            "cron": str(trigger),
        }
    if isinstance(trigger, IntervalTrigger):
        return {
            "type": "interval",
            "seconds": trigger.interval.total_seconds(),
        }
    if isinstance(trigger, DateTrigger):
        return {
            "type": "date",
            "run_date": trigger.run_date.isoformat(),
        }
    return str(trigger)


def _to_serializable(value: Any) -> Any:
    """
    Универсальный рекурсивный сериализатор JSON‑safe.
    *  str / int / float / bool / None           – как есть
    *  datetime / date / time                    – ISO‑строка
    *  uuid.UUID / enum.Enum / callable          – str(value)
    *  list / tuple / set                        – список с рекурсией
    *  dict                                      – dict(str(key) -> value)
    *  APScheduler BaseTrigger                   – структурированный dict
    *  всё прочее                                – str(value)
    """
    if value is None or isinstance(value, (str, bool, numbers.Number)):
        return value
    if isinstance(value, (_dt.datetime, _dt.date, _dt.time)):
        return value.isoformat()
    if isinstance(value, (uuid.UUID, enum.Enum)):
        return str(value)
    if callable(value):
        return str(value)
    if isinstance(value, (list, tuple, set)):
        return [_to_serializable(v) for v in value]
    if isinstance(value, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in value.items():
            if callable(k) or str(k).startswith("_"):
                continue
            cleaned[str(k)] = _to_serializable(v)
        return cleaned
    if isinstance(value, BaseTrigger):
        return _serialize_trigger(value)
    return str(value) 