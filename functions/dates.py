from calendar import monthrange
from datetime import date


def add_months_to_date(base_date: date, months: int) -> date:
    absolute_month = (base_date.year * 12) + (base_date.month - 1) + months
    target_year, target_month_index = divmod(absolute_month, 12)
    target_month = target_month_index + 1
    target_day = min(base_date.day, monthrange(target_year, target_month)[1])
    return date(target_year, target_month, target_day)


# Copyright (c) Liam Suorsa and Mika Suorsa
