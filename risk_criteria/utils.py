import re


def parse_days(value):
    """
    Parse values like: "1", "2", "day 1", "day 3", "1 week", "2 weeks", "1 week 2 days"
    Returns total number of days as int, or raises ValueError.

    Shared by risk_criteria/views.py (deadline/calendar math) and
    risk_criteria/serializers.py (severity-ordering validation) — kept in
    one place so both stay in sync.
    """
    if value is None:
        raise ValueError("Empty value")

    value = str(value).strip().lower()

    # Pure integer: "2", "7"
    if value.isdigit():
        return int(value)

    total_days = 0
    matched = False

    # Match weeks: "1 week", "2 weeks"
    week_match = re.search(r'(\d+)\s*week', value)
    if week_match:
        total_days += int(week_match.group(1)) * 7
        matched = True

    # Match days: "day 1", "1 day", "3 days"
    day_match = re.search(r'(\d+)\s*day|day\s*(\d+)', value)
    if day_match:
        num = day_match.group(1) or day_match.group(2)
        total_days += int(num)
        matched = True

    if not matched:
        raise ValueError(f"Cannot parse day value: '{value}'")

    return total_days
