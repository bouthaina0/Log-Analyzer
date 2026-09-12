import re
from datetime import datetime


def parse_log(line):
    """
    Analyse une ligne de log et retourne
    un dictionnaire contenant les informations importantes.
    """

    # ---------------------------------------------------------
    # FAILED LOGIN
    # ---------------------------------------------------------
    pattern_failed = (
        r"(?P<date>\d{4}-\d{2}-\d{2}) "
        r"(?P<time>\d{2}:\d{2}:\d{2}).*?"
        r"Failed password for user (?P<user>\w+) "
        r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    match = re.search(pattern_failed, line)

    if match:
        timestamp = datetime.strptime(
            f"{match.group('date')} {match.group('time')}",
            "%Y-%m-%d %H:%M:%S"
        )

        return {
            "timestamp": timestamp,
            "event": "failed_login",
            "user": match.group("user"),
            "ip": match.group("ip")
        }

    # ---------------------------------------------------------
    # SUCCESSFUL LOGIN
    # ---------------------------------------------------------
    pattern_success = (
        r"(?P<date>\d{4}-\d{2}-\d{2}) "
        r"(?P<time>\d{2}:\d{2}:\d{2}).*?"
        r"Accepted password for user (?P<user>\w+) "
        r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    match = re.search(pattern_success, line)

    if match:
        timestamp = datetime.strptime(
            f"{match.group('date')} {match.group('time')}",
            "%Y-%m-%d %H:%M:%S"
        )

        return {
            "timestamp": timestamp,
            "event": "successful_login",
            "user": match.group("user"),
            "ip": match.group("ip")
        }

    # ---------------------------------------------------------
    # SUDO / PRIVILEGE ESCALATION
    # ---------------------------------------------------------
    pattern_sudo = (
        r"(?P<date>\d{4}-\d{2}-\d{2}) "
        r"(?P<time>\d{2}:\d{2}:\d{2}) "
        r"sudo: (?P<user>\w+).*COMMAND=(?P<command>.*)"
    )

    match = re.search(pattern_sudo, line)

    if match:
        timestamp = datetime.strptime(
            f"{match.group('date')} {match.group('time')}",
            "%Y-%m-%d %H:%M:%S"
        )

        return {
            "timestamp": timestamp,
            "event": "sudo",
            "user": match.group("user"),
            "command": match.group("command").strip()
        }

    return None
