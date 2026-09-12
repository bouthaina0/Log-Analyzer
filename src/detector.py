import json
from collections import defaultdict
from datetime import timedelta
import os


# ---------------------------------------------------------
# CHARGEMENT DES REGLES
# ---------------------------------------------------------




def load_rules():

    # Chemin du dossier du projet
    base_dir = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )

    rules_path = os.path.join(
        base_dir,
        "config",
        "rules.json"
    )

    with open(rules_path, "r", encoding="utf-8") as file:
        return json.load(file)

# ---------------------------------------------------------
# DETECTION BRUTE FORCE
# ---------------------------------------------------------

def detect_bruteforce(events, rules):

    failed_attempts = defaultdict(list)
    alerts = []

    max_attempts = rules["bruteforce"]["max_attempts"]
    window_minutes = rules["bruteforce"]["window_minutes"]

    for event in events:

        if event["event"] != "failed_login":
            continue

        ip = event["ip"]

        failed_attempts[ip].append(
            event["timestamp"]
        )

        # Garder seulement les tentatives
        # des dernières X minutes
        recent_attempts = [
            timestamp
            for timestamp in failed_attempts[ip]
            if event["timestamp"] - timestamp
            <= timedelta(minutes=window_minutes)
        ]

        failed_attempts[ip] = recent_attempts

        if len(recent_attempts) >= max_attempts:

            alerts.append({
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "timestamp": event["timestamp"].strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "ip": ip,
                "attempts": len(recent_attempts),
                "message": (
                    f"{len(recent_attempts)} failed logins "
                    f"detected from {ip}"
                )
            })

            # Éviter de générer une alerte
            # à chaque tentative supplémentaire
            failed_attempts[ip] = []


    return alerts


# ---------------------------------------------------------
# DETECTION IP SUSPECTE
# ---------------------------------------------------------

def detect_suspicious_ip(events, rules):

    alerts = []

    suspicious_ips = rules["suspicious_ips"]

    for event in events:

        if "ip" not in event:
            continue

        if event["ip"] in suspicious_ips:

            alerts.append({
                "type": "SUSPICIOUS_IP",
                "severity": "HIGH",
                "timestamp": event["timestamp"].strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "ip": event["ip"],
                "message": (
                    f"Connection from suspicious IP "
                    f"{event['ip']}"
                )
            })

    return alerts


# ---------------------------------------------------------
# DETECTION CONNEXION INHABITUELLE
# ---------------------------------------------------------

def detect_unusual_login(events, rules):

    alerts = []

    start_hour = rules["unusual_login"]["start_hour"]
    end_hour = rules["unusual_login"]["end_hour"]

    for event in events:

        if event["event"] != "successful_login":
            continue

        hour = event["timestamp"].hour

        unusual = False

        if start_hour > end_hour:

            if hour >= start_hour or hour < end_hour:
                unusual = True

        else:

            if start_hour <= hour < end_hour:
                unusual = True

        if unusual:

            alerts.append({
                "type": "UNUSUAL_LOGIN",
                "severity": "MEDIUM",
                "timestamp": event["timestamp"].strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "user": event["user"],
                "ip": event["ip"],
                "message": (
                    f"Login at unusual hour "
                    f"({hour}:00)"
                )
            })

    return alerts


# ---------------------------------------------------------
# DETECTION PRIVILEGE ESCALATION
# ---------------------------------------------------------

def detect_privilege_escalation(events):

    alerts = []

    for event in events:

        if event["event"] != "sudo":
            continue

        alerts.append({
            "type": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "timestamp": event["timestamp"].strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "user": event["user"],
            "command": event["command"],
            "message": (
                f"Privilege escalation command executed "
                f"by {event['user']}"
            )
        })

    return alerts
