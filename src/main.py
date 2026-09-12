import os

from parser import parse_log

from detector import (
    load_rules,
    detect_bruteforce,
    detect_suspicious_ip,
    detect_unusual_login,
    detect_privilege_escalation
)

from alerts import (
    print_alerts,
    save_alerts
)


# =========================================================
# CHEMIN DU PROJET
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

LOG_FILE = os.path.join(
    BASE_DIR,
    "logs",
    "auth.log"
)


# =========================================================
# TITRE
# =========================================================

print()
print("=" * 60)
print("              SECURITY LOG ANALYZER")
print("=" * 60)
print()


# =========================================================
# CHARGEMENT DES REGLES
# =========================================================

rules = load_rules()


# =========================================================
# LECTURE DES LOGS
# =========================================================

events = []

try:

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            event = parse_log(line)

            if event:
                events.append(event)

except FileNotFoundError:

    print("ERREUR : fichier auth.log introuvable.")
    print()
    print("Chemin recherché :")
    print(LOG_FILE)
    exit()


# =========================================================
# INFORMATIONS
# =========================================================

print(
    f"Nombre d'événements analysés : {len(events)}"
)

print()


# =========================================================
# DETECTION
# =========================================================

alerts = []


# Brute Force
alerts.extend(
    detect_bruteforce(
        events,
        rules
    )
)


# IP suspectes
alerts.extend(
    detect_suspicious_ip(
        events,
        rules
    )
)


# Connexions inhabituelles
alerts.extend(
    detect_unusual_login(
        events,
        rules
    )
)


# Privilege Escalation
alerts.extend(
    detect_privilege_escalation(
        events
    )
)


# =========================================================
# AFFICHAGE
# =========================================================

print_alerts(alerts)


# =========================================================
# SAUVEGARDE
# =========================================================

save_alerts(alerts)


print()
print("Analyse terminée.")
