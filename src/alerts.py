import json
import os


# =========================================================
# CHEMIN DU PROJET
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

REPORT_FILE = os.path.join(
    BASE_DIR,
    "reports",
    "alerts.json"
)


# =========================================================
# AFFICHER UNE ALERTE
# =========================================================

def print_alert(alert):

    print("=" * 60)

    print(f"TYPE      : {alert['type']}")
    print(f"SEVERITY  : {alert['severity']}")
    print(f"TIMESTAMP : {alert['timestamp']}")

    if "ip" in alert:
        print(f"IP        : {alert['ip']}")

    if "user" in alert:
        print(f"USER      : {alert['user']}")

    if "attempts" in alert:
        print(f"ATTEMPTS  : {alert['attempts']}")

    if "command" in alert:
        print(f"COMMAND   : {alert['command']}")

    print(f"MESSAGE   : {alert['message']}")

    print("=" * 60)


# =========================================================
# AFFICHER TOUTES LES ALERTES
# =========================================================

def print_alerts(alerts):

    if not alerts:

        print("Aucune alerte détectée.")

        return

    print("SECURITY ALERTS")
    print()

    for alert in alerts:

        print_alert(alert)


# =========================================================
# SAUVEGARDER LES ALERTES
# =========================================================

def save_alerts(alerts):

    # Créer le dossier reports s'il n'existe pas
    os.makedirs(
        os.path.dirname(REPORT_FILE),
        exist_ok=True
    )

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            alerts,
            file,
            indent=4,
            ensure_ascii=False
        )

    print()
    print("Rapport sauvegardé dans :")
    print(REPORT_FILE)
