# Security Log Analyzer

## Description

Security Log Analyzer est un outil développé en Python permettant d'analyser des fichiers de logs et de détecter automatiquement certains comportements suspects.

Le projet suit l'architecture suivante :

```text
Logs
  ↓
Python
  ↓
Parsing
  ↓
Events structurés
  ↓
Detection Rules
  ↓
Security Alerts
  ↓
Rapport JSON
```

## Objectifs

L'application permet de détecter :

* plusieurs tentatives de connexion échouées ;
* les attaques potentielles par brute force ;
* les connexions à des heures inhabituelles ;
* les connexions provenant d'adresses IP suspectes ;
* l'utilisation de privilèges élevés avec `sudo`.

## Technologies

* Python 3
* Regular Expressions
* JSON
* Linux/SSH logs
* Python datetime

## Structure

```text
log-analyzer/
│
├── logs/
│   └── auth.log
│
├── src/
│   ├── parser.py
│   ├── detector.py
│   ├── alerts.py
│   └── main.py
│
├── config/
│   └── rules.json
│
├── reports/
│   └── alerts.json
│
└── README.md
```

## Détection

### Brute Force

Une alerte est générée lorsqu'une même adresse IP effectue au moins 5 tentatives de connexion échouées dans une période de 5 minutes.

### IP suspecte

Une alerte est générée lorsqu'une connexion provient d'une adresse IP présente dans la liste des IP suspectes.

### Connexion inhabituelle

Une alerte est générée lorsqu'un utilisateur se connecte pendant une période considérée comme inhabituelle, entre 23h00 et 05h00.

### Privilege Escalation

L'utilisation de commandes via `sudo` est signalée comme événement nécessitant une analyse de sécurité.

## Exécution

Depuis le dossier `src` :

```bash
cd src
python main.py
```

Le programme analyse les logs et affiche les alertes détectées dans le terminal.

Les alertes sont également enregistrées dans :

```text
reports/alerts.json
```

## Résultat

Le système produit des alertes contenant :

* le type de menace ;
* le niveau de gravité ;
* la date et l'heure ;
* l'adresse IP ;
* l'utilisateur ;
* le nombre de tentatives ;
* une description de l'événement.

## Évolutions possibles

Le projet peut être amélioré avec :

* une interface web Flask ;
* un dashboard de sécurité ;
* une base de données SQLite ;
* des graphiques ;
* une blacklist d'IP dynamique ;
* l'envoi d'alertes par email ;
* une surveillance des logs en temps réel ;
* davantage de règles de détection ;
* un système de scoring des événements.
