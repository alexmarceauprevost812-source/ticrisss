# ticrisss 0.2

## Terminal Windows (PowerShell ou CMD)

Python 3 doit être installé et accessible avec `py -3` ou `python`. Décompresser l'archive, ouvrir un terminal dans le dossier `ti-lex-audit`, puis :

```powershell
.\ticrisss.cmd 192.168.1.10 --authorized --web --exposure --output scan.json
py -3 report_html.py scan.json --output scan.html
```

Si `py` n'est pas disponible pour la conversion HTML, utiliser `python report_html.py scan.json --output scan.html`.

## Terminal Kali / Linux

```sh
sh ticrisss.sh 192.168.1.10 --authorized --web --exposure --output scan.json
python3 report_html.py scan.json --output scan.html
```

L'outil ne demande pas les droits administrateur. Remplacer l'adresse par celle d'un appareil autorisé. Utiliser un nouveau nom de rapport à chaque scan. Le moteur Python utilise la bibliothèque standard et ne dépend pas de commandes propres à Linux.

## Rapport HTML et lecteur Android

Après le scan :

```sh
python3 report_html.py exposition.json --output exposition.html
```

Ouvrir `exposition.html` dans un navigateur. La page fonctionne hors ligne, sans JavaScript. Le dossier `android/` contient un lecteur Java à intégrer dans une APK existante ; consulter `android/INTEGRATION.md`. Ce lecteur importe les rapports JSON, il ne lance pas le moteur Python sur Android.

Cette version accepte uniquement une adresse IPv4 privée ou loopback. Pour le web, elle examine les services HTTP/HTTPS sur les ports prévus de cette même adresse locale : la prise en charge des domaines publics et des tests d'authentification n'est pas encore implémentée.

## Vérifier les expositions possibles

```sh
python3 ticrisss.py 192.168.1.10 --authorized --web --exposure --output exposition.json
```

L'option `--exposure` vérifie par HEAD quatre chemins courants : `/.env`, `/.git/config`, `/backup.zip`, `/database.sql`. Une cinquième requête sur un chemin de référence aide à signaler les sites qui renvoient 200 même pour un fichier inexistant. Aucun contenu de fichier n'est lu ou enregistré et les redirections ne sont pas suivies. Les réponses 200 sont des pistes à vérifier manuellement, pas des fuites confirmées. HEAD peut se comporter différemment de GET ; des fichiers exposés sous d'autres noms ne seront pas détectés. Ce module ne contourne pas l'authentification.

Outil indépendant pour Python 3, sans dépendances externes. Fonctionne dans le terminal de Kali Linux. Teste une seule adresse IPv4 privée ou loopback à la fois, avec au maximum 128 ports et 8 connexions simultanées.

## Utilisation

Décompresser l'archive, puis dans son dossier :

```sh
python3 ticrisss.py 192.168.1.10 --authorized --web --output premier-scan.json
```

Remplacer l'adresse par celle d'un appareil que vous êtes autorisé à auditer. Ports personnalisés :

```sh
python3 ticrisss.py 192.168.1.10 --authorized --ports 22,80,443 --output verification.json
```

`--web` effectue une seule requête HEAD à la racine de chaque port web ouvert (80, 443, 8080, 8443). Il ne suit pas les redirections. La validation TLS reste active ; un certificat interne ou un certificat prévu pour un nom de domaine peut échouer avec une adresse IP.

Le JSON contient les résultats TCP, les observations web, les recommandations et les limites. Il pourra être importé dans TI-LEX-V10. L'indicateur `closed_or_filtered` ne distingue pas un port fermé d'un filtrage ou d'une erreur réseau.

Un port ouvert ou un en-tête absent n'est pas une preuve de vulnérabilité. Les noms de services suggérés par les recommandations restent à vérifier. Cette version ne découvre pas automatiquement les appareils, ne teste pas les mots de passe et n'exécute pas d'exploitation. Utiliser un nouveau nom de rapport pour chaque scan : les fichiers existants sont protégés contre l'écrasement.
