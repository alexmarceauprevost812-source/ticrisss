#!/usr/bin/env python3
"""Audit TCP et HTTP prudent d'une adresse IPv4 locale autorisée."""
import argparse
import concurrent.futures
import datetime
import http.client
import ipaddress
import json
import pathlib
import socket
import sys

LOGO = """+--------------------------------------+
|              ticrisss                |
|       Audit de cybersecurite          |
+--------------------------------------+"""

NETWORKS = tuple(ipaddress.ip_network(n) for n in
                 ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'))
DEFAULT_PORTS = '21,22,23,25,53,80,110,139,143,443,445,3389,5432,6379,8080,8443'


def local_ip(value):
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('Indique une adresse IPv4, pas un nom de domaine.') from exc
    if not any(address in network for network in NETWORKS):
        raise argparse.ArgumentTypeError('Seules les adresses privées RFC1918 et loopback sont acceptées.')
    return str(address)


def ports(value):
    try:
        result = sorted(set(int(p.strip()) for p in value.split(',')))
        if not result or len(result) > 128 or any(p < 1 or p > 65535 for p in result):
            raise ValueError()
        return result
    except ValueError as exc:
        raise argparse.ArgumentTypeError('Indique au maximum 128 ports de 1 à 65535, séparés par des virgules.') from exc


def probe(target, port):
    try:
        with socket.create_connection((target, port), timeout=1):
            return {'port': port, 'state': 'open'}
    except OSError:
        return {'port': port, 'state': 'closed_or_filtered'}


def check_web(target, port):
    secure = port in (443, 8443)
    connection_class = http.client.HTTPSConnection if secure else http.client.HTTPConnection
    connection = connection_class(target, port, timeout=3)
    try:
        connection.request('HEAD', '/', headers={'User-Agent': 'ticrisss-Audit/0.1'})
        response = connection.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders()}
        missing = [name for name in ('content-security-policy', 'x-content-type-options')
                   if name not in headers]
        if secure and 'strict-transport-security' not in headers:
            missing.append('strict-transport-security')
        return {'port': port, 'scheme': 'https' if secure else 'http',
                'status': response.status, 'missing_headers': missing,
                'note': 'En-têtes absents : points à examiner selon le type de service, pas des failles confirmées.'}
    except (OSError, http.client.HTTPException) as exc:
        return {'port': port, 'error': str(exc),
                'note': 'Un échec HTTPS peut provenir du certificat, du nom utilisé ou du protocole.'}
    finally:
        connection.close()


def check_exposure(target, port):
    """Observe uniquement les métadonnées : aucun corps de fichier n'est lu."""
    connection_class = http.client.HTTPSConnection if port in (443, 8443) else http.client.HTTPConnection
    observations = []
    # La référence aide à reconnaître les sites qui répondent 200 à toute URL.
    paths = ('/ti-lex-missing-7f8249e6', '/.env', '/.git/config', '/backup.zip', '/database.sql')
    for path in paths:
        connection = connection_class(target, port, timeout=3)
        try:
            connection.request('HEAD', path, headers={'User-Agent': 'ticrisss-Audit/0.2'})
            response = connection.getresponse()
            observations.append({'path': path, 'status': response.status,
                                 'content_type': response.getheader('Content-Type'),
                                 'content_length': response.getheader('Content-Length')})
        except (OSError, http.client.HTTPException):
            observations.append({'path': path, 'error': 'Requête impossible ; résultat inconnu.'})
        finally:
            connection.close()
    baseline = observations[0]
    candidates = []
    for item in observations[1:]:
        if item.get('status') == 200:
            candidates.append({'path': item['path'], 'assessment': 'À vérifier manuellement',
                               'baseline_also_200': baseline.get('status') == 200,
                               'action': 'Vérifier que ce fichier sensible est inaccessible sans authentification ; retirer les sauvegardes et secrets de la racine web.'})
    return {'port': port, 'observations': observations, 'candidates': candidates,
            'note': 'HEAD uniquement, sans contenu ni redirections. Une réponse 200 ne confirme pas la présence de données sensibles. HEAD peut différer de GET.'}


def main():
    print(LOGO, file=sys.stderr, flush=True)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', type=local_ip, help='Adresse IPv4 locale autorisée')
    parser.add_argument('--ports', type=ports, default=DEFAULT_PORTS)
    parser.add_argument('--web', action='store_true', help='Faire une requête HEAD sur les ports web ouverts')
    parser.add_argument('--exposure', action='store_true', help='Vérifier les métadonnées de quatre chemins sensibles courants')
    parser.add_argument('--authorized', action='store_true', help='Confirmer ton autorisation de tester cette cible')
    parser.add_argument('--output', default='ti-lex-report.json', help='Nouveau fichier JSON à créer')
    args = parser.parse_args()
    if not args.authorized:
        parser.error('Ajoute --authorized uniquement si tu es autorisé à tester cette adresse.')
    report_path = pathlib.Path(args.output)
    if report_path.exists():
        parser.error('Le rapport existe déjà : utilise un autre nom avec --output.')
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda port: probe(args.target, port), args.ports))
    opened = [r['port'] for r in results if r['state'] == 'open']
    web = [check_web(args.target, port) for port in opened
           if args.web and port in (80, 443, 8080, 8443)]
    exposure = [check_exposure(args.target, port) for port in opened
                if args.exposure and port in (80, 443, 8080, 8443)]
    recommendations = []
    for port in opened:
        if port in (21, 23, 110, 143):
            recommendations.append({'port': port, 'action': 'Vérifier le service réel et son chiffrement ; désactiver les accès en clair inutiles.'})
        if port in (445, 3389, 5432, 6379):
            recommendations.append({'port': port, 'action': 'Vérifier les accès, les mises à jour et les restrictions du pare-feu.'})
    report = {'tool': 'ticrisss-Audit', 'version': '0.2', 'target': args.target,
              'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'tcp': results, 'web': web, 'exposure': exposure, 'recommendations': recommendations,
              'limitations': ['Un port ouvert ne prouve pas une vulnérabilité.',
                              'Le service réel ne peut pas être déduit uniquement de son numéro de port.',
                              'Aucune recherche exhaustive de failles ni tentative de connexion.',
                              'HTTPS utilise la validation normale des certificats pour cette adresse IP.']}
    try:
        with report_path.open('x', encoding='utf-8') as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2)
    except OSError as exc:
        parser.exit(1, f'Impossible de créer le rapport : {exc}\n')
    print('Ports TCP ouverts : ' + (', '.join(map(str, opened)) or 'aucun parmi les ports testés'))
    print(f'Rapport : {report_path.resolve()}')


if __name__ == '__main__':
    main()
