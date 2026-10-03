#!/usr/bin/env python3
"""Convertit un rapport TI-LEX JSON en page HTML autonome, sans réseau."""
import argparse
import html
import json
from pathlib import Path


def render(report):
    if not isinstance(report, dict) or report.get('tool') != 'ticrisss-Audit':
        raise ValueError('Ce fichier ne contient pas un rapport ticrisss-Audit.')
    escape = lambda value: html.escape(str(value), quote=True)
    rows = ''.join('<tr><td>' + escape(item.get('port', '?')) + '</td><td>' +
                   escape(item.get('state', '?')) + '</td></tr>'
                   for item in report.get('tcp', []) if isinstance(item, dict))
    recommendations = ''.join('<li>Port ' + escape(item.get('port', '?')) + ': ' +
                              escape(item.get('action', '')) + '</li>'
                              for item in report.get('recommendations', []) if isinstance(item, dict))
    candidates = ''.join('<li>Port ' + escape(group.get('port', '?')) + ' — ' +
                         escape(item.get('path', '?')) + ': ' + escape(item.get('assessment', '')) + '</li>'
                         for group in report.get('exposure', []) if isinstance(group, dict)
                         for item in group.get('candidates', []) if isinstance(item, dict))
    return '''<!doctype html><html lang="fr"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>ticrisss — Rapport d’audit</title><style>
body{margin:0;background:#101827;color:#edf2f7;font:16px system-ui,sans-serif}
main{max-width:900px;margin:auto;padding:32px 20px}h1{color:#65dfcc}section{background:#1c283b;padding:20px;margin:20px 0;border-radius:12px}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #435069}li{margin:10px 0}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}p{line-height:1.6}small{color:#b7c7db}
</style><main><h1>ticrisss</h1><p>Cible : ''' + escape(report.get('target', '?')) + '''<br>Date UTC : ''' + escape(report.get('time_utc', '?')) + '''</p>
<p>Un port ouvert ou une réponse HTTP 200 n’est pas une preuve de vulnérabilité. Les pistes doivent être confirmées par le propriétaire du système.</p>
<section><h2>Ports testés</h2><table><tr><th>Port TCP</th><th>État</th></tr>''' + rows + '''</table></section>
<section><h2>Points à examiner</h2><ul>''' + (candidates or '<li>Aucune piste signalée par le module d’exposition. Cela ne prouve pas l’absence de fuite.</li>') + '''</ul></section>
<section><h2>Recommandations</h2><ul>''' + (recommendations or '<li>Aucune recommandation spécifique générée.</li>') + '''</ul></section>
<section><h2>Détails du rapport</h2><pre>''' + escape(json.dumps(report, ensure_ascii=False, indent=2)) + '''</pre></section>
<small>Rapport local autonome. Aucune ressource externe.</small></main></html>'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--output', type=Path, default=Path('ti-lex-report.html'))
    args = parser.parse_args()
    try:
        if args.report.stat().st_size > 2_000_000:
            raise ValueError('Rapport trop volumineux (maximum 2 Mo).')
        page = render(json.loads(args.report.read_text(encoding='utf-8')))
        with args.output.open('x', encoding='utf-8') as handle:
            handle.write(page)
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        parser.exit(1, f'Erreur : {exc}\n')
    print(f'Rapport HTML : {args.output.resolve()}')


if __name__ == '__main__':
    main()
