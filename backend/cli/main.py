import click
import json
import os
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
CONFIG_DIR = Path.home() / '.nmap-ai'
CONFIG_FILE = CONFIG_DIR / 'config.json'
API_BASE = 'http://localhost:8000/api/v1'


def load_config():
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def save_config(config):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def get_token():
    return load_config().get('token')


def api(method, path, data=None, token=None):
    url = API_BASE + path
    hdrs = {'Content-Type': 'application/json'}
    if token:
        hdrs['Authorization'] = 'Bearer ' + token
    b = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=b, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        console.print('[red]Error: ' + e.read().decode() + '[/red]')
        sys.exit(1)
    except urllib.error.URLError:
        console.print('[red]API not reachable[/red]')
        sys.exit(1)


@click.group()
def cli():
    pass


@cli.command()
@click.option('--username', '-u', prompt=True)
@click.option('--password', '-p', prompt=True, hide_input=True)
def login(username, password):
    r = api('POST', '/auth/login', {'username': username, 'password': password})
    save_config({'token': r['access_token'], 'username': username})
    console.print('[green]Logged in[/green]')


@cli.group()
def target():
    pass


@target.command()
@click.argument('value')
@click.option('--name', '-n')
@click.option('--project')
def add(value, name, project):
    d = {'name': name or value, 'target_value': value, 'target_type': 'ip', 'project': project}
    r = api('POST', '/targets', d, get_token())
    console.print('[green]Target ' + str(r['id']) + ': ' + r['name'] + ' (' + r['target_value'] + ')[/green]')


@target.command('list')
def list_targets():
    r = api('GET', '/targets', token=get_token())
    if not r:
        console.print('[yellow]No targets[/yellow]')
        return
    t = Table(title='Targets')
    t.add_column('ID', style='cyan')
    t.add_column('Name', style='green')
    t.add_column('Value')
    t.add_column('Type', style='yellow')
    t.add_column('Project', style='blue')
    for x in r:
        t.add_row(str(x['id']), x.get('name', ''), x.get('target_value', ''), x.get('target_type', ''), x.get('project', '') or '')
    console.print(t)


@target.command()
@click.argument('tid', type=int)
def remove(tid):
    api('DELETE', '/targets/' + str(tid), token=get_token())
    console.print('[green]Target ' + str(tid) + ' deleted[/green]')


@target.command()
@click.argument('value')
def validate(value):
    r = api('POST', '/targets/validate', {'target_value': value}, get_token())
    if r.get('valid'):
        console.print('[green]Valid[/green]')
    else:
        console.print('[red]Invalid: ' + r.get('reason', '?') + '[/red]')


@cli.group()
def scan():
    pass


@scan.command()
@click.option('--target', '-t', 'tid', type=int, required=True)
@click.option('--profile', '-p', 'pname', default='quick')
@click.option('--name', '-n')
def launch(tid, pname, name):
    profs = api('GET', '/scan-profiles', token=get_token())
    pid = None
    for p in profs:
        if p['name'].lower() == pname.lower():
            pid = p['id']
            break
    if not pid:
        console.print('[red]Profile not found[/red]')
        return
    d = {'name': name or 'Scan-' + str(tid), 'target_id': tid, 'profile_id': pid}
    r = api('POST', '/scans', d, get_token())
    console.print('[green]Launched scan ID ' + str(r['id']) + '[/green]')


@scan.command('list')
def list_scans():
    r = api('GET', '/scans', token=get_token())
    if not r:
        console.print('[yellow]No scans[/yellow]')
        return
    t = Table(title='Scan Jobs')
    t.add_column('ID', style='cyan')
    t.add_column('Name', style='green')
    t.add_column('Status', style='yellow')
    t.add_column('Progress')
    for x in r:
        t.add_row(str(x['id']), x.get('name', ''), x.get('status', '?'), '{:.0%}'.format(x.get('progress', 0)))
    console.print(t)


@scan.command()
@click.argument('sid', type=int)
def status(sid):
    r = api('GET', '/scans/' + str(sid) + '/status', token=get_token())
    console.print('Scan ' + str(sid) + ': ' + r['status'] + ' ({:.0%})'.format(r.get('progress', 0)))


@scan.command()
@click.argument('sid', type=int)
def results(sid):
    r = api('GET', '/scans/' + str(sid) + '/results', token=get_token())
    if not r:
        console.print('[yellow]No results[/yellow]')
        return
    hosts = r.get('hosts', [])
    console.print('[bold]Scan ' + str(sid) + ':[/bold] ' + str(r.get('host_count', 0)) + ' hosts, ' + str(r.get('port_count', 0)) + ' ports')
    for h in hosts:
        ip = h.get('ip', '?')
        hn = h.get('hostname', '?')
        lat = str(h.get('latency_ms', '?'))
        console.print('[cyan]' + ip + '[/cyan] (' + hn + ') ' + lat + 'ms')
        for p in h.get('ports', []):
            svc = (p.get('service_name', '') + ' ' + p.get('service_version', '')).strip()
            console.print('  ' + str(p.get('port', '')) + '/' + p.get('protocol', '') + ' ' + p.get('state', '') + ' ' + svc)


@scan.command()
@click.argument('sid', type=int)
def cancel(sid):
    api('POST', '/scans/' + str(sid) + '/cancel', token=get_token())
    console.print('[green]Cancelled ' + str(sid) + '[/green]')


@scan.command()
@click.argument('sid', type=int)
def pause(sid):
    api('POST', '/scans/' + str(sid) + '/pause', token=get_token())
    console.print('[green]Paused ' + str(sid) + '[/green]')


@scan.command()
@click.argument('sid', type=int)
def resume(sid):
    api('POST', '/scans/' + str(sid) + '/resume', token=get_token())
    console.print('[green]Resumed ' + str(sid) + '[/green]')


@scan.command()
@click.argument('sid', type=int)
def watch(sid):
    while True:
        r = api('GET', '/scans/' + str(sid) + '/status', token=get_token())
        pct = '{:.0%}'.format(r.get('progress', 0))
        console.print('\rStatus: ' + r['status'] + ' Progress: ' + pct, end='')
        if r['status'] in ('completed', 'failed', 'cancelled'):
            break
        time.sleep(2)
console.print()

@cli.group()
def profile():
    pass


@profile.command('list')
def list_profiles():
    r = api('GET', '/scan-profiles', token=get_token())
    if not r:
        console.print('[yellow]No profiles[/yellow]')
        return
    t = Table(title='Scan Profiles')
    t.add_column('ID', style='cyan')
    t.add_column('Name', style='green')
    t.add_column('Ports')
    t.add_column('Type', style='yellow')
    t.add_column('Built-in')
    for x in r:
        t.add_row(str(x['id']), x['name'], x.get('ports', ''), x.get('scan_type', ''), '*' if x.get('is_builtin') else '')
    console.print(t)


@cli.group()
def ai():
    pass


@ai.command()
@click.argument('sid', type=int)
def summarize(sid):
    r = api('POST', '/ai/summarize/' + str(sid), token=get_token())
    console.print(Panel(r.get('summary', ''), title='Scan ' + str(sid) + ' Summary'))


@ai.command()
@click.argument('sid', type=int)
def risk(sid):
    scores = api('POST', '/ai/risk-score/' + str(sid), token=get_token())
    if not scores:
        console.print('[yellow]No scores[/yellow]')
        return
    t = Table(title='Risk Scores')
    t.add_column('Host', style='cyan')
    t.add_column('Port')
    t.add_column('Score')
    t.add_column('Severity')
    for s in scores:
        if not s.get('port_id'):
            continue
        t.add_row(s.get('host_ip', '?'), str(s.get('port', '')), str(s.get('score', 0)), s.get('severity', ''))
    console.print(t)


@ai.command()
@click.argument('sid1', type=int)
@click.argument('sid2', type=int)
def compare(sid1, sid2):
    r = api('POST', '/ai/compare', {'scan_job_id_1': sid1, 'scan_job_id_2': sid2}, get_token())
    console.print(Panel(r.get('summary', ''), title='Comparison'))
    if r.get('new_ports'):
        console.print('[red]New: ' + str(len(r['new_ports'])) + '[/red]')
    if r.get('removed_ports'):
        console.print('[green]Closed: ' + str(len(r['removed_ports'])) + '[/green]')


@ai.command()
@click.argument('sid', type=int)
def recommend(sid):
    r = api('POST', '/ai/recommend/' + str(sid), token=get_token())
    if not r:
        console.print('[yellow]No recommendations[/yellow]')
        return
    for x in r:
        console.print('[P' + str(x.get('priority', 3)) + '] ' + x['title'])


@ai.command()
@click.argument('sid', type=int)
@click.argument('question')
def query(sid, question):
    r = api('POST', '/ai/query', {'query': question, 'scan_job_id': sid}, get_token())
    console.print(Panel(r.get('answer', ''), title='Q: ' + question))


@cli.command()
@click.argument('sid', type=int)
@click.option('--format', '-f', 'fmt', default='json')
def export(sid, fmt):
    from urllib.request import urlopen, Request
    url = API_BASE + '/exports/' + str(sid) + '?format=' + fmt
    req = Request(url, headers={'Authorization': 'Bearer ' + get_token()})
    try:
        d = urlopen(req).read()
        Path('scan_' + str(sid) + '.' + fmt).write_bytes(d)
        console.print('[green]Exported to scan_' + str(sid) + '.' + fmt + '[/green]')
    except Exception as e:
        console.print('[red]' + str(e) + '[/red]')


if __name__ == '__main__':
    cli()
