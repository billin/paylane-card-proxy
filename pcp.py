#!/usr/bin/env python

'''PayLane Card Authorisation Proxy Server'''

import sys

if sys.version_info[:2] != (2, 7):
    print >> sys.stderr, 'You must use Python version 2.7'
    sys.exit(1)

import ConfigParser
import SocketServer
import argparse
import base64
import json
import logging
import os
import os.path as p
import socket
import urlparse

from OpenSSL import SSL
from SimpleHTTPServer import SimpleHTTPRequestHandler
from BaseHTTPServer import HTTPServer

## globals
logger = None
client = None
tld = p.dirname(p.realpath(__file__))
default_config = './.pcp.cfg'
default_port = 9080

def relpath(f):
    return p.join(tld, f)

## setup imports
sys.path.append(relpath('passlib-1.5.3-py2.7.egg'))
sys.path.append(relpath('suds-0.4.1-py2.7.egg'))

## Egg imports
from suds.client import Client
from suds.transport.http import HttpAuthenticated
from passlib.apache import HtpasswdFile

## utils
class SOAPEncoder(json.JSONEncoder):
    def default(self, o):
       try:
            iterable = iter(o)
       except TypeError:
           pass
       else:
           return dict(iterable)
       return JSONEncoder.default(self, o) 


def htpasswd_check(user, pwd, pfile):
    return HtpasswdFile(pfile).verify(user, pwd)

def decode_resp(r):
    return json.dumps(r, cls=SOAPEncoder, sort_keys=True, indent=2)

def exit(code):
    global logger
    logging.shutdown()
    if logger:
        logger.info('Exiting.')
    else:
        print >> sys.stderr, 'Exiting.'
    sys.exit(code)

def croak(string):
    global logger
    logger.error(string)
    exit(1)

def parse_args():
    parser = argparse.ArgumentParser(description='PayLane Card Proxy. Copyright (c) Billin Sp. z o.o. 2012. All rights reserved.')
    parser.add_argument('-c', dest='config', type=str, help='Configuration file (default: %s)' % default_config,
            default=default_config)
    parser.add_argument('-p', dest='port', type=int, help='Port number')
    parser.add_argument('-d', dest='daemonize', action='store_true', help='Deamonize process after start')
    parser.add_argument('-l', dest='logfile', type=str, help='Log file')
    parser.add_argument('-v', dest='debug', action='store_const', const='True', default='False', help='Debugging output')
    parser.add_argument('--pid', dest='pidfile', type=str, help='Pid file')
    parser.add_argument('--plu', dest='paylane_user', type=str, help='Paylane user name')
    parser.add_argument('--ppf', dest='paylane_pass_f', type=str, help='Paylane password file')
    parser.add_argument('--wsdl', dest='paylane_wsdl', type=str, help='Paylane wsdl URL')
    parser.add_argument('--sslcrtkey', type=str, help='SSL certificate')
    parser.add_argument('--htpasswdf', type=str, help='HTTP authorization file (htpasswd format)')
    parser.add_argument('--certpassf', type=str, help='SSL certificate password file')
    return parser.parse_args()

class PCPHandler(SimpleHTTPRequestHandler):
    '''Main proxy request handler class'''
    def log_message(self, format, *args):
        global logger
        logger.info('%s - - [%s] %s' % (self.address_string(), 
            self.log_date_time_string(), format % args))

    def setup(self):
        self.connection = self.request
        self.rfile = socket._fileobject(self.request, 'rb', self.rbufsize)
        self.wfile = socket._fileobject(self.request, 'wb', self.wbufsize)

    def do_response(self, code, status, body=None):
        body = body or status
        self.send_response(code, status)
        if body.startswith('{'):
            ctype = 'application/json'
        else:
            ctype = 'text/html'
        self.send_header('Content-type', ctype)
        self.end_headers()
        self.wfile.write(body + "\n")

    def auth_card(self, **d):
        global client
        try:
            ccno=d['ccno']
            ccv=d['cvv']
            expy=d['expy']
            expm=d['expm']
            name=d['name']
            email=d['email']
            ip=d['ip']
            country=d['country']
            city=d['city']
            street=d['street']
            zipcode=d['zipcode']
            amount=d['amount']
            currency=d['currency']
            descr=d['descr']
        except KeyError as e:
            self.do_response(500, 'Argument parsing error', "{ 'ERROR': 'Parameter %s is not defined' }" % e)

        msp = client.factory.create('ns0:multi_sale_params')
        pm = {
                'card_data': { 'card_number': ccno,
                    'card_code': ccv,
                    'expiration_year': expy,
                    'expiration_month': expm,
                    'name_on_card': name
                    }
                }
        msp.payment_method = pm

        ci = {
                'email': email,
                'ip': ip,
                'address': {
                    'city': city,
                    'street_house': street,
                    'zip': zipcode,
                    'country_code': country
                    }
                }
        msp.customer = ci

        msp.amount = amount
        msp.currency_code = currency
        msp.product = descr
        msp.capture_later = True

        return decode_resp(client.service.multiSale(msp))

    def do_HEAD(self):
        self.do_response(200, 'OK', '')

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"PCP\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def auth_user(self):
        info = self.headers.getheader('Authorization')
        atype, adata = info.split(' ')
        if atype == 'Basic':
            adata_decoded = base64.b64decode(adata)
            user, password = adata_decoded.split(':')
            result = htpasswd_check(user, password, relpath(config.get('PCP', 'htpasswd_file')))
            if result:
                return (True, '')
            else:
                msg = 'Authentication for user %s failed' % user
                logger.error(msg)
                return (False, msg)
        else:
            msg = 'Authentication type %s it not supported' % atype
            logger.error(msg)
            return (False, msg)

    def do_POST(self):
        if self.headers.getheader('Authorization') == None:
            self.do_AUTHHEAD()
            self.wfile.write('No auth header received')
        else:
            auth_result, auth_msg = self.auth_user()
            if auth_result:
                length = int(self.headers.getheader('Content-Length'))
                query = urlparse.parse_qs(self.rfile.read(length))
                resp = self.auth_card(**query)
                resp_dict = eval(resp)

                if resp_dict.get('OK'):
                    self.do_response(200, 'OK', resp)
                else:
                    self.do_response(500, 'Gateway error', resp)
            else:
                    self.do_response(403, auth_msg)

    def do_GET(self):
        parsed = urlparse.urlparse(self.path)
        if parsed.path == '/auth':
            self.do_response(500, 'Authorize via POST only', '')
        else:
            self.do_response(404, 'Not found', "{ 'ERROR': 'Page not found', 'PATH': '%s' }" % self.path)

class SecureHTTPServer(HTTPServer):
    def __init__(self, server_address, HandlerClass):
        global config
        HTTPServer.__init__(self, server_address, HandlerClass)
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        fpem = relpath(config.get('PCP', 'ssl_cert_and_key_file'))
        ctx.use_privatekey_file (fpem)
        ctx.use_certificate_file(fpem)
        self.socket = SSL.Connection(ctx, socket.socket(self.address_family, self.socket_type))
        self.server_bind()
        self.server_activate()

    def shutdown_request(self,request): 
        request.shutdown()

def serve_http(port):
    global logger
    Handler = PCPHandler
    httpd = SecureHTTPServer(('', port), Handler)
    logger.info('Serving HTTPS at port %d', port)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        exit(0)

def main():
    global config, logger, client

    args = parse_args()

    ## read config
    config = ConfigParser.SafeConfigParser()
    config.add_section('PCP')
    args.config = p.expanduser(args.config)
    if p.exists(args.config):
        config.read(args.config)

    def getconf(name):
        try:
            return config.get('PCP', name)
        except:
            return None

    ## defaults
    args.port = int(args.port or getconf('port') or default_port)
    args.pidfile = args.pidfile or getconf('pidfile')
    args.logfile = args.logfile or getconf('logfile')

    def default_pass(name, pass_file):
        if args.__dict__[pass_file]:
            with open(args.__dict__[pass_file]) as passf:
                config.set('PCP', name, passf.read())

    def default_conf(name, cname=None):
        cname = cname or name
        if args.__dict__.has_key(name):
            if args.__dict__[name]:
                config.set('PCP', cname, args.__dict__[name])


    default_conf('paylane_user')
    default_pass('paylane_pass', 'paylane_pass_f')
    default_conf('paylane_wsdl')

    default_conf('htpasswdf', 'htpasswd_file')
    default_conf('ssl_cert_and_key_file', 'sslcrtkey')

    default_conf('debug')

    ## missing args check
    if not getconf('paylane_user'):
        croak('You must specify PayLane user name with either --plu option or paylane_user config value')

    if not getconf('paylane_pass'):
        croak('You must specify PayLane user password with either --ppf option or paylane_pass config value')

    if not getconf('ssl_cert_and_key_file'):
        croak('You must specify SSL certificate either with the --sslcrtkey option or ssl_cert_and_key_file config value')

    if not getconf('htpasswd_file'):
        croak('You must specify HTTP password file either with the --httpasswdf option or htpasswd_file')

    ## setup logging
    logger = logging.getLogger('PCP')
    logger.setLevel(logging.INFO)

    soap_logger = logging.getLogger('suds.client')
    soap_logger.setLevel(logging.INFO)

    if args.logfile:
        handler = logging.FileHandler(args.logfile)
        formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    else:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(levelname)-8s %(message)s')

    handler.setFormatter(formatter)

    logger.addHandler(handler)
    soap_logger.addHandler(handler)

    ## demonize
    if args.daemonize:
        if not args.logfile:
            croak('Specifying logfile is mandatory in daemonized mode')

        pid = os.fork()

        if pid > 0:
            exit(0)
        else:
            os.chdir('/')
            if not eval(getconf('debug')):
                sys.stdin.close()
                sys.stdout.close()
                sys.stderr.close()

    ## write pid
    if args.pidfile:
        with open(relpath(args.pidfile), 'w') as pidfile:
            pidfile.write(str(os.getpid()))

    ## setup PayLane com
    trans = HttpAuthenticated(username=getconf('paylane_user'), password=getconf('paylane_pass'))
    client = Client(getconf('paylane_wsdl'), transport=trans)

    serve_http(args.port)

if __name__ == '__main__':
    main()
