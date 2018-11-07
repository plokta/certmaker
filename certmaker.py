#! /usr/bin/env python3

import argparse
import hashlib
import itertools
import os
import sys
import time
from typing import List, Any, Union
from uuid import uuid4

# TODO: consider switching to cryptography module
from OpenSSL import crypto

# Globals and Defaults
NO_CN_SUBJECT_NAME_FIELDS = ["C", "ST", "L", "O", "OU", "SN", "GN", "initials", "title", "email", "serialNumber",
                           "pseudonym", "dnQualifier", "generationQualifier"]
SUBJECT_NAME_FIELDS = ["CN"] + NO_CN_SUBJECT_NAME_FIELDS
DEF_KEYTYPE = crypto.TYPE_RSA
DEF_KEYLENGTH = 2048
DEF_VALID_SINCE = 24 * 60 * 60 * 15  # valid since fifteen days ago; set to 0 for "valid from now on"
DEF_VALID_FOR = 60 * 60 * 24 * 365 * 3  # 3 years
DEF_HASHALG = "sha1"

class CertMaker:

    def __init__(self, cn=None, key=None, key_path=None, key_passwd=b"", ca_path=None, ca_key_path=None, ca_key_passwd=b""):
        self.crt_key = key  # a OpenSSL.crypto.Pkey() instance
        self.crt_key_path = key_path		# path to PEM key file
        self.crt_key_passwd = key_passwd 
        self.ca_path = ca_path			# path to CA cert PEM file
        self.ca_key_path = ca_key_path		# path to CA key PEM file
        self.ca_key_passwd = ca_key_passwd
        self.ca_crt = None
        self.ca_key = None

        # default values
        self.keytype = DEF_KEYTYPE
        self.keylength = DEF_KEYLENGTH
        self.validsince = DEF_VALID_SINCE
        self.validfor = DEF_VALID_FOR
        self.hashalg = DEF_HASHALG

        self.copy = None  # path to PEM cert, copy cert values, replace key
        self.kt = None

        # initialise subject attribs (mainly for setting through cli)
        for field in NO_CN_SUBJECT_NAME_FIELDS:
            setattr(self, field, None)
        self.CN = cn  # mandatory
        # list of subject attributes that will be excluded when copying from a template certificate
        self.rm_subj = []

        # shortcut for cli
        self.email = None

        self.serial = None
        self.ext = []
        # list of shortnames of extensions that will be excluded when copying from a template certificate
        self.rm_ext = []

        self.crl = None
        self.isCA = False

        self.certificate = crypto.X509()
        # TODO: we always set this to version 3, cause we use extensions. May be we should make edge cases possible
        # like having version 2 but including v3 extensions?
        self.certificate.set_version(2)  # set to version 3 (0x02) to enable x509v3 extensions

        self.cert_extensions = []

    def get_rand_serial(self):
        return int(uuid4())

    def set_serial(self, int_serial):
        self.certificate.set_serial_number(int_serial)

    def get_ca(self):
        #ca_crt = crypto.load_certificate(crypto.FILETYPE_PEM, open(self.ca_path).read())
        #ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.ca_key_path).read(), self.ca_key_passwd)
        ca_crt = crypto.load_certificate(crypto.FILETYPE_PEM, self.ca_path.read())
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, self.ca_key_path.read(), self.ca_key_passwd)
        return ca_crt, ca_key

    def gen_key(self):
        key = crypto.PKey()
        if self.kt is not None:
            # self.kt is set via cmdline and can only be RSA or DSA
            self.keytype = getattr(crypto, "TYPE_" + self.kt)
        key.generate_key(self.keytype, self.keylength)
        return key

    # subject and issuer are optional X509 certificate objects (i.e., required for authorityKeyIdentifier extensions)
    # Use cm.set_extension(b'subjectAltName', b'DNS:example.org', False) to set SANs;
    # see https://www.openssl.org/docs/manmaster/man5/x509v3_config.html#STANDARD-EXTENSIONS for more std extensions
    def set_extension(self, ext_name, ext_val, critical, subject=None, issuer=None):
        if type(critical) != bool:
            critical = critical.lower() in [b"true", b"1", b"yes"]
        self.cert_extensions.append(crypto.X509Extension(ext_name, critical, ext_val, subject, issuer))

    ####
    # based on: 
    # https://code.blindspotsecurity.com/trac/bletchley/browser/trunk/lib/bletchley/ssltls.py#L202
    #
    def delete_extensions(self):
        '''
        A dirty hack until this is implemented in pyOpenSSL. See:
        https://github.com/pyca/pyopenssl/issues/152
        '''
        from OpenSSL._util import lib as libssl

        for index in range(self.certificate.get_extension_count()):
                libssl.X509_delete_ext(self.certificate._x509, index)
        #XXX: memory leak.  supposed to free ext here
    #
    ####
    
    def extract_extensions(self):
        return [ self.certificate.get_extension(idx) for idx in range(self.certificate.get_extension_count())] 

    def set_subject(self, x509_subject):
        # overrides cn and all subject_dict values, e.g., to copy all values from an existing x509 subject
        self.certificate.set_subject(x509_subject)

    # applying prepared attributes and generate signature for toBeSignedCert
    def make_cert(self):
        # cert = crypto.X509()
        original_exts = []
        subject = crypto.X509().get_subject()

        if self.copy is None:
            # generate new cert from default values
            cert = self.certificate

            cert.gmtime_adj_notAfter(self.validfor)
            cert.gmtime_adj_notBefore(-self.validsince)
            cert.set_serial_number(self.serial or self.get_rand_serial())
        else:
            # read cert template from pem file and only replace key;
            # make a copy to ensure that all custom fields are kept
            self.certificate = crypto.load_certificate(crypto.FILETYPE_PEM, self.copy.read())
            cert = self.certificate
            # adjusting extensions becomes weird; first, we need to store the extensions from the original cert
            original_exts = self.extract_extensions()

            # then delete original extensions - using an unreliable hack, therefore the while loop
            while cert.get_extension_count() > 0:
                self.delete_extensions()
            # after issuer and subject have been determined, the original extensions will be merged with
            # new extensions from the commandline (to prevent duplicates which could invalidate the cert)

            original_subject = self.certificate.get_subject().get_components()
            for i in original_subject:
                if not i[0] in self.rm_subj:
                    setattr(subject, i[0].decode('ascii'), i[1])

        self.subject_dict = {field: getattr(self, field) for field in SUBJECT_NAME_FIELDS}

        for key, val in self.subject_dict.items():
            if val is not None:
                setattr(subject, key, val.encode('utf-8'))

        cert.set_subject(subject)

        if self.crt_key is None:
            if self.crt_key_path is not None:
                self.crt_key = crypto.load_privatekey(crypto.FILETYPE_PEM, self.crt_key_path.read(),
                                                      self.crt_key_passwd)
            else:
                self.crt_key = self.gen_key()

        cert.set_pubkey(self.crt_key)
        
        if self.ca_path is not None and self.ca_key_path is not None:
            # use provided ca_crt as issuer
            ca_crt, ca_key = self.get_ca()
        elif self.ca_crt is not None and self.ca_key is not None:
            ca_crt = self.ca_crt
            ca_key = self.ca_key
        else:
            # otherwise self sign generated cert
            ca_crt = cert
            ca_key = self.crt_key
        
        cert.set_issuer(ca_crt.get_subject())

        # In case we copied an existing cert, we merge the original extensions with user provided ones
        short_names = [ext_triple[0] for ext_triple in self.ext]
        for extension in original_exts:
            sn = extension.get_short_name()
            if not (sn in short_names or sn in self.rm_ext):
                self.cert_extensions.append(extension)
            elif sn in short_names:
                # keeps original order of copied extensions when adding cli provided ext
                # we also allow multi occurences of extensions
                for ee in self.ext:
                    if ee[0] == sn:
                        self.set_extension(*ee, subject=cert, issuer=ca_crt or cert)
                        self.ext.remove(ee)

        # prepare any (further) extensions
        for ext_triple in self.ext:
            self.set_extension(*ext_triple, subject=cert, issuer=ca_crt or cert)
        
        # really add the extension to the cert object
        cert.add_extensions(self.cert_extensions)
       
        cert.sign(ca_key, self.hashalg)
        
        self.certificate = cert

    def store_cert_and_key(self, path=None):
        # store key and cert in $(pwd)/domains/
        if path is None:
            path = os.path.join(os.path.dirname(__file__), "domains/")
        os.makedirs(path, exist_ok=True)

        key_path = path + self.subject_dict["CN"].replace('.', '_') + ".key"
        with open(key_path, "w") as domain_key:
            domain_key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, self.crt_key).decode('utf-8'))

        cert_path = path + self.subject_dict["CN"].replace('.', '_') + ".cert"
        with open(cert_path, "w") as domain_cert:
            domain_cert.write(crypto.dump_certificate(crypto.FILETYPE_PEM, self.certificate).decode('utf-8'))
        print("Stored cert as: ", cert_path)

    def get_cert_and_key(self, as_PEM):
        if as_PEM:
            return crypto.dump_certificate(crypto.FILETYPE_PEM, self.certificate), \
                   crypto.dump_privatekey(crypto.FILETYPE_PEM, self.crt_key)

        return self.certificate, self.crt_key


# (API) usage:
#  import certmaker
#  c = certgen.CertMaker(cn="new signing Cert", ca_path="./newCA.pem",ca_key_path="./newCA.key")
#  c.subject_dict = {'CN': 'new signing Cert', 'C': "DE", 'ST': "Nrw", 'L': "C<</>>ity", 'O': "HGI", 'OU': "NDS", 'emailAddress': "mail@example.com"}
#  c.set_extension(b'authorityInfoAccess',b'OCSP;URI:http://localhost:8888/ocsp2')
#  c.set_extension(b'basicConstraints',b'CA:FALSE')
#  c.set_extension(b'crlDistributionPoints',b'URI:http://localhost:8888/myca.crl2')
#  c.set_extension(b'keyUsage',b'digitalSignature,nonRepudiation')
#  c.make_cert()
#  ccrt, ckey = c.get_cert_and_key(True)
#  
#  with open('newCert.pem', 'w') as f: f.write(ccrt.decode('UTF-8'))
# ... 
# 1505
#  with open('newCert.key', 'w') as f: f.write(ckey.decode('UTF-8'))
# ... 
# 1708

def file_exists(filepath):
    return os.path.isfile(os.path.realpath(filepath))


def write_to_file(out, targetfilepath):
    rp = os.path.realpath(targetfilepath)
    if file_exists(targetfilepath):
        os.rename(rp, rp + ".bak")
        print("[*] - Moved existing file {} to {}".format(rp, rp + ".bak"))
    with open(rp, "w") as f:
        f.write(out)
    print("[+] - Created {}".format(rp))


def str_to_bytes(arg):

    return bytes(arg, 'ascii')

def make_parser():
    # argument parsing is a mess currently to get a somewhat meaningful helpmessage. apparently, argparse
    # is not the best fit for parsing a (mandatory) subcommand that can occur multiple times. consider to use click or just
    # add a manual help message in a future version.

    epilog_string ="""Example: Generate intermediate CA (issuer read from file) and a leaf cert with several extensions:

./certmaker.py cert -CN "Test-CA Subj" -isCA -ca_path ./ca-crt.pem -ca_key_path ./ca-key.pem \ 
    cert -CN "baz subject" -keylength 512 -email mail@example.com -OU OrgUnit \ 
      -crl https://foo.bar.baz/CRL \ 
      -ext authorityInfoAccess OCSP\;URI:http://ocsp.my.host/ False \ 
      -ext extendedKeyUsage codeSigning True \ 
      -ext 1.2.3333.44 'ASN1:UTF8String:Random content for custom extension with OID 1.2.3333.44' True
"""

    main_parser = argparse.ArgumentParser(epilog=epilog_string,formatter_class=argparse.RawDescriptionHelpFormatter,)
    subparsers = main_parser.add_subparsers(
        help="'cert' is the only (mandatory) subcommand and can occur multiple times. Use 'cert -h' to show options; ", )

    # we define the "cert" keyword as subcommand, to get an appropriate help/usage message - the cert keyword is always required
    # the "cert" subcommand is only used to split the commandline into separate cert configs
    # this way we can specify several "cert" configs on the cli that are used to generate certificate chains
    parser = subparsers.add_parser("cert", help="each certificate starts with the 'cert' keyword and uses all args up "
                                                "to the next 'cert' argument. Preceding cert will sign (i.e. be the "
                                                "issuer of) successing certs, unless the '-ca_path' argument is provided. "
                                                "The first cert will be self signed if '-ca_path' is not present.")
    optional = parser._action_groups.pop()  # Edited this line
    required = parser.add_argument_group('required arguments')

    # TODO: changed required to False for -copy option to work without overriding the CN
    required.add_argument("-CN", type=str, default=None, required=False,
                          help="each certificate needs a commonName (e.g., the domain or hostname). "
                          "special chars need to be escaped otherwise your shell eats them up.")
    for code in NO_CN_SUBJECT_NAME_FIELDS:
        optional.add_argument("-" + code, type=str,
                              help="subject attribute as in OpenSSL CLI; escape special chars!")
    optional.add_argument("-rm_subj", nargs="*", type=str_to_bytes, help="space separated subject attribute to exclude from being copied "
                                                      "if a template cert is provided via the -copy option.", default=[])
    optional.add_argument("-ca_path", type=argparse.FileType('r'), help="path to the issuer certificate in PEM format. "
                                                                        "The preceding cert will be used as Issuer if ca_path is not given. "
                                                                        "The first cert on cmdline will be self-signed, if no ca_path is given.")
    optional.add_argument("-ca_key_path", type=argparse.FileType('r'),
                          help="path to the issuer key in PEM format, required if ca_path is given.")
    optional.add_argument("-ca_key_passwd", type=str, help="the keyfile password, if encrypted")

    optional.add_argument("-hashalg", type=str,
                          help="digest method to use for signing the tbs cert, e.g. 'sha1', 'sha256', "
                               "'md5'. Default is sha1", default="sha1")

    optional.add_argument("-crt_key_path", type=argparse.FileType('r'),
                          help="path to PEM formatted key to use for this cert")
    optional.add_argument("-crt_key_passwd", type=str, help="the keyfile password, if encrypted")

    optional.add_argument("-copy", type=argparse.FileType('r'), help="use provided PEM cert as template but replace"
                                                                     " key (self-sign, if first cert on cli and -ca_crt not given)")
    # extensions
    optional.add_argument("-ext", action='append', type=str_to_bytes, nargs=3, metavar=("extNAME", "extVALUE", "CRIT"),
                          default=[],
                          help="to add an x509v3 Extension such as 'subjectAltNam' enter the name, "
                               "value, and critical-flag separated by space like this: "
                               "'-ext subjectAltName DNS:http://example.com\;IP:1.2.3.4 False' "
                               "Only 'False' and 'True' are permitted for critical-flag."
                               " See https://www.openssl.org/docs/manmaster/man5/x509v3_config.html#STANDARD-EXTENSIONS"
                               " for available syntax")
    optional.add_argument("-rm_ext", nargs="*", default=[], type=str_to_bytes,
                          help="space separated shortnames of extensions that won't be copied from a "
                               "template cert provided with the -copy option")
    # shortcuts for frequent extensions
    optional.add_argument("-crl", type=str, help="the URL of the CRL distribution point. Setting CRL Fullname etc is currently not supported")
    optional.add_argument("-isCA", action='store_true',
                          help="if set, the critical extension 'basicConstraints:CA:TRUE' is added.")
    # TODO: add SANS extension shortcut
    optional.add_argument("-sans", nargs="*", type=str, default=None, help="space separated list of SubjectAlternativenames, e.g. "
                                                             "'-sans DNS:example.com DNS:www.example.com email:mail@mail.example.com'")

    optional.add_argument("-aia", type=str, nargs="*", default=None,
                          help="Space separted list of AuthorityInformationAccess entries, e.g.,"
                               " '-aia OCSP\;URI:http://ocsp.example.com/ caIssuers\;URI:http://ca.example.com/ca.html'"
                               " see https://www.openssl.org/docs/manmaster/man5/x509v3_config.html#STANDARD-EXTENSIONS for syntax")


    optional.add_argument("-validsince", type=int, help="number of seconds since when this cert has been valid. "
                                                        "Default is 0 (i.e., cert is valid from 'now' on)")
    optional.add_argument("-validfor", type=int, help="number of seconds until this certificate shall expire. "
                                                      "Default is 2592000 = 30days")

    optional.add_argument("-kt", choices=["RSA", "DSA"], help="set the keytype to use. default is RSA", default="RSA")
    optional.add_argument("-keylength", type=int, help="keylength in bits, default is 2048", default=2048)
    optional.add_argument("-serial", type=int, help="the serial number for this cert. default is a random number")

    parser._action_groups.append(optional)

    return main_parser


if __name__ == '__main__':

    cmdline = sys.argv[1:]

    parser = make_parser()
    if len(cmdline) == 0 or cmdline[0] != "cert":
        parser.print_help()
        parser.exit()

    # split cmdline, keep the "cert" keyword as trigger for the subcommand parser
    certconfigs = []
    for x, y in itertools.groupby(cmdline, lambda z: z == "cert"):
        if x: certconfigs.append([])
        certconfigs[-1].extend(y)
    #print(repr(certconfigs))

    # prepare certmaker objects for each config parsed from the cmdline
    certs = [CertMaker() for config in certconfigs]

    # generate the actual certificates
    for i in range(len(certs)):
        args = parser.parse_args(certconfigs[i])
        if not(args.CN or args.copy):
            sys.stderr.write("[!] Error: -CN must be set unless -copy is used to read a template "
                             "certificate: \n\t{!s}\n".format(certconfigs[i]))
            #parser.print_help()
            sys.exit(1)

        # 'parser.parse_args(certconfigs[i], certs[i])' would set all args that are not provided
        # on cli to "None". Therefore we can not use certs[i] as the parser-namespace, because we want to re-use the
        # defaults set in the CertMaker class (for API usage).
        # We work around this using setattr:
        for k,v in vars(args).items():
            if v is not None and k not in args.rm_subj:
                setattr(certs[i], k, v)
        #print(vars(certs[i]))

        current = certs[i]
        if i > 0:
            current.ca_crt = certs[i-1].certificate
            current.ca_key = certs[i-1].crt_key

        # check extension shortcuts (crl, isCA, sans, aia) and set accordingly; fill up with default vals for critical flag
        if current.isCA:
            current.ext.append([b"basicConstraints", b"CA:TRUE", "True"])
        if current.crl is not None:
            current.ext.append([b"crlDistributionPoints", str_to_bytes("URI:" + current.crl), "False"])
        if args.aia is not None:
            current.ext.append([b"authorityInfoAccess", str_to_bytes(",".join(args.aia).replace(" ", "")), "False"])
        if args.sans is not None:
            current.ext.append([b"subjectAltName", str_to_bytes(",".join(args.sans).replace(" ", "")), "False"])

        # this is where the TBS-Cert is actually generated and signed
        current.make_cert()
        # current.get_cert_and_key(True)

        # get a new parser for every cert command to prevent collisions when using action='append' as in the -ext option
        parser = make_parser()

    # dump all PEM certs and keys, leaf cert first
    for c in certs[::-1]:
        cc, k = c.get_cert_and_key(True)
        print(cc.decode("UTF-8"))
        print(k.decode("UTF-8"))
