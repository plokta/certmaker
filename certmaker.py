#! /usr/bin/env python3

import argparse
import hashlib
import itertools
import os
import sys
import time
from uuid import uuid4

# TODO: consider switching to cryptography module
from OpenSSL import crypto


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
        self.keytype = crypto.TYPE_RSA
        self.keylength = 2048
        self.validsince = 0  # now
        self.validfor = 60 * 60 * 24 * 30  # 30 days
        self.hashalg = "sha1"

        self.kt = None

        # make subject attribs available (mainly for argparse)
        self.CN = cn  # mandatory
        self.C = self.ST = self.L = self.O = self.OU = None

        # shortcut, mainly for commandline
        self.email = None

        self.serial = None
        self.ext = []
        self.crl = None
        self.isCA = False

        # self.cert = None
        self.certificate = crypto.X509()
        # TODO: we always set this to version 3, cause we use extensions. May be we should make edge cases possible
        # like having version 2 but including v3 extensions?
        self.certificate.set_version(2)  # set to version 3 (0x02) to enable x509v3 extensions

        # Use cm.set_extension(b'subjectAltName', b'DNS:example.org', False) to set SANs;
        # see https://www.openssl.org/docs/manmaster/man5/x509v3_config.html#STANDARD-EXTENSIONS for more std extensions
        self.cert_extensions = []

    # TODO: certificate faking:
    # these values and eventually generate new cert out of these
    def fakecert(certificate):
        # only set new key and re-sign, then return the new fakecert
        pass

    # TODO: copy a cert and modify some values
    def tamper(cert):
        pass

    # deprecated and not used anymore
    def get_serial(self):
        hashfunc = hashlib.sha1()
        # val = self.subject_dict["CN"] + "_" + str(time.time())
        val = self.certificate.get_subject().CN + "_" + str(time.time())
        hashfunc.update(val.encode("utf-8"))
        # print(type(hashfunc.digest()))
        return int.from_bytes(hashfunc.digest(), byteorder="big")

    def get_rand_serial(self):
        return int(uuid4())

    def set_serial(self, int_serial):
        self.certificate.set_serial_number(int_serial)

    def get_ca(self):
        ca_crt = crypto.load_certificate(crypto.FILETYPE_PEM, open(self.ca_path).read())
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.ca_key_path).read(), self.ca_key_passwd)
        return ca_crt, ca_key

    def gen_key(self):
        key = crypto.PKey()
        if self.kt is not None:
            # self.kt is set via cmdline and can only be RSA or DSA
            self.keytype = getattr(crypto, "TYPE_" + self.kt)
        key.generate_key(self.keytype, self.keylength)
        return key

    # TODO: add some default extensions (like BasicConstraints CA:False, SANS, ...) or
    # at least simple workarounds to add these
    # example:
    # cm.set_extension(b'basicConstraints', b'CA:TRUE', True)
    # subject and issuer are optional X509 certificate objects (i.e., required for authorityKeyIdentifier extensions)
    def set_extension(self, ext_name, ext_val, critical, subject=None, issuer=None):
        if type(critical) != bool:
            critical = critical.lower() in [b"true", b"1", b"yes"]
        self.cert_extensions.append(crypto.X509Extension(ext_name, critical, ext_val, subject, issuer))

    def set_subject(self, x509_subject):
        # overrides cn and all subject_dict values, e.g., to copy all values from an existing x509 subject
        self.certificate.set_subject(x509_subject)

    # applying prepared attributes and generate signature for toBeSignedCert
    def make_cert(self):
        # cert = crypto.X509()
        cert = self.certificate

        self.subject_dict = {"CN": self.CN, "C": self.C, "ST": self.ST, "L": self.L, "O": self.O, "OU": self.OU,
                             "emailAddress": self.email}

        if self.subject_dict is not None:
            for key, val in self.subject_dict.items():
                if val is not None:
                    setattr(cert.get_subject(), key, val)

        #if self.email is not None:
        #    cert.get_subject().emailAddress = self.email

        cert.gmtime_adj_notAfter(self.validfor)
        cert.gmtime_adj_notBefore(-self.validsince)

        if self.crt_key is None:
            if self.crt_key_path is not None:
                self.crt_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.crt_key_path).read(),
                                                      self.crt_key_passwd)
            else:
                self.crt_key = self.gen_key()

        cert.set_pubkey(self.crt_key)

        cert.set_serial_number(self.serial or self.get_rand_serial())

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

        cert.add_extensions(self.cert_extensions)

        cert.sign(ca_key, self.hashalg)
        
        # TODO: add method to change any attribute after signature has been applied;
        #  e.g, to use invalid pubkey, set a different subjet etc. That would
        # of course invalidate the certificate's signature but should still be possible
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


def str_to_bytes(arg):
    # attempted to inject NUL bytes failed due to the underlying openssl lib cutting strings on NUL.
    # perhaps one could edit the ASN1 structure of the certificate before signing to generate such certs?
    # edit: tested with python "cryptography" module, has the same problem (cutting commonname at first NUL byte
    #
    # make sure NUL bytes are correctly added
    #arg = arg.replace('\\x00', '\0')
    return bytes(arg, 'ascii')

if __name__ == '__main__':

    # argument parsing is a mess currently to get a somewhat meaningful helpmessage. apperently, argparse
    # is not the best fit for parsing a (mandatory) subcommand that can occur multiple times. consider to use click or just
    # add a manual help message in a future version.
    main_parser = argparse.ArgumentParser()
    subparsers = main_parser.add_subparsers(help="'cert' is the only (mandatory) subcommand and can occure multiple times. Use 'cert -h' to show options; ",)

    # we define the "cert" keyword as subcommand, to get an appropriate help/usage message - the cert keyword is always required
    # the "cert" subcommand is only used to split the commandline into separate cert configs
    # this way we can specify several "cert" configs on the cli that are used to generate certificate chains
    parser = subparsers.add_parser("cert", help="each certificate starts with the 'cert' keyword and uses all args up "
                                                "to the next 'cert' argument. Preceding cert will sign (i.e. be the "
                                                "issuer of) successing certs, unless the '-ca_path' argument is provided. "
                                                "The first cert will be self signed if '-ca_path' is not present.")
    optional = parser._action_groups.pop()  # Edited this line
    required = parser.add_argument_group('required arguments')

    required.add_argument("-CN", type=str_to_bytes, help="each certificate needs a commonName (e.g., the domain or hostname). "
                                              "special chars need to be escaped otherwise your shell eats them up.", required=True)

    for code in ["C", "ST", "L", "O", "OU", "email"]:
        optional.add_argument("-" + code, type=str_to_bytes, help="subject attribute as used in OpenSSL; escape special chars!")

    optional.add_argument("-ca_path", type=argparse.FileType('r'), help="path to the issuer certificate in PEM format. "
                                                                      "The preceding cert will be used as Issuer if ca_path is not given. "
                                                                      "The first cert on cmdline will be self-signed, if no ca_path is given.")
    optional.add_argument("-ca_key_path", type=argparse.FileType('r'), help="path to the issuer key in PEM format, required if ca_path is given.")
    optional.add_argument("-ca_key_passwd", type=str, help="the keyfile password, if encrypted")

    optional.add_argument("-hashalg", type=str, help="digest method to use for signing the tbs cert, e.g. 'sha1', 'sha256', "
                                                   "'md5'. Default is sha1", default="sha1")

    optional.add_argument("-crt_key_path", type=argparse.FileType('r'), help="path to PEM formatted key to use for this cert")
    optional.add_argument("-crt_key_passwd", type=str, help="the keyfile password, if encrypted")

    # extensions
    optional.add_argument("-ext", action='append', type=str, nargs=3, metavar=("extNAME", "extVALUE", "CRIT"),default=[],
                        help="to add an x509v3 Extension such as 'subjectAltNam' enter the name, "
                            "value, and critical-flag separated by space like this: "
                            "'-ext subjectAltName DNS:http://example.com\;IP:1.2.3.4 False' "
                            "Only 'False' and 'True' are permitted for critical-flag."
                            " See https://www.openssl.org/docs/manmaster/man5/x509v3_config.html#STANDARD-EXTENSIONS"
                            " for available syntax")
    # shortcuts for frequent extensions
    optional.add_argument("-crl", type=str, help="the URL of the CRL distribution point")
    optional.add_argument("-isCA", action='store_true', default=False, help="if set, the critical extension 'basicConstraints:CA:TRUE' is added.")
#    parser.add_argument("-aia", type=str, help="authority information access, see https://www.openssl.org/docs/manmaster/man5/x509v3_config.html#STANDARD-EXTENSIONS for syntax")
    optional.add_argument("-validsince", type=int, help="number of seconds since when this cert has been valid. "
                                                      "Default is 0 (i.e., cert is valid from 'now' on)")
    optional.add_argument("-validfor", type=int, help="number of seconds until this certificate shall expire. "
                                                    "Default is 2592000 = 30days")

    optional.add_argument("-kt", choices=["RSA", "DSA"], help="set the keytype to use. default is RSA", default="RSA")
    optional.add_argument("-keylength", type=int, help="keylength in bits, default is 2048", default=2048)
    optional.add_argument("-serial", type=int, help="the serial number for this cert. default is a random number")

    parser._action_groups.append(optional)

    cmdline = sys.argv[1:]

    if len(cmdline) == 0 or cmdline[0] != "cert":
        main_parser.print_help()
        main_parser.exit()

    # debugging
    # print(repr(cmdline))
    #cmdline = ['cert', '-CN', 'foo bar subj', 'cert', '-CN', 'bazn\'">><h\\oh', '-ext', 'basicConstraints', 'CA:FALSE', 'True', '-ext', 'authorityInfoAccess', 'OCSP;URI:http://ocsp.my.host/', 'False']

    # split cmdline to have lists of arguments for each certificate; removes the 'cert' keywords
    #certconfigs = [list(y) for x,y in itertools.groupby(cmdline, lambda z: z == "cert") if not x]

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
        # subparser such as 'parser.parse_args(certconfigs[i], certs[i])' would set all args that are not provided
        # on cli to "None". Therefore we can not use certs[i] as the parser-namespace, because we want to re-use the
        # defaults set in the CertMaker class (for API usage).
        # We work around this using setattr:
        args = main_parser.parse_args(certconfigs[i])
        #print(vars(args))
        for k,v in vars(args).items():
            if v is not None:
                setattr(certs[i], k, v)
        #main_parser.parse_args(certconfigs[i], certs[i])
        #print(vars(certs[i]))

        current = certs[i]
        if i > 0:
            current.ca_crt = certs[i-1].certificate
            current.ca_key = certs[i-1].crt_key

        # check extension shortcuts (crl, isCA,) and set accordingly; fill up with default vals for critical flag
        if current.isCA:
            current.ext.append(["basicConstraints", "CA:TRUE", "True"])
        if current.crl is not None:
            current.ext.append(["crlDistributionPoints", "URI:" + current.crl, "False"])

        # add explicitly spelled out extensions
        for ext_triple in current.ext[::]:
            # TODO: the use of 'issuer=current.ca_crt or current'  may cause trouble, double check and test
            current.set_extension(*[e.encode('ascii') for e in ext_triple], subject=current.certificate, issuer=current.ca_crt or current.certificate)

        # this is where the TBS-Cert is actually generated and signed
        current.make_cert()
        # current.get_cert_and_key(True)

    # dump all PEM certs and keys, leaf cert first
    for c in certs[::-1]:
        cc, k = c.get_cert_and_key(True)
        print(cc.decode("UTF-8"))
        print(k.decode("UTF-8"))

        # Usage example including one CA cert and several extensions
        # ./certmaker.py cert -CN "foo bar subj" -isCA cert -CN bazn\'\"\>\>\<h\\oh -ext authorityInfoAccess OCSP\;URI:http://ocsp.my.host/ FalseTrue -keylength 512 -crl https://foo.bar.baz/CRL -email sergio.ramos@caramba.ca -OU NDS -ST NRW -ext  extendedKeyUsage codeSigning,1.2.3.4 True -ext  1.2.3.4.5.6 DER:01:02:03:04 True
