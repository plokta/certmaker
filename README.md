# CertMaker 

A lightweight wrapper around `pyOpenSSL` to facilitate certificate generation from the commandline.

## Generate Certificates and Certificate-Chains
Quickly generating a highly customized certificate chain is not really an every-day task. However, if one needs to do so, common tools are not exactly fit for the purpose. 
Of course one can fiddle around with the OpenSSL CLI tool to create special certificates but that tends to be, well, fiddly. This is where **CertMaker** comes to the rescue. As an example, to generate a self-signed certificate with the subject's CommonName set to John Doe, simply run:

```
./certmaker.py  cert -CN 'John Doe'
```
Generating a certificate chain is as easy as running:

```
./certmaker.py cert -CN RootCA -isCA cert -CN JohnDoe
```

## Installation

`CertMaker` is a Python3 script which uses`pyOpenSSL` internally. Other than that, only standardlibrary modules are used. To install `pyOpenSSL` on a Debian based distribution run

```
sudo apt-get install python3-openssl
```

Alternatively, you may install `pip3` using `apt-get install python3-pip` and run `sudo -H pip3 install pyOpenSSL`. This may require to manually install `libssl-dev` beforehand.


## Usage
As already shown above, simply running `./certmaker.py cert -CN "Test Subject"` will generate a self signed certificate where subject = issuer = "Test Subject". Default values are applied to all other required values such as key (random RSA Key with 2048 bit length is generated automatically), validity period, serial number (random), and so on...

Calling for help with `./certmaker -h` will only hint at the subcommand `cert` and provide a rather complex example:

```
./certmaker.py -h
usage: certmaker.py [-h] {cert} ...

positional arguments:
  {cert}      'cert' is the only (mandatory) subcommand and can occure
              multiple times. Use 'cert -h' to show options;
    cert      each certificate starts with the 'cert' keyword and uses all
              args up to the next 'cert' argument. Preceding cert will sign
              (i.e. be the issuer of) successing certs, unless the '-ca_path'
              argument is provided. The first cert will be self signed if
              '-ca_path' is not present.

optional arguments:
  -h, --help  show this help message and exit

Example: Generate intermediate CA (issuer read from file) and a leaf cert with several extensions:

./certmaker.py cert -CN "Test-CA Subj" -isCA -ca_path ./ca-crt.pem -ca_key_path ./ca-key.pem \ 
    cert -CN "baz subject" -keylength 512 -email mail@example.com -OU OrgUnit \ 
      -crl https://foo.bar.baz/CRL \ 
      -ext authorityInfoAccess OCSP\;URI:http://ocsp.my.host/ False \ 
      -ext  extendedKeyUsage codeSigning True \ 
      -ext 1.2.3333.44 'ASN1:UTF8String:Random content for custom extension with OID 1.2.3333.44' True

```

To get information about `cert` command's options, run `./certmaker.py cert -h`:

```
./certmaker.py cert -h
usage: certmaker.py cert [-h] -CN CN [-C C] [-ST ST] [-L L] [-O O] [-OU OU]
                         [-email EMAIL] [-ca_path CA_PATH]
                         [-ca_key_path CA_KEY_PATH]
                         [-ca_key_passwd CA_KEY_PASSWD] [-hashalg HASHALG]
                         [-crt_key_path CRT_KEY_PATH]
                         [-crt_key_passwd CRT_KEY_PASSWD]
                         [-ext extNAME extVALUE CRIT] [-crl CRL] [-isCA]
                         [-validsince VALIDSINCE] [-validfor VALIDFOR]
                         [-kt {RSA,DSA}] [-keylength KEYLENGTH]
                         [-serial SERIAL]

required arguments:
  -CN CN                each certificate needs a commonName (e.g., the domain
                        or hostname). special chars need to be escaped
                        otherwise your shell eats them up.

optional arguments:
  -h, --help            show this help message and exit
  -C C                  subject attribute as used in OpenSSL; escape special
                        chars!
  -ST ST                subject attribute as used in OpenSSL; escape special
                        chars!
  -L L                  subject attribute as used in OpenSSL; escape special
                        chars!
  -O O                  subject attribute as used in OpenSSL; escape special
                        chars!
  -OU OU                subject attribute as used in OpenSSL; escape special
                        chars!
  -email EMAIL          subject attribute as used in OpenSSL; escape special
                        chars!
  -ca_path CA_PATH      path to the issuer certificate in PEM format. The
                        preceding cert will be used as Issuer if ca_path is
                        not given. The first cert on cmdline will be self-
                        signed, if no ca_path is given.
  -ca_key_path CA_KEY_PATH
                        path to the issuer key in PEM format, required if
                        ca_path is given.
  -ca_key_passwd CA_KEY_PASSWD
                        the keyfile password, if encrypted
  -hashalg HASHALG      digest method to use for signing the tbs cert, e.g.
                        'sha1', 'sha256', 'md5'. Default is sha1
  -crt_key_path CRT_KEY_PATH
                        path to PEM formatted key to use for this cert
  -crt_key_passwd CRT_KEY_PASSWD
                        the keyfile password, if encrypted
  -ext extNAME extVALUE CRIT
                        to add an x509v3 Extension such as 'subjectAltNam'
                        enter the name, value, and critical-flag separated by
                        space like this: '-ext subjectAltName
                        DNS:http://example.com\;IP:1.2.3.4 False' Only 'False'
                        and 'True' are permitted for critical-flag. See https:
                        //www.openssl.org/docs/manmaster/man5/x509v3_config.ht
                        ml#STANDARD-EXTENSIONS for available syntax
  -crl CRL              the URL of the CRL distribution point
  -isCA                 if set, the critical extension
                        'basicConstraints:CA:TRUE' is added.
  -validsince VALIDSINCE
                        number of seconds since when this cert has been valid.
                        Default is 0 (i.e., cert is valid from 'now' on)
  -validfor VALIDFOR    number of seconds until this certificate shall expire.
                        Default is 2592000 = 30days
  -kt {RSA,DSA}         set the keytype to use. default is RSA
  -keylength KEYLENGTH  keylength in bits, default is 2048
  -serial SERIAL        the serial number for this cert. default is a random
                        number

```
## Generating Certificate Chains

The first `cert` specified on the commandline will be self-signed, that is, subject equals issuer and the subject public key is used to signe the to-be-signed certificate structure. You can specify a PEM formatted certificate file and a PEM formatted key file to use a different issuer like this:  

```
./certmaker.py cert -CN subjectname -ca_path ./my_ca.pem -ca_key_path ./my_ca.key -ca_key_passwd PASSWORD
```

To create certificate chains, simply add more`cert` commands: each successor will be signed by the preceding certificate. Of course, each cert needs a`-CN COMMONNAME` argument and may be further customized using additional options. As an example

```
./certmaker.py cert -CN 'John Doe' -isCA cert -CN 'Alice' -isCA cert -CN Bob
```

will create a chain of certificates, where `John Doe` is a self-signed certificate with the `BasicConstraints` extension set to `CA:TRUE`. `John Doe` issues (i.e., signs) the certificate of `Alice`which also is marked as CA certificate an, in turn, issues a certificate of subject `Bob`. 

If you want to use a fixed key any cert in the chain, simply add the `-crt_key_path PEM-FILE -crt_key_passwd PASSWORD` options to the respective `cert` command.

Note that `certmaker.py` prints the generated certificates from leaf to root. That is, the leaf certificate is always printed first, followed by its key. Next, any intermediate CAs and their keys are printed. The last cert/key combination printed is the "root" certificate.

### X509v3 Extensions

Use the `-ext` option with three arguments to add an extension field to the generated certificate. The `-ext` option takes as positional arguments the
extension-name, the extension-value and the boolean value of the extension's critical-flag. The syntax as established by OpenSSL is used. Below are some examples

```
./certmake.py cert -CN example.com -ext subjectAltName DNS:http://san.example.com False

./certmake.py cert -CN example.com -ext authorityInfoAccess OCSP\;URI:http://ocsp.ca.example.com/ False -ext  extendedKeyUsage codeSigning,digitalsignature True
```

See https://openssl.org/docs/manmaster/man5/x509v3_config.html#STANDARD-EXTENSIONS for more details on the available extension syntax.

Shortcuts for some extensions exist: the basicConstraints CA:TRUE extension can be added to a certificate by specifying the commandlineflag `-isCA` instead of writing `-ext basicConstraints CA:TRUE True`. A CRL URL can be added using `-crl CRL-URL`, i.e., `-crl https://crl.ca.example.com` instead of `-ext crlDistributionPoints URI:http://crl.ca.example.com False`

