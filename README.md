# CertMaker 

A lightweight wrapper around `pyOpenSSL` to facilitate certificate generation from the commandline.

## Certificates and Certificate-Chains (not only) for Adversarial Testing
Quickly generating a highly customized certificate chain is not really an every-day task. However, if one needs to do so, the usually available tools are not exactly fit to the purpose. As an example, imagine that a specific, custom extension needs to be added to the third imtermediate CA cert. Or, perhaps the `Organisation` field of a certificate's subject shall be tested as XSS (or SQL-Injection) vector against some service. This may require lots of attempts and thus generated certificates until the right attack vector has been found.

Of course one can fiddle around with the OpenSSL CLI tool to create such certificates but that tends to be, well, fiddly. This is where **CertMaker** comes to the rescue. Let's stick to the last example of an XSS in the `Organisation` field. Using `CertMaker`'s CLI, one can simply run:

```
./certmaker.py  cert -CN ''TestSubjects Common Name' -O 'some<script>alert(1)</script>XSS vector'
```

This will generate a self-signed certificate with the following subject/issuer fields:

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5f:fb:d7:ce:c6:0d:46:f9:8e:7d:e9:24:35:98:b2:a6
    Signature Algorithm: sha1WithRSAEncryption
        Issuer: CN=foo bar baz, O=some<script>alert(1)</script>XSS
        Validity
            Not Before: Sep  5 10:32:50 2018 GMT
            Not After : Oct  5 10:32:50 2018 GMT
        Subject: CN=foo bar baz, O=some<script>alert(1)</script>XSS
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)

```

and the following hexdump:
```
echo '-----BEGIN CERTIFICATE-----
MIIDCjCCAfKgAwIBAgIQX/vXzsYNRvmOfekkNZiypjANBgkqhkiG9w0BAQU
...
uMqL7j6yqi45fUH/1jo=
 -----END CERTIFICATE----- | openssl x509 -outform der |xxd
00000000: 3082 030a 3082 01f2 a003 0201 0202 105f  0...0.........._
00000010: fbd7 cec6 0d46 f98e 7de9 2435 98b2 a630  .....F..}.$5...0
00000020: 0d06 092a 8648 86f7 0d01 0105 0500 3041  ...*.H........0A
00000030: 3114 3012 0603 5504 030c 0b66 6f6f 2062  1.0...U....foo b
00000040: 6172 2062 617a 3129 3027 0603 5504 0a0c  ar baz1)0'..U...
00000050: 2073 6f6d 653c 7363 7269 7074 3e61 6c65   some<script>ale
00000060: 7274 2831 293c 2f73 6372 6970 743e 5853  rt(1)</script>XS
00000070: 5330 1e17 0d31 3830 3930 3531 3033 3235  S0...18090510325
00000080: 305a 170d 3138 3130 3035 3130 3332 3530  0Z..181005103250
00000090: 5a30 4131 1430 1206 0355 0403 0c0b 666f  Z0A1.0...U....fo

```

**Note:** In the example above, single quotes were used for (bash) escaping of the `Organisation` string - otherwise bash would eat up any special chars. Further escaping might be necessary depending on the shell and special chars used. Unfortunately, it is not currently possible to inject `NUL` bytes in the certificate structure using `certmaker.py`.

## Installation

`CertMaker` is aPython3 script which uses`pyOpenSSL` internally. Other than that, only standardlibrary modules are used. To install `pyOpenSSL` on a Debian based distribution run

```
sudo apt-get install python3-openssl
```

Alternatively, you may install `pip3` using `apt-get install python3-pip` and run `sudo -H pip3 install pyOpenSSL`. This may require to manually install `libssl-dev` beforehand.


## Usage
As already shown above, simply running `./certmaker.py cert -CN "Test Subject"` will generate a self signed certificate where subject = issuer = "Test Subject". Default values are applied to all other required values such as key (random RSA Key with 2048 bit length is generated automatically), validity period, serial number (random), and so on...

Calling for help with `./certmaker -h` will only hint at the subcommand `cert`

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

```

So what you really need is `./certmaker.py cert -h`, which will display all options of the `cert` command:

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
### X509v3 Extensions

Use the `-ext` option with three arguments to add an extension field to the generated certificate. The `-ext` option takes as positional arguments the
extension-name, the extension-value and the boolean value of the extension's critical-flag. The syntax as established by OpenSSL is used. Below are some examples

```
./certmake.py cert -CN example.com -ext subjectAltName DNS:http://san.example.com False

./certmake.py cert -CN example.com -ext authorityInfoAccess OCSP\;URI:http://ocsp.ca.example.com/ False -ext  extendedKeyUsage codeSigning,digitalsignature True
```

See https://openssl.org/docs/manmaster/man5/x509v3_config.html#STANDARD-EXTENSIONS for more details on the available extension syntax.

Shortcuts for some extensions exist: the basicConstraints CA:TRUE extension can be added to a certificate by specifying the commandlineflag `-isCA` instead of writing `-ext basicConstraints CA:TRUE True`. A CRL URL can be added using `-crl CRL-URL`, i.e., `-crl https://crl.ca.example.com` instead of `-ext crlDistributionPoints URI:http://crl.ca.example.com False`

## Chains of Trust

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
