import 'source-map-support/register';
import Promise from 'bluebird';
import fs from 'fs'; Promise.promisifyAll(fs);
import path from 'path';
import del from 'del';
import {pick, defaults} from 'lodash';
import forge, {pki, md} from 'node-forge'; Promise.promisifyAll(pki.rsa);
// import {FileSystemError} from 'core-error-predicates';
const cwd = process.cwd();
import moment from 'moment';

export default class EasyRSA {
  static defaults = {
    pkiDir: path.join(cwd, 'pki'),
    keysize: 2048,
    nopass: false,
    subca: false,
    days: 3650
  };
  constructor(argv) {
    this.config = defaults({}, pick(argv, ...Object.keys(EasyRSA.defaults)), EasyRSA.defaults);
    this.dir = this.config.pkiDir;
  }
  _verifyPKI() {
    return fs.statAsync(this.dir).then(file => {
      if (!file.isDirectory) {
        throw new Error('PKI not ready!');
      }
    });
  }
  _loadCA() {
    return Promise.props({
      privateKey: fs.readFileAsync(path.join(this.dir, 'private', 'ca.key')).then(pki.privateKeyFromPem),
      cert: fs.readFileAsync(path.join(this.dir, 'ca.crt')).then(pki.certificateFromPem)
    }).tap(({privateKey, cert}) => {
      this._ca = {
        privateKey,
        cert
      };
    });
  }
  initPKI({force = false} = {}) {
    const setupFolders = (dir) => {
      return fs.mkdirAsync(dir).then(() => {
        return Promise.all([
          fs.mkdirAsync(path.join(dir, 'private')),
          fs.mkdirAsync(path.join(dir, 'reqs'))
        ]);
      });
    };
    return setupFolders(this.dir)
    // @TODO fix catch
    .catch({code: 'EEXIST'}, err => {
      if (!force) {
        throw err;
      }
      return del(this.dir).then(() => {
        return setupFolders(this.dir);
      });
    })
    // .catch(err => {
    //   d(err.name, err.code);
    // })
    .return(this.dir);
  }
  // https://github.com/OpenVPN/easy-rsa/blob/master/easyrsa3/easyrsa#L408
  // watch -n.75 'openssl x509 -in pki/ca.crt -text -noout'
  buildCA() {
    const setupFolders = (dir) => {
      return Promise.all([
        fs.mkdirAsync(path.join(dir, 'issued')).catch(err => {}),
        fs.mkdirAsync(path.join(dir, 'certs_by_serial'))
      ]);
    };
    return this._verifyPKI()
      .then(() => {
        return setupFolders(this.dir).catch(err => {
          return;
        });
      })
      .then(() => {
        return generateFastKeyPair(this.config.keysize);
      })
      .then(({privateKey, publicKey}) => {
        const cert = pki.createCertificate();
        cert.publicKey = publicKey;
        cert.serialNumber = 'cc3f3ee26d9a574e';
        const date = moment();
        cert.validity.notBefore = date.clone().toDate();
        cert.validity.notAfter = date.clone().add(this.config.days, 'days').toDate();
        const attrs = [{
          name: 'commonName',
          value: 'Easy-RSA CA'
        }/* , {
          name: 'countryName',
          value: 'US'
        }, {
          shortName: 'ST',
          value: 'Virginia'
        }, {
          name: 'localityName',
          value: 'Blacksburg'
        }, {
          name: 'organizationName',
          value: 'Test'
        }, {
          shortName: 'OU',
          value: 'Test'
        }*/];
        cert.setSubject(attrs);
        cert.setIssuer(attrs);
        cert.setExtensions([{
          name: 'subjectKeyIdentifier'
        }, {
          name: 'authorityKeyIdentifier',
          keyIdentifier: true,
          authorityCertIssuer: true,
          serialNumber: true
        }, {
          name: 'basicConstraints',
          cA: true
        }, {
          name: 'keyUsage',
          keyCertSign: true,
          cRLSign: true
        }]);
        cert.sign(privateKey, md.sha256.create());
        return {privateKey, cert};
      }).tap(({privateKey, cert}) => {
        return Promise.all([
          fs.writeFileAsync(path.join(this.dir, 'ca.crt'), pki.certificateToPem(cert)),
          fs.writeFileAsync(path.join(this.dir, 'private', 'ca.key'), pki.privateKeyToPem(privateKey)),
          fs.writeFileAsync(path.join(this.dir, 'index.txt'), ''),
          fs.writeFileAsync(path.join(this.dir, 'serial'), '01')
        ]);
      });
  }
  // watch -n.75 'openssl req -in pki/reqs/EntityName.req -text -noout'
  genReq(commonName) {
    return this._verifyPKI()
      .then(() => {
        return generateFastKeyPair(this.config.keysize);
      })
      .then(({privateKey, publicKey}) => {
        const csr = pki.createCertificationRequest();
        csr.publicKey = publicKey;
        csr.setSubject([{
          name: 'commonName',
          value: commonName
        }/* , {
          name: 'countryName',
          value: 'US'
        }, {
          shortName: 'ST',
          value: 'Virginia'
        }, {
          name: 'localityName',
          value: 'Blacksburg'
        }, {
          name: 'organizationName',
          value: 'Test'
        }, {
          shortName: 'OU',
          value: 'Test'
        }*/]);
        // csr.setAttributes([{
        //   name: 'challengePassword',
        //   value: 'password'
        // }, {
        //   name: 'unstructuredName',
        //   value: 'My Company, Inc.'
        // }, {
        //   name: 'extensionRequest',
        //   extensions: [{
        //     name: 'subjectAltName',
        //     altNames: [{
        //       // 2 is DNS type
        //       type: 2,
        //       value: 'test.domain.com'
        //     }, {
        //       type: 2,
        //       value: 'other.domain.com',
        //     }, {
        //       type: 2,
        //       value: 'www.domain.net'
        //     }]
        //   }]
        // }]);
        csr.sign(privateKey, md.sha256.create());
        return {privateKey, csr, commonName};
      }).tap(({privateKey, csr}) => {
        return Promise.all([
          fs.writeFileAsync(path.join(this.dir, 'reqs', `${commonName}.req`), pki.certificationRequestToPem(csr)),
          fs.writeFileAsync(path.join(this.dir, 'private', `${commonName}.key`), pki.privateKeyToPem(privateKey))
        ]);
      });
  }
  signReq(type = 'client', commonName) {
    if (!commonName) {
      throw new Error('Missing commonName');
    }
    return this._verifyPKI()
      .then(this._loadCA.bind(this))
      .then(() => {
        return Promise.props({
          serial: fs.readFileAsync(path.join(this.dir, 'serial')).call('toString'),
          csr: fs.readFileAsync(path.join(this.dir, 'reqs', `${commonName}.req`))
                 .then(forge.pki.certificationRequestFromPem)
        });
      })
      .then(({csr, serial}) => {
        if (!csr.verify()) {
          throw new Error('The certificate request file is not in a valid X509 request format.');
        }
        const cert = pki.createCertificate();
        cert.publicKey = csr.publicKey;
        cert.serialNumber = serial;
        const date = moment();
        cert.validity.notBefore = date.clone().toDate();
        cert.validity.notAfter = date.clone().add(this.config.days, 'days').toDate();
        //         Subject: CN=F567FC13-704D-47DE-9993-15C8EBB236AF, C=US, ST=CA, L=Cupertino, O=Apple Inc., OU=iPhone
        const attrs = [{
          name: 'commonName',
          value: 'Easy-RSA CA'
        }/* , {
          name: 'countryName',
          value: 'US'
        }, {
          shortName: 'ST',
          value: 'Virginia'
        }, {
          name: 'localityName',
          value: 'Blacksburg'
        }, {
          name: 'organizationName',
          value: 'Test'
        }, {
          shortName: 'OU',
          value: 'Test'
        }*/];
        cert.setSubject(attrs);
        cert.setIssuer(attrs);
        switch (type) {
          case 'client':
            cert.setExtensions([{
              name: 'basicConstraints',
              critical: true, // iPad
              cA: false
            }, {
              name: 'subjectKeyIdentifier'
            }, {
              name: 'authorityKeyIdentifier',
              keyIdentifier: this._ca.cert.generateSubjectKeyIdentifier().getBytes()
              // authorityCertIssuer: this._ca.cert.issuer, // not-iPad
              // serialNumber: this._ca.cert.serialNumber // not-iPad
            }, {
              name: 'keyUsage',
              critical: true, // iPad
              digitalSignature: true,
              keyEncipherment: true // iPad
            }, {
              name: 'extKeyUsage',
              critical: true, // iPad
              serverAuth: true, // iPad
              clientAuth: true
            }]);
            break;
          default:
            throw new Error('Type not supported');
        }
        cert.sign(this._ca.privateKey, md.sha256.create());
        return {cert, serial, commonName};
      }).tap(({cert, serial}) => {
        const updatedSerial = (parseInt(serial, 16) + 1).toString(16);
        const certPem = pki.certificateToPem(cert);
        return Promise.all([
          fs.writeFileAsync(path.join(this.dir, 'certs_by_serial', `${serial}.pem`), certPem),
          fs.writeFileAsync(path.join(this.dir, 'issued', `${commonName}.crt`), certPem),
          fs.writeFileAsync(path.join(this.dir, 'serial'), updatedSerial.length % 2 ? `0${updatedSerial}` : updatedSerial)
        ]);
      });
  }
}

function generateFastKeyPair(bits = 2048, exponent = 65537) {
  try {
    const keyPair = require('ursa').generatePrivateKey(bits, exponent);
    return {
      privateKey: pki.privateKeyFromPem(keyPair.toPrivatePem().toString()),
      publicKey: pki.publicKeyFromPem(keyPair.toPublicPem().toString())
    };
  } catch (err) {
    return pki.rsa.generateKeyPairAsync({bits, workers: -1});
  }
}

// function prettyPrintCertificate(filePath) {
//   return fs.readFileAsync(filePath, 'utf8')
//     .then(contents => pem.decode(contents)[0])
//     .then(message => asn1.fromDer(message.body))
//     .then(object => asn1.prettyPrint(object))
//     .then(console.log.bind(console));
// }
