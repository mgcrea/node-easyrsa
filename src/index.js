// import {FileSystemError} from 'core-error-predicates';

import {pick, defaults} from 'lodash';
import del from 'del';
import forge, {pki, md} from 'node-forge';
import fs from 'fs';
import moment from 'moment';
import path from 'path';
import Promise from 'bluebird';
import mkdirp from 'mkdirp';
import crypto from 'crypto';

import templates from './templates';

Promise.promisifyAll(fs);
Promise.promisifyAll(pki.rsa);
const mkdirpAsync = Promise.promisify(mkdirp);

const cwd = process.cwd();
const noop = () => {};

export default class EasyRSA {
  static defaults = {
    pkiDir: path.join(cwd, 'pki'),
    template: 'vpn',
    keysize: 2048,
    nopass: false,
    subca: false,
    days: 3650
  };
  constructor(argv) {
    this.config = defaults(pick(argv, ...Object.keys(EasyRSA.defaults)), EasyRSA.defaults);
    this.dir = this.config.pkiDir;
  }
  verifyPKI() {
    return fs.statAsync(this.dir).then((file) => {
      if (!file.isDirectory) {
        throw new Error('PKI not ready!');
      }
    });
  }
  loadCA() {
    return Promise.props({
      privateKey: fs.readFileAsync(path.join(this.dir, 'private', 'ca.key')).then(pki.privateKeyFromPem),
      cert: fs.readFileAsync(path.join(this.dir, 'ca.crt')).then(pki.certificateFromPem)
    }).tap(({privateKey, cert}) => {
      this.ca = {
        privateKey,
        cert
      };
    });
  }
  initPKI({force = false} = {}) {
    const setupFolders = dir => mkdirpAsync(dir)
      .then(() => Promise.all([
        fs.mkdirAsync(path.join(dir, 'private')),
        fs.mkdirAsync(path.join(dir, 'reqs'))
      ]));
    return setupFolders(this.dir)
    // @TODO fix catch
    .catch({code: 'EEXIST'}, (err) => {
      if (!force) {
        throw err;
      }
      return del(this.dir).then(() => setupFolders(this.dir));
    })
    // .catch(err => {
    //   d(err.name, err.code);
    // })
    .return(this.dir);
  }
  // https://github.com/OpenVPN/easy-rsa/blob/master/easyrsa3/easyrsa#L408
  // watch -n.75 'openssl x509 -in pki/ca.crt -text -noout'
  buildCA({commonName = 'Easy-RSA CA'} = {}) {
    const cfg = this.config;
    const setupFolders = dir => Promise.all([
      fs.mkdirAsync(path.join(dir, 'issued')).catch((err) => {}),
      fs.mkdirAsync(path.join(dir, 'certs_by_serial'))
    ]);
    return this.verifyPKI()
      .then(() => setupFolders(this.dir).catch(noop))
      .then(() => generateFastKeyPair(cfg.keysize))
      .then(({privateKey, publicKey}) => {
        const cert = pki.createCertificate();
        cert.publicKey = publicKey;
        const date = moment();
        cert.validity.notBefore = date.clone().toDate();
        cert.validity.notAfter = date.clone().add(cfg.days, 'days').toDate();
        cert.serialNumber = crypto.randomBytes(16).toString('hex');
        // Apply template to certificate
        if (templates[cfg.template].buildCA) {
          templates[cfg.template].buildCA(cert, {commonName});
        }
        cert.sign(privateKey, md.sha256.create());
        return {privateKey, cert};
      })
      .tap(({privateKey, cert}) => Promise.all([
        fs.writeFileAsync(path.join(this.dir, 'ca.crt'), pki.certificateToPem(cert)),
        fs.writeFileAsync(path.join(this.dir, 'private', 'ca.key'), pki.privateKeyToPem(privateKey)),
        fs.writeFileAsync(path.join(this.dir, 'index.txt'), ''),
        fs.writeFileAsync(path.join(this.dir, 'serial'), '01')
      ]));
  }
  // watch -n.75 'openssl req -in pki/reqs/EntityName.req -text -noout'
  genReq({commonName = 'Easy-RSA CA'}) {
    const cfg = this.config;
    return this.verifyPKI()
      .then(() => generateFastKeyPair(cfg.keysize))
      .then(({privateKey, publicKey}) => {
        const csr = pki.createCertificationRequest();
        csr.publicKey = publicKey;
        // Apply template to certificate
        if (templates[cfg.template].genReq) {
          templates[cfg.template].genReq(csr, {commonName});
        }
        csr.sign(privateKey, md.sha256.create());
        return {privateKey, csr, commonName};
      }).tap(({privateKey, csr}) => Promise.all([
        fs.writeFileAsync(path.join(this.dir, 'reqs', `${commonName}.req`), pki.certificationRequestToPem(csr)),
        fs.writeFileAsync(path.join(this.dir, 'private', `${commonName}.key`), pki.privateKeyToPem(privateKey))
      ]));
  }
  signReq({commonName, type = 'client'}) {
    const cfg = this.config;
    if (!commonName) {
      throw new Error('Missing commonName');
    }
    return this.verifyPKI()
      .then(::this.loadCA)
      .then(() => Promise.props({
        index: fs.readFileAsync(path.join(this.dir, 'index.txt')).call('toString'),
        serial: fs.readFileAsync(path.join(this.dir, 'serial')).call('toString'),
        csr: fs.readFileAsync(path.join(this.dir, 'reqs', `${commonName}.req`))
               .then(forge.pki.certificationRequestFromPem)
      }))
      .then(({csr, index, serial}) => {
        if (!csr.verify()) {
          throw new Error('The certificate request file is not in a valid X509 request format.');
        }
        const cert = pki.createCertificate();
        cert.publicKey = csr.publicKey;
        cert.serialNumber = crypto.randomBytes(16).toString('hex');
        const date = moment();
        cert.validity.notBefore = date.clone().toDate();
        cert.validity.notAfter = date.clone().add(cfg.days, 'days').toDate();
        // Apply template to certificate
        if (templates[cfg.template].signReq) {
          templates[cfg.template].signReq(cert, {commonName, type, ca: this.ca});
        }
        cert.sign(this.ca.privateKey, md.sha256.create());
        return {cert, serial, commonName};
      })
      .tap(({cert, index, serial}) => {
        const updatedSerial = (parseInt(serial, 16) + 1).toString(16);
        const certPem = pki.certificateToPem(cert);
        const indexKey = cert.tbsCertificate.value[4].value[1].value;
        const indexContent = `${index ? `${index}\n` : ''}V ${indexKey}    ${cert.serialNumber}  unknown /CN=${commonName}`;
        return Promise.all([
          fs.writeFileAsync(path.join(this.dir, 'index.txt'), indexContent),
          fs.writeFileAsync(path.join(this.dir, 'certs_by_serial', `${serial}.pem`), certPem),
          fs.writeFileAsync(path.join(this.dir, 'issued', `${commonName}.crt`), certPem),
          fs.writeFileAsync(path.join(this.dir, 'serial'), updatedSerial.length % 2 ? `0${updatedSerial}` : updatedSerial)
        ]);
      });
  }
}

function generateFastKeyPair(bits = 2048, exponent = 65537) {
  try {
    const keyPair = require('ursa').generatePrivateKey(bits, exponent); // eslint-disable-line global-require

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
