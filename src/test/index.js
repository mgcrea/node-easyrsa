
import fs from 'fs';
import chai from 'chai';
// import sinon from 'sinon';
import path from 'path';
const expect = chai.expect;
import EasyRSA from './..';
import {pki} from 'node-forge';

const options = {
  pkiDir: path.resolve(__dirname, '..', '..', '.tmp', 'pki')
};

describe('EasyRSA', () => {
  describe('#constructor()', () => {
    it('should properly merge options', () => {
      const easyrsa = new EasyRSA();
      expect(easyrsa.config).to.be.a('object');
      expect(easyrsa.config.pkiDir).to.eql(path.resolve(__dirname, '..', '..', 'pki'));
    });
  });
  describe('#initPKI()', () => {
    it('should properly return a privateKey and a cert', () => {
      const easyrsa = new EasyRSA(options);
      return easyrsa.initPKI({force: true}).then(() => {
        return fs.statAsync(easyrsa.config.pkiDir).call('isDirectory').then((isDirectory) => {
          expect(isDirectory).to.be.true;
        });
      });
    });
  });
  describe('#buildCA()', () => {
    it('should properly return a privateKey and a cert', () => {
      const easyrsa = new EasyRSA(options);
      easyrsa.buildCA().then(({privateKey, cert}) => {
        const privateKeyPem = pki.privateKeyToPem(privateKey);
        expect(privateKeyPem).to.be.a('string');
        expect(privateKeyPem).to.match(/^-----BEGIN RSA PRIVATE KEY-----\r\n.+/);
        const certPem = pki.certificateToPem(cert);
        expect(certPem).to.be.a('string');
        expect(certPem).to.match(/^-----BEGIN CERTIFICATE-----\r\n.+/);
      });
    });
  });
  describe('#genReq()', () => {
    it('should properly return a privateKey and a csr', () => {
      const easyrsa = new EasyRSA(options);
      easyrsa.genReq('EntityName').then(({privateKey, csr}) => {
        const privateKeyPem = pki.privateKeyToPem(privateKey);
        expect(privateKeyPem).to.be.a('string');
        expect(privateKeyPem).to.match(/^-----BEGIN RSA PRIVATE KEY-----\r\n.+/);
        const csrPem = pki.certificationRequestToPem(csr);
        expect(csrPem).to.be.a('string');
        expect(csrPem).to.match(/^-----BEGIN CERTIFICATE REQUEST-----\r\n.+/);
      });
    });
  });
  describe('#signReq()', () => {
    it('should properly return a privateKey and a csr', () => {
      const easyrsa = new EasyRSA(options);
      easyrsa.signReq('client', 'EntityName').then(({cert, serial}) => {
        const certPem = pki.certificateToPem(cert);
        expect(certPem).to.be.a('string');
        expect(certPem).to.match(/^-----BEGIN CERTIFICATE-----\r\n.+/);
        expect(serial).to.be.a('string');
        expect(serial).to.match(/[\da-f]/i);
      });
    });
  });
});
