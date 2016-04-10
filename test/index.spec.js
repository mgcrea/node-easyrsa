
import fs from 'fs';
import path from 'path';
import expect from 'expect';
import EasyRSA from './..';
import {pki} from 'node-forge';

const options = {
  pkiDir: path.resolve(__dirname, 'fixtures', 'pki')
};

describe('EasyRSA', () => {
  describe('#constructor()', () => {
    it('should properly merge options', () => {
      const easyrsa = new EasyRSA();
      expect(easyrsa.config).toBeA('object');
      expect(easyrsa.config.pkiDir).toEqual(path.resolve(__dirname, '..', 'pki'));
    });
  });
  describe('#initPKI()', () => {
    it('should properly return a privateKey and a cert', () => {
      const easyrsa = new EasyRSA(options);
      return easyrsa.initPKI({force: true}).then(() => {
        return fs.statAsync(easyrsa.config.pkiDir).call('isDirectory').then((isDirectory) => {
          expect(isDirectory).toBeTrue;
        });
      });
    });
  });
  describe('#buildCA()', () => {
    it('should properly return a privateKey and a cert', () => {
      const easyrsa = new EasyRSA(options);
      easyrsa.buildCA().then(({privateKey, cert}) => {
        const privateKeyPem = pki.privateKeyToPem(privateKey);
        expect(privateKeyPem).toBeA('string');
        expect(privateKeyPem).toMatch(/^-----BEGIN RSA PRIVATE KEY-----\r\n.+/);
        const certPem = pki.certificateToPem(cert);
        expect(certPem).toBeA('string');
        expect(certPem).toMatch(/^-----BEGIN CERTIFICATE-----\r\n.+/);
      });
    });
  });
  describe('#genReq()', () => {
    it('should properly return a privateKey and a csr', () => {
      const easyrsa = new EasyRSA(options);
      easyrsa.genReq('EntityName').then(({privateKey, csr}) => {
        const privateKeyPem = pki.privateKeyToPem(privateKey);
        expect(privateKeyPem).toBeA('string');
        expect(privateKeyPem).toMatch(/^-----BEGIN RSA PRIVATE KEY-----\r\n.+/);
        const csrPem = pki.certificationRequestToPem(csr);
        expect(csrPem).toBeA('string');
        expect(csrPem).toMatch(/^-----BEGIN CERTIFICATE REQUEST-----\r\n.+/);
      });
    });
  });
  describe('#signReq()', () => {
    it('should properly return a privateKey and a csr', () => {
      const easyrsa = new EasyRSA(options);
      easyrsa.signReq('client', 'EntityName').then(({cert, serial}) => {
        const certPem = pki.certificateToPem(cert);
        expect(certPem).toBeA('string');
        expect(certPem).toMatch(/^-----BEGIN CERTIFICATE-----\r\n.+/);
        expect(serial).toBeA('string');
        expect(serial).toMatch(/[\da-f]/i);
      });
    });
  });
});
