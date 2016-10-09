import 'debug-utils';
import fs from 'fs';
import del from 'del';
import path from 'path';
import expect from 'expect';
import Promise from 'bluebird';
import {pki} from 'node-forge';
import {map, groupBy, sort} from 'lodash';

import EasyRSA from './../src';

Promise.promisifyAll(fs);


const loadCertificateFromFile = filepath =>
  fs.readFileAsync(path.resolve(__dirname, filepath))
    .then(::pki.certificateFromPem);

const loadCertificationRequestFromFile = filepath =>
  fs.readFileAsync(path.resolve(__dirname, filepath))
    .then(::pki.certificationRequestFromPem);


describe('HTTPS', () => {
  // Load fixtures
  Promise.props({
    rootCa: loadCertificateFromFile('fixtures/https/DigiCert High Assurance EV Root CA.pem'),
    serverCa: loadCertificateFromFile('fixtures/https/DigiCert SHA2 Extended Validation Server CA.pem'),
    cert: loadCertificateFromFile('fixtures/https/www.digitalocean.com.pem')
  })
  // .then(({rootCa, serverCa, cert}) => {
  //   d(rootCa.extensions);
  // });
});

describe.only('EasyRSA', () => {
  let fixtures;
  const options = {
    pkiDir: path.resolve(__dirname, '.tmp')
  };
  before(() => Promise.all([
    del([options.pkiDir]).catch(),
    Promise.props({
      rootCa: loadCertificateFromFile('fixtures/pki/ca.crt'),
      serverCa: loadCertificateFromFile('fixtures/pki/issued/server@foo.bar.com.crt'),
      req: loadCertificationRequestFromFile('fixtures/pki/reqs/baz@foo.bar.com.req'),
      cert: loadCertificateFromFile('fixtures/pki/issued/baz@foo.bar.com.crt')
    }).then((props) => { fixtures = props; })
  ]));
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
      return easyrsa.initPKI({force: true}).then(() =>
        fs.statAsync(easyrsa.config.pkiDir).call('isDirectory').then((isDirectory) => {
          expect(isDirectory).toBe(true);
        }));
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
        // Compare against fixture
        const resultCert = pki.certificateFromPem(certPem);
        const expectedCert = fixtures.rootCa;
        // Should have the same extensions
        expect(map(resultCert.extensions, 'name')).toEqual(map(expectedCert.extensions, 'name'));
        expect(map(resultCert.extensions, 'id')).toEqual(map(expectedCert.extensions, 'id'));
        // Should have the same basicConstraints and keyUsage
        const extensions = groupBy(resultCert.extensions, 'name');
        const expectedExtensions = groupBy(fixtures.rootCa.extensions, 'name');
        expect(extensions.basicConstraints).toEqual(expectedExtensions.basicConstraints);
        expect(extensions.keyUsage).toEqual(expectedExtensions.keyUsage);
      });
    });
  });
  describe('#genReq()', () => {
    it('should properly return a privateKey and a csr', () => {
      const easyrsa = new EasyRSA(options);
      easyrsa.genReq({commonName: 'EntityName'}).then(({privateKey, csr}) => {
        const privateKeyPem = pki.privateKeyToPem(privateKey);
        expect(privateKeyPem).toBeA('string');
        expect(privateKeyPem).toMatch(/^-----BEGIN RSA PRIVATE KEY-----\r\n.+/);
        const csrPem = pki.certificationRequestToPem(csr);
        expect(csrPem).toBeA('string');
        expect(csrPem).toMatch(/^-----BEGIN CERTIFICATE REQUEST-----\r\n.+/);
        // Compare against fixture
        const resultCsr = pki.certificationRequestFromPem(csrPem);
        const expectedCsr = fixtures.req;
        // Should have the same extensions
        expect(map(resultCsr.extensions, 'name')).toEqual(map(expectedCsr.extensions, 'name'));
        expect(map(resultCsr.extensions, 'id')).toEqual(map(expectedCsr.extensions, 'id'));
        // Should have the same basicConstraints and keyUsage
        const extensions = groupBy(resultCsr.extensions, 'name');
        const expectedExtensions = groupBy(fixtures.req.extensions, 'name');
        expect(extensions.basicConstraints).toEqual(expectedExtensions.basicConstraints);
        expect(extensions.keyUsage).toEqual(expectedExtensions.keyUsage);
      });
    });
  });
  describe('#signReq()', () => {
    it('should properly return a cert and a serial', () => {
      const easyrsa = new EasyRSA(options);
      easyrsa.signReq('client', 'EntityName').then(({cert, serial}) => {
        const certPem = pki.certificateToPem(cert);
        expect(certPem).toBeA('string');
        expect(certPem).toMatch(/^-----BEGIN CERTIFICATE-----\r\n.+/);
        expect(serial).toBeA('string');
        expect(serial).toMatch(/[\da-f]/i);
        // Compare against fixture
        const resultCert = pki.certificateFromPem(certPem);
        const expectedCert = fixtures.cert;
        // Should have the same extensions
        expect(map(resultCert.extensions, 'name')).toEqual(map(expectedCert.extensions, 'name'));
        expect(map(resultCert.extensions, 'id')).toEqual(map(expectedCert.extensions, 'id'));
        // Should have the same basicConstraints and keyUsage
        const extensions = groupBy(resultCert.extensions, 'name');
        const expectedExtensions = groupBy(fixtures.rootCa.extensions, 'name');
        expect(extensions.basicConstraints).toEqual(expectedExtensions.basicConstraints);
        expect(extensions.keyUsage).toEqual(expectedExtensions.keyUsage);
      });
    });
  });
});
