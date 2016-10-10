import 'debug-utils';
import fs from 'fs';
import path from 'path';
import expect from 'expect';
import Promise from 'bluebird';
import {pki} from 'node-forge';
import {map, reject, groupBy} from 'lodash';

import EasyRSA from './../src';
import {assignTo, loadCertificateFromPemFile} from './helpers';

Promise.promisifyAll(fs);

describe('EasyRSA ~ mdm', () => {
  const fixtures = {};
  const options = {
    template: 'mdm',
    pkiDir: path.resolve(__dirname, '.tmp', 'mdm')
  };
  before(() => Promise.all([
    Promise.props({
      ca: loadCertificateFromPemFile('fixtures/mdm/AppleIncRootCertificate.pem'),
      chain: Promise.all([
        loadCertificateFromPemFile('fixtures/mdm/Apple_iPhone_CA.pem'),
        loadCertificateFromPemFile('fixtures/mdm/Apple_iPhone_Device_CA.pem')
      ]),
      cert: loadCertificateFromPemFile('fixtures/mdm/F567FC13-704D-47DE-9993-15C8EBB236AF.pem')
    }).then(assignTo(fixtures))
  ]));
  describe('#constructor()', () => {
    it('should properly merge options', () => {
      const easyrsa = new EasyRSA();
      expect(easyrsa.config).toBeA('object');
      expect(easyrsa.config.pkiDir).toEqual(path.resolve(__dirname, '..', 'pki'));
    });
  });
  describe('#initPKI()', () => {
    it('should properly initialize a new pki', () => {
      const easyrsa = new EasyRSA(options);
      return easyrsa.initPKI({force: true}).then(() =>
        fs.statAsync(easyrsa.config.pkiDir).call('isDirectory').then((isDirectory) => {
          expect(isDirectory).toBe(true);
        }));
    });
  });
  describe('#buildCA()', () => {
    const easyrsa = new EasyRSA(options);
    const res = {};
    before(() => Promise.all([
      easyrsa.buildCA().then(assignTo(res))
    ]));
    it('should properly return a privateKey and a cert', () => {
      const {privateKey, cert} = res;
      const privateKeyPem = pki.privateKeyToPem(privateKey);
      expect(privateKeyPem).toBeA('string');
      expect(privateKeyPem).toMatch(/^-----BEGIN RSA PRIVATE KEY-----\r\n.+/);
      const certPem = pki.certificateToPem(cert);
      expect(certPem).toBeA('string');
      expect(certPem).toMatch(/^-----BEGIN CERTIFICATE-----\r\n.+/);
      expect(cert.serialNumber).toMatch(/[0-9a-f]{16}/);
    });
    it('should have correct extensions', () => {
      const {cert} = res;
      const certPem = pki.certificateToPem(cert);
      const resultCert = pki.certificateFromPem(certPem);
      const expectedCert = fixtures.ca;
      expect(map(resultCert.extensions, 'name').sort()).toEqual(map(expectedCert.extensions, 'name').sort());
      expect(map(resultCert.extensions, 'id').sort()).toEqual(map(expectedCert.extensions, 'id').sort());
    });
    it('should have correct basicConstraints and keyUsage', () => {
      const {cert} = res;
      const certPem = pki.certificateToPem(cert);
      const resultCert = pki.certificateFromPem(certPem);
      const expectedCert = fixtures.ca;
      const extensions = groupBy(resultCert.extensions, 'name');
      const expectedExtensions = groupBy(expectedCert.extensions, 'name');
      // d(getCertificateShortSubject(expectedCert));
      expect(extensions.basicConstraints).toEqual(expectedExtensions.basicConstraints);
      expect(extensions.keyUsage).toEqual(expectedExtensions.keyUsage);
    });
  });
  describe('#genReq()', () => {
    const easyrsa = new EasyRSA(options);
    const res = {};
    before(() => Promise.all([
      easyrsa.genReq({commonName: 'EntityName'}).then(assignTo(res))
    ]));
    it('should properly return a privateKey and a csr', () => {
      const {privateKey, csr} = res;
      const privateKeyPem = pki.privateKeyToPem(privateKey);
      expect(privateKeyPem).toBeA('string');
      expect(privateKeyPem).toMatch(/^-----BEGIN RSA PRIVATE KEY-----\r\n.+/);
      const csrPem = pki.certificationRequestToPem(csr);
      expect(csrPem).toBeA('string');
      expect(csrPem).toMatch(/^-----BEGIN CERTIFICATE REQUEST-----\r\n.+/);
    });
    // it('should have correct extensions', () => {
    //   const {csr} = res;
    //   const csrPem = pki.certificationRequestToPem(csr);
    //   const resultCsr = pki.certificationRequestFromPem(csrPem);
    //   const expectedCsr = fixtures.req;
    //   expect(map(resultCsr.extensions, 'name')).toEqual(map(expectedCsr.extensions, 'name'));
    //   expect(map(resultCsr.extensions, 'id')).toEqual(map(expectedCsr.extensions, 'id'));
    // });
    // it('should have correct basicConstraints and keyUsage', () => {
    //   const {csr} = res;
    //   const csrPem = pki.certificationRequestToPem(csr);
    //   const resultCsr = pki.certificationRequestFromPem(csrPem);
    //   const expectedCsr = fixtures.req;
    //   const extensions = groupBy(resultCsr.extensions, 'name');
    //   const expectedExtensions = groupBy(expectedCsr.extensions, 'name');
    //   expect(extensions.basicConstraints).toEqual(expectedExtensions.basicConstraints);
    //   expect(extensions.keyUsage).toEqual(expectedExtensions.keyUsage);
    // });
  });
  describe('#signReq()', () => {
    const easyrsa = new EasyRSA(options);
    const res = {};
    before(() => Promise.all([
      easyrsa.signReq({commonName: 'EntityName', type: 'client'}).then(assignTo(res))
    ]));
    it('should properly return a cert and a serial', () => {
      const {cert, serial} = res;
      const certPem = pki.certificateToPem(cert);
      expect(certPem).toBeA('string');
      expect(certPem).toMatch(/^-----BEGIN CERTIFICATE-----\r\n.+/);
      expect(serial).toBeA('string');
      expect(serial).toMatch(/[\da-f]/i);
      expect(cert.serialNumber).toMatch(/[0-9a-f]{16}/);
    });
    it('should have correct extensions', () => {
      const {cert} = res;
      const certPem = pki.certificateToPem(cert);
      const resultCert = pki.certificateFromPem(certPem);
      const expectedCert = fixtures.cert;
      // d(reject(expectedCert, 'extensions'));
      expect(map(resultCert.extensions, 'name').sort()).toEqual(map(expectedCert.extensions, 'name').sort());
      expect(map(resultCert.extensions, 'id').sort()).toEqual(map(expectedCert.extensions, 'id').sort());
    });
    it('should have correct basicConstraints and keyUsage', () => {
      const {cert} = res;
      const certPem = pki.certificateToPem(cert);
      const resultCert = pki.certificateFromPem(certPem);
      const expectedCert = fixtures.cert;
      // d(getCertificateShortSubject(expectedCert));
      const extensions = groupBy(resultCert.extensions, 'name');
      const expectedExtensions = groupBy(expectedCert.extensions, 'name');
      expect(extensions.basicConstraints).toEqual(expectedExtensions.basicConstraints);
      expect(extensions.keyUsage).toEqual(expectedExtensions.keyUsage);
      expect(extensions.extKeyUsage).toEqual(expectedExtensions.extKeyUsage);
    });
  });
});
