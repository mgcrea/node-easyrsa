import 'debug-utils';
import fs from 'fs';
import path from 'path';
import expect from 'expect';
import Promise from 'bluebird';
import {pki} from 'node-forge';
import {map, groupBy} from 'lodash';

import EasyRSA from './../../src';
import {
  assignTo, loadCertificateFromPemFile, loadCertificationRequestFromPemFile, getCertificateSubject, getCertificateIssuer
} from './../helpers';

Promise.promisifyAll(fs);

const rootDir = path.resolve(__dirname, '..', '..');
const pkiDir = path.resolve(rootDir, '.tmp', 'vpn');
jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000; // 10 second timeout

describe.only('EasyRSA ~ vpn', () => {
  const res = {};
  const fixtures = {};
  const options = {
    pkiDir
  };
  beforeAll(() => Promise.all([
    Promise.props({
      ca: loadCertificateFromPemFile('fixtures/vpn/ca.crt'),
      chain: Promise.all([loadCertificateFromPemFile('fixtures/vpn/issued/server@foo.bar.com.crt')]),
      req: loadCertificationRequestFromPemFile('fixtures/vpn/reqs/baz@foo.bar.com.req'),
      cert: loadCertificateFromPemFile('fixtures/vpn/issued/baz@foo.bar.com.crt')
    }).then(assignTo(fixtures))
  ]));
  describe('#constructor()', () => {
    it('should properly merge options', () => {
      const easyrsa = new EasyRSA();
      expect(easyrsa.config).toBeA('object');
      expect(easyrsa.config.pkiDir).toEqual(path.resolve(rootDir, 'pki'));
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
    beforeAll(() => Promise.all([
      easyrsa.buildCA({serialNumberBytes: 9}).then(assignTo(res, 'ca'))
    ]));
    it('should properly return a privateKey and a cert', () => {
      const {privateKey, cert} = res.ca;
      const privateKeyPem = pki.privateKeyToPem(privateKey);
      expect(privateKeyPem).toBeA('string');
      expect(privateKeyPem).toMatch(/^-----BEGIN RSA PRIVATE KEY-----\r\n.+/);
      const certPem = pki.certificateToPem(cert);
      expect(certPem).toBeA('string');
      expect(certPem).toMatch(/^-----BEGIN CERTIFICATE-----\r\n.+/);
      expect(cert.serialNumber).toMatch(/[0-9a-f]{16}/);
    });
    it('should have correct extensions', () => {
      const {cert} = res.ca;
      const certPem = pki.certificateToPem(cert);
      const resultCert = pki.certificateFromPem(certPem);
      const expectedCert = fixtures.ca;
      expect(getCertificateSubject(resultCert)).toEqual(getCertificateSubject(expectedCert));
      expect(resultCert.serialNumber.length).toEqual(expectedCert.serialNumber.length);
      expect(map(resultCert.extensions, 'name').sort()).toEqual(map(expectedCert.extensions, 'name').sort());
      expect(map(resultCert.extensions, 'id').sort()).toEqual(map(expectedCert.extensions, 'id').sort());
    });
    it('should have correct basicConstraints and keyUsage', () => {
      const {cert} = res.ca;
      const certPem = pki.certificateToPem(cert);
      const resultCert = pki.certificateFromPem(certPem);
      const expectedCert = fixtures.ca;
      const extensions = groupBy(resultCert.extensions, 'name');
      const expectedExtensions = groupBy(expectedCert.extensions, 'name');
      expect(extensions.basicConstraints).toEqual(expectedExtensions.basicConstraints);
      expect(extensions.keyUsage).toEqual(expectedExtensions.keyUsage);
    });
  });
  describe('#genReq()', () => {
    const easyrsa = new EasyRSA(options);
    const commonName = 'baz@foo.bar.com';
    const attributes = {};
    beforeAll(() => Promise.all([
      easyrsa.genReq({commonName, attributes}).then(assignTo(res, 'req'))
    ]));
    it('should properly return a privateKey and a csr', () => {
      const {privateKey, csr} = res.req;
      const privateKeyPem = pki.privateKeyToPem(privateKey);
      expect(privateKeyPem).toBeA('string');
      expect(privateKeyPem).toMatch(/^-----BEGIN RSA PRIVATE KEY-----\r\n.+/);
      const csrPem = pki.certificationRequestToPem(csr);
      expect(csrPem).toBeA('string');
      expect(csrPem).toMatch(/^-----BEGIN CERTIFICATE REQUEST-----\r\n.+/);
    });
    it('should have correct extensions', () => {
      const {csr} = res.req;
      const csrPem = pki.certificationRequestToPem(csr);
      const resultCsr = pki.certificationRequestFromPem(csrPem);
      const expectedCsr = fixtures.req;
      expect(map(resultCsr.extensions, 'name').sort()).toEqual(map(expectedCsr.extensions, 'name').sort());
      expect(map(resultCsr.extensions, 'id').sort()).toEqual(map(expectedCsr.extensions, 'id').sort());
    });
    it('should have correct basicConstraints and keyUsage', () => {
      const {csr} = res.req;
      const csrPem = pki.certificationRequestToPem(csr);
      const resultCsr = pki.certificationRequestFromPem(csrPem);
      const expectedCsr = fixtures.req;
      const extensions = groupBy(resultCsr.extensions, 'name');
      const expectedExtensions = groupBy(expectedCsr.extensions, 'name');
      expect(extensions.basicConstraints).toEqual(expectedExtensions.basicConstraints);
      expect(extensions.keyUsage).toEqual(expectedExtensions.keyUsage);
    });
  });
  describe('#signReq()', () => {
    const easyrsa = new EasyRSA(options);
    const commonName = 'baz@foo.bar.com';
    const attributes = {};
    beforeAll(() => Promise.all([
      easyrsa.signReq({commonName, attributes, type: 'client', serialNumberBytes: 16}).then(assignTo(res, 'cert'))
    ]));
    it('should properly return a cert and a serial', () => {
      const {cert, serial} = res.cert;
      const certPem = pki.certificateToPem(cert);
      expect(certPem).toBeA('string');
      expect(certPem).toMatch(/^-----BEGIN CERTIFICATE-----\r\n.+/);
      expect(serial).toBeA('string');
      expect(serial).toMatch(/[\da-f]/i);
      expect(cert.serialNumber).toMatch(/[0-9a-f]{16}/);
    });
    it('should have correct extensions', () => {
      const {cert} = res.cert;
      const certPem = pki.certificateToPem(cert);
      const resultCert = pki.certificateFromPem(certPem);
      const expectedCert = fixtures.cert;
      expect(getCertificateIssuer(resultCert)).toEqual(getCertificateSubject(res.ca.cert));
      expect(getCertificateIssuer(resultCert)).toEqual(getCertificateIssuer(expectedCert));
      expect(getCertificateSubject(resultCert)).toEqual(getCertificateSubject(expectedCert));
      expect(resultCert.serialNumber.length).toEqual(expectedCert.serialNumber.slice(2).length); // 00?
      expect(map(resultCert.extensions, 'name').sort()).toEqual(map(expectedCert.extensions, 'name').sort());
      expect(map(resultCert.extensions, 'id').sort()).toEqual(map(expectedCert.extensions, 'id').sort());
    });
    it('should have correct basicConstraints and keyUsage', () => {
      const {cert} = res.cert;
      const certPem = pki.certificateToPem(cert);
      const resultCert = pki.certificateFromPem(certPem);
      const expectedCert = fixtures.cert;
      const extensions = groupBy(resultCert.extensions, 'name');
      const expectedExtensions = groupBy(expectedCert.extensions, 'name');
      expect(extensions.basicConstraints).toEqual(expectedExtensions.basicConstraints);
      expect(extensions.keyUsage).toEqual(expectedExtensions.keyUsage);
      expect(extensions.extKeyUsage).toEqual(expectedExtensions.extKeyUsage);
    });
  });
});
