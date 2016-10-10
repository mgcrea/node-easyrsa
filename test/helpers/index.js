import fs from 'fs';
import path from 'path';
import {pki, asn1} from 'node-forge';
import Promise from 'bluebird';

Promise.promisifyAll(fs);

export const assignTo = (source = {}, key) => (res) => {
  if (key && typeof source[key] === 'undefined') {
    source[key] = {};
  }
  Object.assign(key ? source[key] : source, res);
  return source;
};

export const loadCertificateFromPemFile = filepath =>
  fs.readFileAsync(path.resolve(__dirname, '..', filepath))
    .then(::pki.certificateFromPem);

export const loadCertificationRequestFromPemFile = filepath =>
  fs.readFileAsync(path.resolve(__dirname, '..', filepath))
    .then(::pki.certificationRequestFromPem);

export const loadCertificateFromDerFile = filepath =>
  fs.readFileAsync(path.resolve(__dirname, '..', filepath))
    .then(buffer => pki.certificateFromAsn1(asn1.fromDer(buffer.toString('binary'))));

export const getSubjectFromAttrs = attributes =>
  attributes.reduce((soFar, value) => {
    if (value.shortName) {
      soFar[value.name] = value.value;
    }
    return soFar;
  }, {});

export const getCertificateSubject = cert =>
  getSubjectFromAttrs(cert.subject.attributes);

export const getCertificateIssuer = cert =>
  getSubjectFromAttrs(cert.issuer.attributes);

export const getCertificateShortSubject = cert =>
  cert.subject.attributes.reduce((soFar, value) => {
    if (value.shortName) {
      soFar[value.shortName] = value.value;
    }
    return soFar;
  }, {});
