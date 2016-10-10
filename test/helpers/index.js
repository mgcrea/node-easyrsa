import fs from 'fs';
import path from 'path';
import {pki, asn1} from 'node-forge';
import Promise from 'bluebird';

Promise.promisifyAll(fs);

export const assignTo = source =>
  res => Object.assign(source, res);

export const loadCertificateFromPemFile = filepath => // eslint-disable-line no-unused-vars
  fs.readFileAsync(path.resolve(__dirname, '..', filepath))
    .then(::pki.certificateFromPem);

export const loadCertificationRequestFromPemFile = filepath =>
  fs.readFileAsync(path.resolve(__dirname, '..', filepath))
    .then(::pki.certificationRequestFromPem);

export const loadCertificateFromDerFile = filepath => // eslint-disable-line no-unused-vars
  fs.readFileAsync(path.resolve(__dirname, '..', filepath))
    .then(buffer => pki.certificateFromAsn1(asn1.fromDer(buffer.toString('binary'))));

export const getCertificateShortSubject = cert => // eslint-disable-line no-unused-vars
  cert.subject.attributes.reduce((soFar, value) => {
    if (value.shortName) {
      soFar[value.shortName] = value.value;
    }
    return soFar;
  }, {});
