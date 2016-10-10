
export const buildCA = (cert, {commonName}) => {
  cert.setExtensions([{
    name: 'subjectKeyIdentifier'
  }, {
    name: 'authorityKeyIdentifier',
    keyIdentifier: true,
    authorityCertIssuer: true,
    serialNumber: true
  }, {
    name: 'basicConstraints',
    critical: true,
    cA: true
  }, {
    name: 'keyUsage',
    critical: true,
    keyCertSign: true,
    cRLSign: true
  }, {
    name: 'certificatePolicies',
    value: `Reliance on this certificate by any party assumes acceptance of the
    then applicable standard terms and conditions of use, certificate policy and
    certification practice statements.`
  }]);
};

export const genReq = (csr, {commonName}) => {
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
};

export const signReq = (cert, {type, commonName, ca}) => {
  switch (type) {
    case 'client':
      cert.setExtensions([{
        name: 'basicConstraints',
        critical: true,
        cA: false
      }, {
        name: 'subjectKeyIdentifier'
      }, {
        name: 'authorityKeyIdentifier',
        keyIdentifier: ca.cert.generateSubjectKeyIdentifier().getBytes()
        // authorityCertIssuer: this._ca.cert.issuer, // not-iPad
        // serialNumber: this._ca.cert.serialNumber // not-iPad
      }, {
        name: 'extKeyUsage',
        critical: true,
        serverAuth: true,
        clientAuth: true
      }, {
        name: 'keyUsage',
        critical: true,
        digitalSignature: true,
        keyEncipherment: true
      }, {
        id: '1.2.840.113635.100.6.10.2',
        value: String.fromCharCode(0x0005) + String.fromCharCode(0x0000)
      }]);
      break;
    default:
      throw new Error('Type not supported');
  }
};
