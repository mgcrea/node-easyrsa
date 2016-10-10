
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
    cA: true
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    cRLSign: true
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
        // critical: true, // iPad
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
        // critical: true, // iPad
        // serverAuth: true, // iPad
        clientAuth: true
      }, {
        name: 'keyUsage',
        cRLSign: false,
        keyCertSign: false,
        // critical: true, // iPad
        digitalSignature: true
        // keyEncipherment: true // iPad
      }]);
      break;
    default:
      throw new Error('Type not supported');
  }
};
