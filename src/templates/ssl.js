
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
    cRLSign: true,
    digitalSignature: true,
    keyCertSign: true
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
      // }, {
      //   name: 'subjectAltName',
      //   altNames: []
      // }, {
      //   name: 'cRLDistributionPoints',
      //   altNames: []
      // }, {
      //   name: 'authorityInfoAccess',
      // }, {
      // }, {
      //   name: 'certificatePolicies',
      // }, {
      // }, {
      //   name: 'timestampList',
      // }, {
      }, {
        name: 'authorityKeyIdentifier',
        keyIdentifier: ca.cert.generateSubjectKeyIdentifier().getBytes()
        // authorityCertIssuer: this._ca.cert.issuer, // not-iPad
        // serialNumber: this._ca.cert.serialNumber // not-iPad
      }, {
        name: 'extKeyUsage',
        clientAuth: true,
        serverAuth: true
      }, {
        name: 'keyUsage',
        critical: true,
        digitalSignature: true,
        keyEncipherment: true
      }]);
      break;
    default:
      throw new Error('Type not supported');
  }
};
