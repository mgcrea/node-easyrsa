# Node.js EasyRSA

[![npm version](https://img.shields.io/npm/v/easyrsa.svg)](https://www.npmjs.com/package/easyrsa)
[![license](https://img.shields.io/github/license/mgcrea/node-easyrsa.svg?style=flat)](https://tldrlegal.com/license/mit-license)
[![build status](http://img.shields.io/travis/mgcrea/node-easyrsa/master.svg?style=flat)](http://travis-ci.org/mgcrea/node-easyrsa)
[![dependencies status](https://img.shields.io/david/mgcrea/node-easyrsa.svg?style=flat)](https://david-dm.org/mgcrea/node-easyrsa)
[![devDependencies status](https://img.shields.io/david/dev/mgcrea/node-easyrsa.svg?style=flat)](https://david-dm.org/mgcrea/node-easyrsa#info=devDependencies)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/99844d4bed38450f9ec9e03650d19954)](https://www.codacy.com/app/mgcrea/node-easyrsa?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=mgcrea/node-easyrsa&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/99844d4bed38450f9ec9e03650d19954)](https://www.codacy.com/app/mgcrea/node-easyrsa?utm_source=github.com&utm_medium=referral&utm_content=mgcrea/node-easyrsa&utm_campaign=Badge_Coverage)
[![npm downloads](https://img.shields.io/npm/dm/easyrsa.svg)](https://www.npmjs.com/package/easyrsa)

Node.js public key infrastructure management library inspired by [EasyRSA](https://github.com/OpenVPN/easy-rsa).

- Uses [forge](https://github.com/digitalbazaar/forge) to manage cryptography
- Provides ready-to-use templates to create your certificate authority: `vpn`, `ssl` or `mdm`.
- Available both as a cli and a lib.
- Provides easy-to-use templates for generic use cases (VPN, SSL, MDM)
- Can easily be plugged to a database backend.

## Quickstart

- Command Line Interface

```bash
npm i -g easyrsa
easyrsa init-pki
easyrsa gen-req EntityName
easyrsa sign-req client EntityName
```

## Testing

- You can quickly start hacking around

```bash
git clone -o github git@github.com:mgcrea/node-easyrsa.git
cd node-easyrsa
npm i
npm start
```

## Docs

- [EasyRSA quickstart](https://github.com/OpenVPN/easy-rsa/blob/master/README.quickstart.md)
