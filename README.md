# Node.js EasyRSA

[![npm version](https://img.shields.io/npm/v/easyrsa.svg)](https://www.npmjs.com/package/easyrsa)
[![license](https://img.shields.io/github/license/mgcrea/node-easyrsa.svg?style=flat)](https://tldrlegal.com/license/mit-license) [![build status](http://img.shields.io/travis/mgcrea/node-easyrsa/master.svg?style=flat)](http://travis-ci.org/mgcrea/node-easyrsa) [![dependencies status](https://img.shields.io/david/mgcrea/node-easyrsa.svg?style=flat)](https://david-dm.org/mgcrea/node-easyrsa) [![devDependencies status](https://img.shields.io/david/dev/mgcrea/node-easyrsa.svg?style=flat)](https://david-dm.org/mgcrea/node-easyrsa#info=devDependencies) [![coverage status](http://img.shields.io/codeclimate/coverage/github/mgcrea/node-easyrsa.svg?style=flat)](https://codeclimate.com/github/mgcrea/node-easyrsa) [![climate status](https://img.shields.io/codeclimate/github/mgcrea/node-easyrsa.svg?style=flat)](https://codeclimate.com/github/mgcrea/node-easyrsa)
[![npm downloads](https://img.shields.io/npm/dm/easyrsa.svg)](https://www.npmjs.com/package/easyrsa)

Node.js implementation of the [EasyRSA](https://github.com/OpenVPN/easy-rsa) OpenVPN Public Key Infrastructure.

- Uses [forge](https://github.com/digitalbazaar/forge) to manage cryptography
- Aims to be 100% ISO with the `easyrsa` bash script from [EasyRSA](https://github.com/OpenVPN/easy-rsa).
- Available both as a cli and a lib.
- Databases backends on the TODO-list.

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
