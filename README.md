# Node.js EasyRSA

Node.js implementation of the [EasyRSA](https://github.com/OpenVPN/easy-rsa) OpenVPN Public Key Infrastructure.

- Uses [forge](https://github.com/digitalbazaar/forge) to manage cryptography
- Aims to be 100% ISO with the `easyrsa` bash script from [EasyRSA](https://github.com/OpenVPN/easy-rsa).
- Available both as a cli and a lib.
- Databases backends on the TODO-list.

## quickstart

- Command Line Interface

```bash
npm i -g easyrsa
easyrsa init-pki
easyrsa gen-req EntityName
easyrsa sign-req client EntityName
```

## docs

- [EasyRSA quickstart](https://github.com/OpenVPN/easy-rsa/blob/master/README.quickstart.md)
