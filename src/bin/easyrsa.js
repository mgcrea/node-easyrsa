#!/usr/bin/env node
import yargs from 'yargs';
import pkg from './../../package.json';
import EasyRSA from './../../lib';
import Promise from 'bluebird';
import {mapKeys, camelCase} from 'lodash';
import inquirer from 'inquirer'; Promise.promisifyAll(inquirer);
import log from './../utils/log';
try { require('debug-utils'); } catch (err) {/**/}

const argv = yargs
  .usage('Usage: $0 <command> [options]')
  .command('init-pki', 'Removes & re-initializes the PKI dir for a clean PKI')
  .demand(1)
  // .example('$0 count -f foo.js', 'count the lines in the given file')
  // .demand('f')
  // .alias('f', 'file')
  // .nargs('f', 1)
  .describe('pki-dir', 'Declares the PKI directory')
  .command('build-ca', 'Creates a new CA', () => {
    yargs
      .option('nopass', {description: 'Do not encrypt the CA key', type: 'boolean'})
      .option('subca', {description: 'Create a sub-CA keypair and request', type: 'boolean'})
      .option('days', {description: 'Sets the signing validity to the specified number of days', default: EasyRSA.defaults.days, type: 'number'})
      .help('h').alias('h', 'help');
  })
  .command('gen-req', 'Generate a standalone keypair and request (CSR)', () => {
    yargs
      .usage('Usage: easyrsa gen-req <filename_base>')
      .demand(2, 'Incorrect number of arguments provided')
      .option('nopass', {description: 'Do not encrypt the CA key', type: 'boolean'})
      .help('h').alias('h', 'help');
  })
  .command('sign-req', 'Sign a certificate request of the defined type. <type> must be a known type such as \'client\', \'server\', or \'ca\' (or a user-added type.)', () => {
    yargs
      .usage('Usage: easyrsa sign-req <type> <filename_base>')
      .demand(3, 'Incorrect number of arguments provided')
      .option('nopass', {description: 'Do not encrypt the CA key', type: 'boolean'})
      .help('h').alias('h', 'help');
  })
  .help('h').alias('h', 'help')
  // .epilog('copyright 2015')
  .version(pkg.version)
  .argv;

const pki = new EasyRSA(mapKeys(argv, (value, key) => camelCase(key)));
const cmds = argv._.slice(1);
switch (argv._[0]) {
  case 'init-pki':
    pki.initPKI()
    .catch({code: 'EEXIST'}, err => {
      log.warn('You are about to remove the EASYRSA_PKI at: %s and initialize a fresh PKI here.', pki.dir);
      return inquirer.promptAsync({name: 'confirm', message: 'Confirm removal', type: 'confirm', default: false}).catch(({confirm}) => {
        if (!confirm) {
          process.exit(1);
        }
        return pki.initPKI({force: true});
      });
    })
    .then(() => {
      log.info('init-pki complete; you may now create a CA or requests.');
      log.info('Your newly created PKI dir is: %s', pki.dir);
      process.exit(0);
    });
    break;
  case 'build-ca':
    pki.buildCA()
    .then(() => {
      log.info('init-pki complete; you may now create a CA or requests.');
      log.info('Your newly created PKI dir is: %s', pki.dir);
      process.exit(0);
    });
    break;
  case 'gen-req':
    pki.genReq(...cmds);
    break;
  case 'sign-req':
    pki.signReq(...cmds);
    break;
  default:
}
