'use strict';
const ConsentManagementContract = require('./lib/consent_contract');
const IdentityContract = require('./lib/identity_contract');

module.exports.ConsentManagementContract = ConsentManagementContract;
module.exports.IdentityContract = IdentityContract;
module.exports.contracts = [ConsentManagementContract, IdentityContract];