'use strict';

const { Contract } = require('fabric-contract-api');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

class IdentityContract extends Contract {

    constructor() {
        super('IdentityContract');
    }

    async RegisterPublicKey(ctx, P_hex_json = null) {
        // Verify that the transaction is invoked using a valid X.509 certificate
        const clientID = ctx.clientIdentity.getID();
        const mspID = ctx.clientIdentity.getMSPID();
        if (!clientID || !clientID.startsWith('x509::')) {
            throw new Error('Unauthorized: A valid X.509 certificate is required to register a public key.');
        }

        if (!P_hex_json) {
            throw new Error('Missing public key payload.');
        }

        const P_data = JSON.parse(P_hex_json);

        // Validate Point structure and curve membership
        if (!P_data || !P_data.x || !P_data.y) {
            throw new Error('Invalid public key structure.');
        }

        const P = ec.curve.point(P_data.x, P_data.y);
        if (!ec.curve.validate(P)) {
            throw new Error('Invalid public key: Point is not on the secp256k1 curve.');
        }

        const pubKeyRegistryKey = 'GLOBAL_PUB_KEY_REGISTRY';
        let registryBytes = await ctx.stub.getState(pubKeyRegistryKey);
        let registry = [];

        if (registryBytes && registryBytes.length > 0) {
            registry = JSON.parse(registryBytes.toString());
        }

        // Check if P is already in registry
        const exists = registry.some(key => key.x === P_data.x && key.y === P_data.y);
        if (exists) {
            throw new Error('Public key already registered.');
        }

        // Append to L and Publish
        registry.push({ x: P_data.x, y: P_data.y });
        await ctx.stub.putState(pubKeyRegistryKey, Buffer.from(JSON.stringify(registry)));
        console.info(`[INFO] Public key registered by ${mspID} (${clientID})`);

        return 1;
    }

    async GetRegistry(ctx) {
        const pubKeyRegistryKey = 'GLOBAL_PUB_KEY_REGISTRY';
        let registryBytes = await ctx.stub.getState(pubKeyRegistryKey);
        if (!registryBytes || registryBytes.length === 0) {
            return JSON.stringify([]);
        }
        return registryBytes.toString();
    }
}

module.exports = IdentityContract;
