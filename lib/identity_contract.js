'use strict';

const { Contract } = require('fabric-contract-api');
const crypto = require('crypto');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const BN = require('bn.js');

class IdentityContract extends Contract {

    constructor() {
        super('IdentityContract');
    }

    async RegisterPublicKey(ctx, P_hex_json, pi_json) {
        const P_data = JSON.parse(P_hex_json);
        const pi = JSON.parse(pi_json); // Contains { R_x, R_y, s }
        const SID_1 = "SID_1_REGISTRY"; // Global Registry Scope

        // Validate Point
        if (!P_data.x || !P_data.y) {
            throw new Error('Invalid public key structure.');
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

        // Compute m_i = H(P_i || SID_1)
        const m_i_bn = this._hashFunc(P_data, SID_1);

        // Verify Schnorr Proof-of-Possession
        const isValid = this._schnorrVerify(P_data, m_i_bn, pi);
        if (!isValid) {
            throw new Error('Schnorr Proof-of-Possession verification failed.');
        }

        // Append to L and Publish
        registry.push(P_data);
        await ctx.stub.putState(pubKeyRegistryKey, Buffer.from(JSON.stringify(registry)));

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

    _schnorrVerify(P_data, m_i_bn, pi) {
        const q = ec.curve.n;
        
        const P = ec.curve.point(P_data.x, P_data.y);
        const R = ec.curve.point(pi.R_x, pi.R_y);
        const s = new BN(pi.s, 16);

        // Standard Schnorr Verification: e = H(P || R || m)
        const hash = crypto.createHash('sha256');
        hash.update(P.getX().toString(10) + P.getY().toString(10), 'utf8');
        hash.update(R.getX().toString(10) + R.getY().toString(10), 'utf8');
        hash.update(m_i_bn.toString(10), 'utf8');
        
        const e = new BN(hash.digest('hex'), 16).umod(q);

        // Check: s*G == R + e*P
        const sG = ec.g.mul(s);
        const eP = P.mul(e);
        const rightSide = R.add(eP);

        return sG.eq(rightSide);
    }

    _hashFunc(P_data, SID) {
        const q = ec.curve.n;
        const hash = crypto.createHash('sha256');
        
        const xStr = new BN(P_data.x, 16).toString(10);
        const yStr = new BN(P_data.y, 16).toString(10);
        hash.update(`${xStr},${yStr}`, 'utf8');
        hash.update(SID, 'utf8');
        
        return new BN(hash.digest('hex'), 16).umod(q);
    }
}

module.exports = IdentityContract;