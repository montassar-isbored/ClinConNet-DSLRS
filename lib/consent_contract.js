'use strict';

const { Contract } = require('fabric-contract-api');
const crypto = require('crypto');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const BN = require('bn.js');

class ConsentManagementContract extends Contract {

    constructor() {
        super('ConsentManagementContract');
    }

    async QueryConsent(ctx, consent_proof) {
        console.info(`[INFO] QueryConsent execution started for proof: ${consent_proof}`);
        const recordBytes = await ctx.stub.getState(consent_proof);
        
        if (!recordBytes || recordBytes.length === 0) {
            console.error(`[ERROR] Consent proof not found in World State: ${consent_proof}`);
            throw new Error(`Consent proof ${consent_proof} does not exist.`);
        }
        
        console.info(`[INFO] Consent proof retrieved successfully: ${consent_proof}`);
        return recordBytes.toString();
    }

    async PublishConsent(ctx, consent_proof, sigma_json) {
        console.info(`[INFO] PublishConsent execution started for proof: ${consent_proof}`);
        const sigma = JSON.parse(sigma_json);
        
        const isValid = this._dslrsVerify(consent_proof, sigma);
        if (isValid === 0) {
            console.error(`[ERROR] DSLRS Verification failed for proof: ${consent_proof}`);
            throw new Error('DSLRS Verification failed.');
        }
        console.info(`[INFO] DSLRS Verification successful for proof: ${consent_proof}`);

        const consentRecord = {
            consent_proof: consent_proof,
            sigma: sigma,
            status: 'VALID',
            signer: '0' 
        };

        await ctx.stub.putState(consent_proof, Buffer.from(JSON.stringify(consentRecord)));
        console.info(`[INFO] Consent record committed to ledger: ${consent_proof}`);
        return 1;
    }

    async RevokeOrUpdateConsent(ctx, consent_proof_old, consent_proof_new, sigma_new_json) {
        console.info(`[INFO] RevokeOrUpdateConsent started for old proof: ${consent_proof_old}`);
        const oldRecordBytes = await ctx.stub.getState(consent_proof_old);
        if (!oldRecordBytes || oldRecordBytes.length === 0) {
            throw new Error('Old consent proof not found.');
        }

        const oldRecord = JSON.parse(oldRecordBytes.toString());
        if (oldRecord.status !== 'VALID') {
            throw new Error('Old consent is not VALID.');
        }

        const sigma_new = JSON.parse(sigma_new_json);
        const isLinked = this._dslrsLink(oldRecord.sigma, consent_proof_old, sigma_new, consent_proof_new);
        
        if (isLinked === 0) {
            console.error(`[ERROR] Linkability check failed between ${consent_proof_old} and ${consent_proof_new}`);
            throw new Error('Signer or scope mismatch, or invalid signature.');
        }
        console.info(`[INFO] Linkability check successful.`);

        oldRecord.status = 'REVOKED';
        await ctx.stub.putState(consent_proof_old, Buffer.from(JSON.stringify(oldRecord)));
        console.info(`[INFO] Status updated to REVOKED for proof: ${consent_proof_old}`);

        if (consent_proof_new === 'REV') {
            return 0; 
        }

        const newRecord = {
            consent_proof: consent_proof_new,
            sigma: sigma_new,
            status: 'VALID',
            signer: '0'
        };

        await ctx.stub.putState(consent_proof_new, Buffer.from(JSON.stringify(newRecord)));
        console.info(`[INFO] New consent record committed: ${consent_proof_new}`);
        return 1;
    }

    async SubmitDeanonymizationShare(ctx, consent_proof, share_json) {
        console.info(`[INFO] SubmitDeanonymizationShare started for proof: ${consent_proof}`);
        const recordBytes = await ctx.stub.getState(consent_proof);
        if (!recordBytes || recordBytes.length === 0) {
            throw new Error('Consent proof not found.');
        }

        const record = JSON.parse(recordBytes.toString());
        
        if (record.status === 'REVEALED') {
            throw new Error('Consent is already deanonymized.');
        }

        if (!record.pending_shares) {
            record.pending_shares = [];
        }

        const newShare = JSON.parse(share_json);
        
        const exists = record.pending_shares.some(share => share.omega === newShare.omega);
        if (exists) {
            throw new Error('Share from this committee node already submitted.');
        }

        record.pending_shares.push(newShare);
        console.info(`[INFO] Share appended. Total shares: ${record.pending_shares.length}`);

        const k = 8; 
        
        if (record.pending_shares.length >= k) {
            console.info(`[INFO] Threshold reached. Executing _dslrsDeanonymize.`);
            const Ps = this._dslrsDeanonymize(record.sigma, record.pending_shares);
            record.status = 'REVEALED';
            record.signer = Ps;
            console.info(`[INFO] Signer deanonymized successfully.`);
        }

        await ctx.stub.putState(consent_proof, Buffer.from(JSON.stringify(record)));
        return JSON.stringify({ status: record.status, current_shares: record.pending_shares.length });
    }

    _hashToCurve(dataString) {
        const p = ec.curve.p;
        let counter = 0;
        while (true) {
            const hash = crypto.createHash('sha256');
            hash.update(dataString + counter.toString(), 'utf8');
            const hHex = hash.digest('hex');
            const x = new BN(hHex, 16).umod(p);
            
            try {
                const red = BN.red(p);
                const xRed = x.toRed(red);
                const y2Red = xRed.redPow(new BN(3)).redAdd(new BN(7).toRed(red));
                const exp = p.add(new BN(1)).div(new BN(4));
                const yRed = y2Red.redPow(exp);
                const y = yRed.fromRed();

                if (y.mul(y).umod(p).cmp(y2Red.fromRed()) === 0) {
                    return ec.curve.point(x, y);
                }
            } catch (e) {}
            counter++;
        }
    }

    _hashOracle(sid, c1, c2, L_pt, R_pt, A_pt, B_pt) {
        const q = ec.curve.n;
        const hash = crypto.createHash('sha256');
        
        const getXStr = (pt) => {
            if (pt && pt.getX) return pt.getX().toString(10);
            if (pt && pt.x) return new BN(pt.x, 16).toString(10);
            return "0";
        };

        hash.update(sid.toString(), 'utf8');
        hash.update(getXStr(c1), 'utf8');
        hash.update(getXStr(c2), 'utf8');
        hash.update(getXStr(L_pt), 'utf8');
        hash.update(getXStr(R_pt), 'utf8');
        hash.update(getXStr(A_pt), 'utf8');
        hash.update(getXStr(B_pt), 'utf8');
        
        return new BN(hash.digest('hex'), 16).umod(q);
    }

    _dslrsVerify(m, sigma) {
        if (!sigma) return 0;

        const { I_scope, L, SID, P_net, C_1, C_2, ch_0, x, z } = sigma;
        const n = L.length;

        if (n < 3) return 0; 

        let ch = new Array(n).fill(0);
        ch[0] = ch_0;
        
        const q = ec.curve.n;
        const G = ec.g;
        const I_scope_pt = ec.curve.point(new BN(I_scope.x, 16), new BN(I_scope.y, 16));
        const C_1_pt = ec.curve.point(new BN(C_1.x, 16), new BN(C_1.y, 16));
        const C_2_pt = ec.curve.point(new BN(C_2.x, 16), new BN(C_2.y, 16));
        const P_net_pt = ec.curve.point(new BN(P_net.x, 16), new BN(P_net.y, 16));

        for (let i = 0; i < n; i++) {
            let next_i = (i + 1) % n;
            
            const P_i = ec.curve.point(new BN(L[i].x, 16), new BN(L[i].y, 16));
            const dataStr = new BN(L[i].x, 16).toString(10) + SID;
            const Hp_i = this._hashToCurve(dataStr);
            
            const x_i = new BN(x[i], 16);
            const z_i = new BN(z[i], 16);
            const ch_i = new BN(ch[i], 16);
            
            const neg_ch_i = q.sub(ch_i).umod(q);
            const neg_P_i = ec.curve.point(P_i.getX(), P_i.getY().neg().umod(ec.curve.p));
            const C2_minus_Pi = C_2_pt.add(neg_P_i);
            
            const L_i_prime = G.mul(x_i).add(P_i.mul(ch_i));
            const R_i_prime = Hp_i.mul(x_i).add(I_scope_pt.mul(ch_i));
            const A_i_prime = G.mul(z_i).add(C_1_pt.mul(neg_ch_i));
            const B_i_prime = P_net_pt.mul(z_i).add(C2_minus_Pi.mul(neg_ch_i));

            let computed_ch = this._hashOracle(SID, C_1_pt, C_2_pt, L_i_prime, R_i_prime, A_i_prime, B_i_prime);
            
            if (next_i === 0) {
                if (computed_ch.toString(16) === new BN(ch[0], 16).toString(16)) {
                    return 1;
                }
            } else {
                ch[next_i] = computed_ch.toString(16);
            }
        }
        return 0;
    }

    _dslrsLink(sigma_1, m_1, sigma_2, m_2) {
        if (!sigma_1 || !sigma_2) return 0;
        
        const SID_1 = sigma_1.SID;
        const SID_2 = sigma_2.SID;
        
        if (SID_1 !== SID_2) return 0;
        
        if (this._dslrsVerify(m_1, sigma_1) === 1 && this._dslrsVerify(m_2, sigma_2) === 1) {
            if (JSON.stringify(sigma_1.I_scope) === JSON.stringify(sigma_2.I_scope)) {
                return 1;
            }
        }
        return 0;
    }

    _dslrsDeanonymize(sigma, d_shares) {
        const q = ec.curve.n; 
        const k = d_shares.length;
        
        let lam = new Array(k);

        for (let j = 0; j < k; j++) {
            let num = new BN(1);
            let den = new BN(1);
            let omega_j = new BN(d_shares[j].omega, 16);

            for (let i = 0; i < k; i++) {
                if (i !== j) {
                    let omega_i = new BN(d_shares[i].omega, 16);
                    num = num.mul(omega_i).umod(q);
                    let diff = omega_i.sub(omega_j).umod(q);
                    den = den.mul(diff).umod(q);
                }
            }

            let den_inv = den.invm(q);
            lam[j] = num.mul(den_inv).umod(q);
        }

        let V = null;
        for (let j = 0; j < k; j++) {
            let D_j = ec.curve.point(d_shares[j].D.x, d_shares[j].D.y);
            let term = D_j.mul(lam[j]);

            if (V === null) {
                V = term;
            } else {
                V = V.add(term);
            }
        }

        let C_2 = ec.curve.point(sigma.C_2.x, sigma.C_2.y);
        let q_minus_1 = q.sub(new BN(1));
        let V_neg = V.mul(q_minus_1);
        let P_s = C_2.add(V_neg);

        return { 
            x: P_s.getX().toString(16), 
            y: P_s.getY().toString(16) 
        };
    }
}

module.exports = ConsentManagementContract;