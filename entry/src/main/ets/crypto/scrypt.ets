// Reference:
//  - https://en.wikipedia.org/wiki/Scrypt
//  - https://en.wikipedia.org/wiki/Salsa20
//  - https://github.com/beemdevelopment/Aegis/blob/v3.3/app/src/main/java/com/beemdevelopment/aegis/crypto/bc/SCrypt.java

import { Uint8ArrayToString } from '../common/utils';
import { pbkdf2KeyDerive } from './authUtils';

export interface ScryptMaterial {
    salt: Uint8Array,
    length: number,
    n: number,
    r: number,
    p: number,
}

function salsa20R8(B: Uint32Array) {
    let x = new Uint32Array(B);

    for (let i = 0; i < 8; i++) {
        x[4] ^= (x[0] + x[12]) << 7 | (x[0] + x[12]) >>> (32 - 7);
        x[8] ^= (x[4] + x[0]) << 9 | (x[4] + x[0]) >>> (32 - 9);
        x[12] ^= (x[8] + x[4]) << 13 | (x[8] + x[4]) >>> (32 - 13);
        x[0] ^= (x[12] + x[8]) << 18 | (x[12] + x[8]) >>> (32 - 18);

        x[9] ^= (x[5] + x[1]) << 7 | (x[5] + x[1]) >>> (32 - 7);
        x[13] ^= (x[9] + x[5]) << 9 | (x[9] + x[5]) >>> (32 - 9);
        x[1] ^= (x[13] + x[9]) << 13 | (x[13] + x[9]) >>> (32 - 13);
        x[5] ^= (x[1] + x[13]) << 18 | (x[1] + x[13]) >>> (32 - 18);

        x[14] ^= (x[10] + x[6]) << 7 | (x[10] + x[6]) >>> (32 - 7);
        x[2] ^= (x[14] + x[10]) << 9 | (x[14] + x[10]) >>> (32 - 9);
        x[6] ^= (x[2] + x[14]) << 13 | (x[2] + x[14]) >>> (32 - 13);
        x[10] ^= (x[6] + x[2]) << 18 | (x[6] + x[2]) >>> (32 - 18);

        x[3] ^= (x[15] + x[11]) << 7 | (x[15] + x[11]) >>> (32 - 7);
        x[7] ^= (x[3] + x[15]) << 9 | (x[3] + x[15]) >>> (32 - 9);
        x[11] ^= (x[7] + x[3]) << 13 | (x[7] + x[3]) >>> (32 - 13);
        x[15] ^= (x[11] + x[7]) << 18 | (x[11] + x[7]) >>> (32 - 18);

        x[1] ^= (x[0] + x[3]) << 7 | (x[0] + x[3]) >>> (32 - 7);
        x[2] ^= (x[1] + x[0]) << 9 | (x[1] + x[0]) >>> (32 - 9);
        x[3] ^= (x[2] + x[1]) << 13 | (x[2] + x[1]) >>> (32 - 13);
        x[0] ^= (x[3] + x[2]) << 18 | (x[3] + x[2]) >>> (32 - 18);

        x[6] ^= (x[5] + x[4]) << 7 | (x[5] + x[4]) >>> (32 - 7);
        x[7] ^= (x[6] + x[5]) << 9 | (x[6] + x[5]) >>> (32 - 9);
        x[4] ^= (x[7] + x[6]) << 13 | (x[7] + x[6]) >>> (32 - 13);
        x[5] ^= (x[4] + x[7]) << 18 | (x[4] + x[7]) >>> (32 - 18);

        x[11] ^= (x[10] + x[9]) << 7 | (x[10] + x[9]) >>> (32 - 7);
        x[8] ^= (x[11] + x[10]) << 9 | (x[11] + x[10]) >>> (32 - 9);
        x[9] ^= (x[8] + x[11]) << 13 | (x[8] + x[11]) >>> (32 - 13);
        x[10] ^= (x[9] + x[8]) << 18 | (x[9] + x[8]) >>> (32 - 18);

        x[12] ^= (x[15] + x[14]) << 7 | (x[15] + x[14]) >>> (32 - 7);
        x[13] ^= (x[12] + x[15]) << 9 | (x[12] + x[15]) >>> (32 - 9);
        x[14] ^= (x[13] + x[12]) << 13 | (x[13] + x[12]) >>> (32 - 13);
        x[15] ^= (x[14] + x[13]) << 18 | (x[14] + x[13]) >>> (32 - 18);
    }

    for (let i = 0; i < 16; i++) {
        B[i] += x[i];
    }
}

function Xor_Block32(X32: Uint32Array, b: Uint32Array) {
    for (let i = 0; i < X32.length; i++) {
        X32[i] ^= b[i];
    }
}

// Convert the last 16 words (64 bytes) of the block to a little-endian number
function Integerify32(block: Uint32Array): number {
    const slice = block.subarray(block.length-16, block.length);
    const dataView = new DataView(slice.buffer, slice.byteOffset, slice.byteLength);
    return dataView.getUint32(0, true);
}

function BlockMix32(Y: Uint32Array) {
    const r = Y.length / (2*16); // to (2*r) 16-word chunks
    const B = new Uint32Array(Y);

    let X = new Uint32Array( B.subarray(B.length-16, B.length) );
    for (let i = 0; i < 2 * r; i++) {
        const Bi = B.subarray(i*16, (i+1)*16);
        Xor_Block32(X, Bi);
        salsa20R8(X);
        if (i % 2 === 0) {
            Y.set(X, 8 * i);
        } else {
            Y.set(X, 16 * r + 8 * (i-1));
        }
    }
}

function ROMix(X32: Uint32Array, iterations: number) {
    const V: Array<Uint32Array> = new Array(iterations);
    //
    for (let i = 0; i < iterations; i++) {
        V[i] = new Uint32Array(X32);
        BlockMix32(X32);
    }
    //
    for (let _ = 0; _ < iterations; _++) {
        const j = Integerify32(X32) % iterations;
        Xor_Block32(X32, V[j]);
        BlockMix32(X32);
    }
}

export async function scryptKeyDerive(password: string, material: ScryptMaterial): Promise<Uint8Array> {
    const salt = Uint8ArrayToString(material.salt);
    const blockSize = 128 * material.r;
    const dkLen = blockSize * material.p;
    const dk = await pbkdf2KeyDerive(password, {salt, iteration:1}, dkLen*8);

    const exSalt = new Uint32Array(dkLen>>2);
    //TODO: ROMix could be paralleled
    for (let i = 0; i < material.p; i++) {
        const slice = dk.subarray(i*blockSize, (i+1)*blockSize);
        const B = new Uint32Array(slice.buffer, slice.byteOffset, slice.byteLength>>2);
        ROMix(B, material.n);
        exSalt.set(B, i * blockSize>>2);
    }
    const exSaltStr = Uint8ArrayToString(new Uint8Array(exSalt.buffer));

    const result = await pbkdf2KeyDerive(password, {salt:exSaltStr, iteration:1}, material.length*8);
    return result;
}