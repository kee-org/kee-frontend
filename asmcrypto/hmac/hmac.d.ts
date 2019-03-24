import { Hash } from '../hash/hash';
import { sha256result } from '../hash/sha256/sha256.asm';
export declare abstract class Hmac<T extends Hash<sha256result>> {
    hash: T;
    protected BLOCK_SIZE: number;
    HMAC_SIZE: number;
    protected key: Uint8Array;
    protected verify: Uint8Array | null;
    result: Uint8Array | null;
    protected constructor(hash: T, password: Uint8Array, verify?: Uint8Array);
    process(data: Uint8Array): this;
    finish(): this;
    _hmac_init_verify(verify: Uint8Array): void;
}
export declare function _hmac_key(hash: Hash<sha256result>, password: Uint8Array): Uint8Array;
