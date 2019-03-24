import { sha256result } from './sha256/sha256.asm';
export declare abstract class Hash<T extends sha256result> {
    result: Uint8Array | null;
    pos: number;
    len: number;
    asm: T;
    heap: Uint8Array;
    BLOCK_SIZE: number;
    HASH_SIZE: number;
    reset(): this;
    process(data: Uint8Array): this;
    finish(): this;
}
