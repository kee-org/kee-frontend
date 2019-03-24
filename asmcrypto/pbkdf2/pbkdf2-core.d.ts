import { HmacSha256 } from "../hmac/hmac-sha256";
export declare function pbkdf2core(hmac: HmacSha256, salt: Uint8Array, length: number, count: number): Uint8Array;
