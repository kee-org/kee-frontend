import { Tokens } from "./Tokens";

import * as srp from "secure-remote-password/client";
import { bufferToBase64, hex2base64, base642hex, base64toByteArray, hexStringToByteArray, bufferToHex, utf8encode } from "./Utils";
import { JWT } from "./JWT";
import { RemoteService, isResponse } from "./RemoteService";
import { KeeError } from "./KeeError";
import { Claim } from "./Claim";
import { Response } from "superagent";
import { Pbkdf2HmacSha256 } from "./asmcrypto/entry-export_all";

let remoteService: RemoteService;
let tokenChangeHandler: (tokens: Tokens) => void;

export type Feature = string;

export class Features {
    enabled: Feature[];
    validUntil: number;
    source: string;
}


export class User {
    private email: string;
    private _emailHashed: string;
    public get emailHashed (): string {
        return this._emailHashed;
    }
    private _userId: string;
    public get userId (): string {
        return this._userId;
    }
    private salt: string;
    private passKey: string;
    private features: Features;
    private _tokens: Tokens;
    public get tokens (): Tokens {
        return this._tokens;
    }
    private loginParameters?: { clientEphemeral: srp.Ephemeral, B: string, authId: string, nonce: string };
    private _verificationStatus: AccountVerificationStatus = AccountVerificationStatus.Never;
    public get verificationStatus (): AccountVerificationStatus {
        return this._verificationStatus;
    }

    // hashedMasterKey may come from a combination of password and keyfile in future but for now, we require a text password
    static async fromEmailAndKey (email: string, hashedMasterKey: ArrayBuffer) {
        const user = new User();
        user.email = email;
        user.passKey = await user.derivePassKey(email, hashedMasterKey);
        user._emailHashed = await hashString(email, EMAIL_ID_SALT);
        return user;
    }

    static async fromEmail (email: string) {
        const user = new User();
        user.email = email;
        user._emailHashed = await hashString(email, EMAIL_ID_SALT);
        return user;
    }

    static async fromResetProcess (email: string, unverifiedJWTString: string, hashedMasterKey: ArrayBuffer,
        sendResetConfirmation: (obj: object) => Promise<KeeError|Response>) {
        if (!remoteService) {
            return false;
        }

        if (!unverifiedJWTString) {
            return false;
        }

        if (!email) {
            console.error("Email missing. Can't complete reset procedure.");
            return false;
        }

        const unverifiedJWT = JWT.parse(unverifiedJWTString);
        if (!unverifiedJWT || !unverifiedJWT.sub) {
            return false;
        }

        const user = new User();
        user.email = email;
        user.passKey = await user.derivePassKey(email, hashedMasterKey);
        user._emailHashed = await hashString(email, EMAIL_ID_SALT);

        // Mostly just a sanity check to ensure truncated links can't result in an invalid
        // verifier being associated with the user's account
        if (unverifiedJWT.sub !== user._emailHashed) {
            console.error("Email mismatch. Can't complete reset procedure.");
            return false;
        }

        const hexSalt = srp.generateSalt();
        const salt = hex2base64(hexSalt);
        user.salt = salt;

        const privateKey = srp.derivePrivateKey(hexSalt, unverifiedJWT.sub, user.passKey);
        const verifier = hex2base64(srp.deriveVerifier(privateKey));

        try {
            const response = await sendResetConfirmation({
                verifier,
                salt
            });

            if (!isResponse(response)) {
                return false;
            }
            await user.parseJWTs(response.body.JWTs);
            return user;
        } catch (e) {
            console.error(e);
            return false;
        }
    }

    public currentFeatures () {
        return this.features ? this.features.enabled : [];
    }

    public setUserId (userId: string) {
        this._userId = userId;
    }

    public async derivePassKey (email: string, hashedMasterKey: ArrayBuffer) {
        const emailHash = await hashString(email, EMAIL_AUTH_SALT);
        const passHash = await hashByteArray(new Uint8Array(hashedMasterKey), hexStringToByteArray(PASS_AUTH_SALT));
        const b1 = base64toByteArray(emailHash);
        const b2 = base64toByteArray(passHash);
        const byteArray = new Uint8Array(b1.byteLength+b2.byteLength);
        byteArray.set(b1);
        byteArray.set(b2, b1.length);
        return stretchByteArray(byteArray, STRETCH_SALT);
    }

    public async register (introEmailStatus: number, marketingEmailStatus: number, isMobile: boolean, code: string) {
        if (!remoteService) {
            return KeeError.InvalidState;
        }

        const hexSalt = srp.generateSalt();
        const salt = hex2base64(hexSalt);
        this.salt = salt;

        const privateKey = srp.derivePrivateKey(hexSalt, this.emailHashed, this.passKey);
        const verifier = hex2base64(srp.deriveVerifier(privateKey));

        try {
            const response = await remoteService.postUnauthenticatedRequest("register", {
                emailHashed: this.emailHashed,
                verifier,
                salt,
                email: this.email,
                introEmailStatus,
                marketingEmailStatus,
                mob: isMobile ? 1 : 0,
                code
            });

            if (isResponse(response)) {
                if (response.status !== 201) {
                    console.error("Unexpected status code");
                    return KeeError.Unexpected;
                }

                await this.parseJWTs(response.body.JWTs);
                return true;
            }

            if (response === KeeError.ServerConflict) {
                return KeeError.AlreadyRegistered; // .......... similar.......
            }
            return response;

        } catch (e) {
            console.error(e);
            return KeeError.Unexpected;
        }

    }

    public async loginStart () {
        if (!remoteService) {
            return KeeError.InvalidState;
        }

        try {
            const request1 = remoteService.postUnauthenticatedRequest("loginStart", {
                emailHashed: this.emailHashed
            });
            const clientEphemeral = srp.generateEphemeral();
            const response1 = await request1;

            if (isResponse(response1)) {
                const srp1 = response1.body as SRP1;
                this.salt = srp1.salt;
                const nonce = srp1.costFactor > 0 ? await calculateCostNonce(srp1.costFactor, srp1.costTarget!) : "";

                this.loginParameters = { clientEphemeral, B: srp1.B, authId: srp1.authId, nonce };
                return { kms: srp1.kms };
            }

            // We can't handle any errors. The server is either working with a 200 response or failed in some unexpected way
            return response1;

        } catch (e) {
            console.error(e);
            return KeeError.Unexpected;
        }
    }

    async loginFinish (hashedMasterKey?: ArrayBuffer) {
        if (!remoteService) {
            return KeeError.InvalidState;
        }

        if (hashedMasterKey) {
            if (!this.email) {
                console.error("Email missing. Can't complete login procedure.");
                return KeeError.InvalidState;
            }
            this.passKey = await this.derivePassKey(this.email, hashedMasterKey);
        }

        if (!this.loginParameters) {
            return KeeError.MaybeOffline;
        }

        if (!this.emailHashed) {
            console.error("Hashed email missing. Can't complete login procedure.");
            return KeeError.InvalidState;
        }
        if (!this.salt) {
            console.error("salt missing. Can't complete login procedure.");
            return KeeError.InvalidState;
        }
        if (!this.passKey) {
            console.error("passKey missing. Can't complete login procedure.");
            return KeeError.InvalidState;
        }
        if (!this.loginParameters.clientEphemeral) {
            console.error("clientEphemeral missing. Can't complete login procedure.");
            return KeeError.InvalidState;
        }
        if (!this.loginParameters.B) {
            console.error("B missing. Can't complete login procedure.");
            return KeeError.InvalidState;
        }
        if (!this.loginParameters.authId) {
            console.error("authId missing. Can't complete login procedure.");
            return KeeError.InvalidState;
        }

        const privateKey = srp.derivePrivateKey(base642hex(this.salt), this.emailHashed, this.passKey);
        const clientSession = srp.deriveSession(
            this.loginParameters.clientEphemeral.secret,
            base642hex(this.loginParameters.B),
            base642hex(this.salt),
            this.emailHashed,
            privateKey);

        try {
            const response2 = await remoteService.postUnauthenticatedRequest("loginFinish", {
                emailHashed: this.emailHashed,
                clientSessionEphemeral: hex2base64(this.loginParameters.clientEphemeral.public),
                authId: this.loginParameters.authId,
                costNonce: this.loginParameters.nonce,
                clientSessionProof: hex2base64(clientSession.proof)
            });

            if (isResponse(response2)) {
                const srp2 = response2.body as SRP2;

                try {
                    srp.verifySession(this.loginParameters.clientEphemeral.public, clientSession, base642hex(srp2.proof));
                } catch (e) {
                    return KeeError.LoginFailedMITM;
                }

                await this.parseJWTs(srp2.JWTs);
                this._verificationStatus = srp2.verificationStatus;
                return true;
            }

            // If we are told we need to login after attempting to do so, clearly there
            // were invalid authentication credentials supplied
            if (response2 === KeeError.LoginRequired) {
                return KeeError.LoginFailed;
            }

            // We can't handle any other errors
            return response2;

        } catch (e) {
            console.error(e);
            return KeeError.Unexpected;
        }
    }

    async applyCouponToSubscription (code: string) {
        if (!remoteService) {
            return KeeError.InvalidState;
        }
        if (!this.email) {
            console.error("Email missing. Can't apply coupon.");
            return KeeError.InvalidState;
        }
        if (!this.emailHashed) {
            console.error("Hashed email missing. Can't apply coupon.");
            return KeeError.InvalidState;
        }
        if (!code) {
            console.error("Code missing. Can't apply coupon.");
            return KeeError.InvalidState;
        }

        try {
            const response = await remoteService.getRequest(`applyCoupon/${code}`,
                this.tokens ? this.tokens.identity : undefined, () => this.refresh());

            if (!isResponse(response)) {
                if (response === KeeError.LoginRequired) {
                    return KeeError.LoginFailed;
                }
                // We can't handle any other errors
                return response;
            }
            return response.ok;
        } catch (e) {
            console.error(e);
            return KeeError.Unexpected;
        }
    }

    async refresh () {
        if (!remoteService) {
            return KeeError.InvalidState;
        }

        try {
            let response: KeeError|Response = KeeError.LoginRequired;
            if (this.tokens && this.tokens.identity) {
                response = await remoteService.postRequest("refresh", {}, this.tokens.identity);

                if (isResponse(response)) {
                    if (response.status !== 200) {
                        console.error("Unexpected status code");
                        return KeeError.Unexpected;
                    }

                    await this.parseJWTs(response.body.JWTs);
                    return this.tokens;
                }
            }

            if (response === KeeError.LoginRequired) {

                // We need to reauthenticate. If we have a cached User object with
                // a hashedPassword and emailHashed, we can trigger the login process automatically...
                // but if not, or it it fails, we need to force the user's session to logout and ask them
                // to login again. Initially this will involve logging out of the vault DBs too but perhaps could relax that one day.
                try {
                    if (this.emailHashed && this.passKey) {
                        await this.loginStart();
                        const loginResult = await this.loginFinish();
                        return loginResult === true ? this.tokens : loginResult;
                    } else {
                        return KeeError.LoginRequired;
                    }
                } catch (error) {
                    return KeeError.LoginRequired;
                }
            }

            // We can't handle any other errors
            return response;

        } catch (e) {
            console.error(e);
            return KeeError.Unexpected;
        }
    }

    async resendVerificationEmail () {
        if (!remoteService) {
            return KeeError.InvalidState;
        }
        if (!this.tokens || !this.tokens.identity) {
            return KeeError.InvalidState;
        }

        try {
            const response = await remoteService.postRequest("resendVerificationEmail", {}, this.tokens.identity);

            if (isResponse(response)) {
                if (response.status !== 200) {
                    console.error("Unexpected status code");
                    return KeeError.Unexpected;
                }
                return true;
            }

            if (response === KeeError.LoginRequired) {

                // We need to reauthenticate. If we have a cached User object with
                // a hashedPassword and emailHashed, we can trigger the login process automatically...
                try {
                    if (this.emailHashed && this.passKey) {
                        await this.loginStart();
                        const success = await this.loginFinish();
                        return success;
                    } else {
                        return KeeError.LoginRequired;
                    }
                } catch (error) {
                    return KeeError.LoginRequired;
                }
            }

            // We can't handle any other errors
            return response;

        } catch (e) {
            console.error(e);
            return KeeError.Unexpected;
        }
    }

    async restartTrial () {
        if (!remoteService) {
            return KeeError.InvalidState;
        }

        if (!this.emailHashed) {
            console.error("Hashed email missing. Can't complete trial restart procedure.");
            return KeeError.InvalidState;
        }

        try {
            const response1 = await remoteService.getRequest("restartTrial/", this.tokens ? this.tokens.identity : undefined, () => this.refresh());

            if (!isResponse(response1)) {
                if (response1 === KeeError.LoginRequired) {
                    return KeeError.LoginFailed;
                }
                // We can't handle any other errors
                return response1;
            }
            return true;
        } catch (e) {
            console.error(e);
            return KeeError.Unexpected;
        }
    }

    async changePassword (hashedMasterKey: ArrayBuffer, onChangeStarted: () => Promise<boolean>) {
        if (!remoteService) {
            return KeeError.InvalidState;
        }

        if (!this.email) {
            console.error("Email missing. Can't complete change password procedure.");
            return KeeError.InvalidState;
        }

        const newPassKey = await this.derivePassKey(this.email, hashedMasterKey);

        if (!this.emailHashed) {
            console.error("Hashed email missing. Can't complete change password procedure.");
            return KeeError.InvalidState;
        }
        if (!this.salt) {
            console.error("salt missing. Can't complete change password procedure.");
            return KeeError.InvalidState;
        }
        if (!newPassKey) {
            console.error("passKey missing. Can't complete change password procedure.");
            return KeeError.InvalidState;
        }

        const privateKey = srp.derivePrivateKey(base642hex(this.salt), this.emailHashed, newPassKey);
        const verifier = hex2base64(srp.deriveVerifier(privateKey));

        try {
            const response1 = await remoteService.postRequest("changePasswordStart", {
                verifier
            }, this.tokens ? this.tokens.identity : undefined, () => this.refresh());

            if (!isResponse(response1)) {
                if (response1 === KeeError.LoginRequired) {
                    return KeeError.LoginFailed;
                }
                // We can't handle any other errors
                return response1;
            }

            const success = await onChangeStarted();

            if (!success) {
                throw new Error("Password change aborted.");
            }

            const response2 = await remoteService.postRequest("changePasswordFinish", {},
                this.tokens ? this.tokens.identity : undefined, () => this.refresh());

            if (isResponse(response2)) {
                this.passKey = newPassKey;
                await this.parseJWTs(response2.body.JWTs);
                return true;
            } else {
                if (response2 === KeeError.LoginRequired) {
                    return KeeError.LoginFailed;
                }
                // We can't handle any other errors
                return response2;
            }

        } catch (e) {
            console.error(e);
            return KeeError.Unexpected;
        }
    }

    async resetStart () {
        if (!remoteService) {
            return false;
        }

        if (!this.email) {
            console.error("Email missing. Can't reset.");
            return false;
        }
        if (!this.emailHashed) {
            console.error("Hashed email missing. Can't reset.");
            return false;
        }

        try {
            const response1 = await remoteService.postUnauthenticatedRequest("resetPasswordRequest", {
                emailHashed: this.emailHashed
            });

            if (!isResponse(response1)) {
                // We can't handle any errors
                return false;
            }

            const unverifiedJWTString = response1.body.jwt;
            if (!unverifiedJWTString) {
                return false;
            }

            const unverifiedJWT = JWT.parse(unverifiedJWTString);
            if (!unverifiedJWT || !unverifiedJWT.costTarget || !unverifiedJWT.costFactor) {
                return false;
            }
            const nonce = await calculateCostNonce(unverifiedJWT.costFactor, unverifiedJWT.costTarget);

            const response2 = await remoteService.postUnauthenticatedRequest("resetPasswordStart", {
                authToken: unverifiedJWTString,
                costNonce: nonce
            });

            if (isResponse(response2)) {
                return response2.ok;
            }
        } catch (e) {
            console.error(e);
        }
        return false;
    }

    private async parseJWTs (JWTs: string[]) {

        this._tokens = {};

        // Extract features from the client claim supplied by the server and cache
        // the other claims for later forwarding back to the server
        for (const jwt of JWTs) {
            try {
                const { audience, claim } = await JWT.verify(jwt, remoteService.stage);
                switch (audience) {
                case "client": {
                    if (claim !== undefined) {
                        // Don't do anything in the unlikely event that the JWT has already expired
                        if (claim.exp > Date.now()) {
                            this.features = {
                                enabled: claim.features,
                                source: "unknown",
                                validUntil: claim.featureExpiry
                            };
                            this._userId = claim.sub;
                            this._tokens.client = jwt;
                        }
                    }
                } break;
                case "storage": this._tokens.storage = jwt; break;
                case "forms": this._tokens.forms = jwt; break;
                case "identity": this._tokens.identity = jwt; break;
                case "sso": this._tokens.sso = jwt; break;
                }
            } catch (e) {
                console.log("Token error: " + e);
            }
        }

        if (tokenChangeHandler) tokenChangeHandler(this._tokens);
    }

}

export class UserManager {
    public static init (stage: "dev"|"beta"|"prod", tokenChangeHandlerParam: (tokens: Tokens) => void) {
        remoteService = new RemoteService(stage, "identity");
        tokenChangeHandler = tokenChangeHandlerParam;
    }

    public static verifyJWT (jwt: string): Promise<{audience: string, claim?: Claim | undefined}> {
        return JWT.verify(jwt, remoteService.stage);
    }
}

export async function hashString (text: string, salt?: string) {
    const message = (salt ? salt : "") + text;
    const msgBuffer = utf8encode(message);
    const hash = await crypto.subtle.digest("SHA-256", msgBuffer);
    return bufferToBase64(hash);
}

export async function hashStringToHex (text: string, salt?: string) {
    const message = (salt ? salt : "") + text;
    const msgBuffer = utf8encode(message);
    const hash = await crypto.subtle.digest("SHA-256", msgBuffer);
    return bufferToHex(hash);
}

export async function hashByteArray (text: Uint8Array, salt: Uint8Array) {
    const msgBuffer = new Uint8Array(salt.byteLength+text.byteLength);
    msgBuffer.set(salt);
    msgBuffer.set(text, salt.byteLength);
    const hash = await crypto.subtle.digest("SHA-256", msgBuffer);
    return bufferToBase64(hash);
}

export async function stretchByteArray (byteArray: Uint8Array, salt: string) {
    const saltArray = base64toByteArray(salt);
    try {
        const key = await crypto.subtle.importKey(
            "raw",
            byteArray,
            {
                name: "PBKDF2"
            },
            false,
            ["deriveKey"]
        );

        const derivedKey = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: saltArray,
                iterations: 500,
                hash: { name: "SHA-256" }
            },
            key,
            {
                name: "AES-CTR",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
        const hashBuffer = await crypto.subtle.exportKey("raw", derivedKey);
        return bufferToBase64(hashBuffer);
    } catch (e) {
        // Exception expected in Edge until it switches to Chromium
        // backend, maybe in other rare browsers too.
        return bufferToBase64(Pbkdf2HmacSha256(byteArray, saltArray, 500, 32));
    }
}

export const EMAIL_ID_SALT = "a7d60f672fc7836e94dabbd7000f7ef4e5e72bfbc66ba4372add41d7d46a1c24";
export const EMAIL_AUTH_SALT = "4e1cc573ed8cd48a19beb6ec6729be6c7a19c91a40c6483be3c9d671b5fbae9a";
export const PASS_AUTH_SALT = "a90b6364315150a39a60d324bfafe6f4444deb15bee194a6d34726c31493dacc";
export const STRETCH_SALT = "509d04a4c27ea9947335e7aa45aabe4fcc2222c87daf0f0520712cefb000124a";

export enum AccountVerificationStatus {
    Never,
    Reverify,
    Sent,
    Success
}

class SRP1 {
    costFactor: number;
    costTarget?: string;
    B: string;
    authId: string;
    salt: string;
    kms: string[];
}

class SRP2 {
    proof: string;
    authId: string;
    JWTs: string[];
    verificationStatus: AccountVerificationStatus;
}

//TODO: Might want to do this differently - not sure how much overhead this many async awaits will add
async function calculateCostNonce (costFactor: number, costTarget: string) {
    let nonce = 0;
    let h = await hashStringToHex(costTarget + nonce);
    while (!checkNonce(h, costFactor)) {
        nonce++;
        h = await hashStringToHex(costTarget + nonce);
    }
    return nonce.toString();
}

function checkNonce (proposedSolution: string, costFactor: number) {
    let i;
    for (i = 0; i < proposedSolution.length; i++) {
        if (proposedSolution[i] !== "0") break;
    }
    return i >= costFactor;
}
