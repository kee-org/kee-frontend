import { base64urlDecode, base64urltoByteArray, utf8encode } from "./Utils";
import { Claim } from "./Claim";
import * as elliptic from "elliptic";
import { Sha256 } from "./asmcrypto/entry-export_all";

export class JWT {

    public static parse (sig: string) {
        const sigParts = sig.split(".");

        if (sigParts.length !== 3) {
            throw new Error("Invalid JWT");
        }

        const claimJSON = base64urlDecode(sigParts[1]);
        return JSON.parse(claimJSON);
    }

    public static async verify (sig: string, expectedStage: "dev"|"beta"|"prod"): Promise<{audience: string, claim?: Claim}> {

        const sigParts = sig.split(".");

        if (sigParts.length !== 3) {
            throw new Error("Invalid JWT");
        }

        const claimJSON = base64urlDecode(sigParts[1]);
        let claim: Claim;

        try {
            claim = JSON.parse(claimJSON) as Claim;
            if (claim.aud !== "client") {
                return { audience: claim.aud };
            }
        } catch (e) {
            throw new Error("Invalid claim");
        }

        const data = utf8encode(sigParts[0] + "." + sigParts[1]).buffer;

        // Untrusted source might tell us which key to use but they can't actually pick the
        // key material so we only have to defend against cross-stage server-side breaches
        if ((expectedStage === "dev" && claim.iss !== "idDev") ||
        (expectedStage === "beta" && claim.iss !== "idBeta") ||
        (expectedStage === "prod" && claim.iss !== "idProd")) {
            throw new Error("Claim issued using wrong key pair");
        }

        let jwk;
        switch (claim.iss) {
        case "idProd": jwk = {
            kty: "EC",
            crv: "P-256",
            x: "O6bWMktjPnOtZAkmz9NzMTO9O2VzuECTa9Jj5g90QSA",
            y: "aIE-8dLpJIoAnLIzH1XDCPxK_asKtIC_fVlSLJyGpcg",
            ext: true
        }; break;
        case "idBeta": jwk = {
            kty: "EC",
            crv: "P-256",
            x: "CinRkFHv6IGNcd52YlzD3BF_WruIMs-6Nn5oI7QmgjU",
            y: "pJ66MRPoCC2MUBFdYyRqGPfw3pZEnPGtHVhvspLTVDA",
            ext: true
        }; break;
        case "idDev": jwk = {
            kty: "EC",
            crv: "P-256",
            x: "mk8--wDgrkPyHttzjQH6jxmjfZS9MaHQ5Qzj53OnNLo",
            y: "XAFQCFwKL7qrV27vI1tug3X2v50grAk_ioieHRe8h18",
            ext: true
        }; break;
        default: throw new Error("Unknown JWT issuer so cannot verify");
        }

        let isValid = false;
        try {
            const key = await window.crypto.subtle.importKey(
                "jwk",
                jwk,
                {   //these are the algorithm options
                    name: "ECDSA",
                    namedCurve: "P-256" //can be "P-256", "P-384", or "P-521"
                },
                false, //whether the key is extractable (i.e. can be used in exportKey)
                ["verify"] //"verify" for public key import, "sign" for private key imports
            );

            isValid = await window.crypto.subtle.verify(
                {
                    name: "ECDSA",
                    hash: { name: "SHA-256" } //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                },
                key, //from generateKey or importKey above
                base64urltoByteArray(sigParts[2]), //ArrayBuffer of the signature
                data //ArrayBuffer of the data
            );
        } catch (e) {
            // try again using fallback (slower) - only known
            // beneficiary of this in 2019 is Edge
            try {
                const ec = new elliptic.ec("p256");
                const pubData = { x: base64urltoByteArray(jwk.x), y: base64urltoByteArray(jwk.y) };
                const pubKey = ec.keyFromPublic(pubData as any);
                const digest = new Sha256().process(new Uint8Array(data)).finish().result;
                const sigBuffer = base64urltoByteArray(sigParts[2]);
                const sigObj = { r: sigBuffer.slice(0, 32), s: sigBuffer.slice(32) };
                isValid = ec.verify(digest! as any, sigObj as any, pubKey as any);
            } catch (ex) {
                throw new Error("Error using fallback p256 curve for token verification. Original webcrypto error: " + e + ". This error: " + ex);
            }
        }

        if (!isValid) {
            throw new Error("JWT signature did not verify");
        }

        return { claim, audience: claim.aud };
    }
}
