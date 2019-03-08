import { RemoteService } from "./RemoteService";
import { User } from "./User";
import { JWT } from "./JWT";

let remoteService: RemoteService;

export class ResetManager {
    public static init (stage: "dev"|"beta"|"prod") {
        remoteService = new RemoteService(stage, "reset");
    }

    static allegedRemainingMinutes (unverifiedJWTString: string): number {

        if (!unverifiedJWTString) {
            return 0;
        }

        const unverifiedJWT = JWT.parse(unverifiedJWTString);
        if (!unverifiedJWT || !unverifiedJWT.sub || !unverifiedJWT.exp) {
            return 0;
        }
        return Math.floor((unverifiedJWT.exp - Date.now()) / 60000);
    }

    static async resetUser (email: string, unverifiedJWTString: string, hashedMasterKey: ArrayBuffer) {
        if (!remoteService) {
            return false;
        }
        const userOrFalse = await User.fromResetProcess(email, unverifiedJWTString, hashedMasterKey, payload => {
            return remoteService.postRequest("resetPasswordConfirm", payload, unverifiedJWTString);

        });
        return userOrFalse;
    }

}
