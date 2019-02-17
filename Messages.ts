import { User } from "./User";
import { RemoteService, isResponse } from "./RemoteService";
import { KeeError } from "./KeeError";

let remoteService: RemoteService;

export class MessagesManager {

    public static init (stage: "dev"|"beta"|"prod") {
        remoteService = new RemoteService(stage, "messages");
    }

    // any client utilising this library should perform a sanity check that ensures we're not called if
    // we have no suitable token but if not for any reason, the underlying request will be made without
    // the necessary authentication token and a max-retry (3ish) algorithm will kick in, returning an
    // authorisation error to the calling client

    public static async list (user: User) {
        if (!remoteService) {
            return KeeError.InvalidState;
        }

        const token = ( user && user.tokens ) ? user.tokens.identity : undefined;

        try {
            const response = await remoteService.getRequest("v1/", token, () => user.refresh());

            if (isResponse(response)) {
                if (response.status !== 200) {
                    console.error("Unexpected status code");
                    return KeeError.Unexpected;
                }
                return response.body;
            }

            // We can't handle any other type of error
            return response;
        } catch (e) {
            console.error(e);
            return KeeError.Unexpected;
        }
    }

    public static async create (user: User, supportUser: any, message: any) {
        if (!remoteService) {
            return KeeError.InvalidState;
        }

        try {
            const response = await remoteService.postRequest("v1/", {user: supportUser, message}, user.tokens.identity, () => user.refresh());

            if (isResponse(response)) {
                if (response.status !== 200) {
                    console.error("Unexpected status code");
                    return KeeError.Unexpected;
                }
                return true;
            }

            if (response === KeeError.InvalidRequest) {
                console.error("Invalid request");
                return response;
            }

            // We can't handle any other type of error
            return response;
        } catch (e) {
            console.error(e);
            return KeeError.Unexpected;
        }
    }

    public static async add (user: User, supportUser: any, message: any) {
        if (!remoteService) {
            return KeeError.InvalidState;
        }

        try {
            const response = await remoteService.putRequest("v1/", {user: supportUser, message}, user.tokens.identity, () => user.refresh());

            if (isResponse(response)) {
                if (response.status !== 200) {
                    console.error("Unexpected status code");
                    return KeeError.Unexpected;
                }
                return true;
            }

            if (response === KeeError.InvalidRequest) {
                console.error("Invalid request");
                return response;
            }

            // We can't handle any other type of error
            return response;
        } catch (e) {
            console.error(e);
            return KeeError.Unexpected;
        }
    }

}
