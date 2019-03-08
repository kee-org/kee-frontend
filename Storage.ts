import { User } from "./User";
import { RemoteService, isResponse } from "./RemoteService";
import { KeeError } from "./KeeError";

let remoteService: RemoteService;

export enum StorageType {
    KEE_S3 = "kee-s3"
}

export type URLlist = {ul: string, dl: string, st: string};

export class StorageItem {
    public emailHashed: string;
    public schemaVersion: number;
    public id: string;
    public location: string;
    public type: StorageType;
    public urls: URLlist;
    public name: string;

    public constructor (init?: Partial<StorageItem>) {
        Object.assign(this, init);
    }

    static fromEmailHash (emailHashed: string) {
        const si = new StorageItem({ emailHashed, schemaVersion: 1, type: StorageType.KEE_S3 });
        return si;
    }

    static fromEmailHashAndId (emailHashed: string, id: string) {
        const si = new StorageItem({ emailHashed, schemaVersion: 1, type: StorageType.KEE_S3, id });
        return si;
    }
}

export class StorageManager {

    public static init (stage: "dev"|"beta"|"prod") {
        remoteService = new RemoteService(stage, "storage");
    }

    // any client utilising this library should perform a sanity check that ensures we're not called if
    // we have no storage token but if not for any reason, the underlying request will be made without
    // the necessary authentication token and a max-retry (3ish) algorithm will kick in, returning an
    // authorisation error to the calling client

    public static async list (user: User) {
        if (!remoteService) {
            return KeeError.InvalidState;
        }
        if (!user) {
            return KeeError.InvalidRequest;
        }
        const storageToken = user.tokens ? user.tokens.storage : undefined;

        try {
            const response = await remoteService.getRequest("meta/", storageToken, () => user.refresh());

            if (isResponse(response)) {
                if (response.status !== 200) {
                    console.error("Unexpected status code");
                    return KeeError.Unexpected;
                }

                return (response.body as any[]).map(s => new StorageItem({
                    id: s.id,
                    name: s.name,
                    location: s.location,
                    type: s.type,
                    emailHashed: s.emailHashed,
                    schemaVersion: s.schemaVersion,
                    urls: s.urls }));
            }

            // We can't handle any other type of error
            return response;

        } catch (e) {
            console.error(e);
            return KeeError.Unexpected;
        }

    }

    public static async create (user: User, name: string, emptyVault: string) {
        if (!remoteService) {
            return KeeError.InvalidState;
        }
        if (!user) {
            return KeeError.InvalidRequest;
        }
        const storageToken = user.tokens ? user.tokens.storage : undefined;

        try {
            const si = StorageItem.fromEmailHash(user.emailHashed);
            si.name = name;
            const response = await remoteService.postRequest("meta/", { si, emptyVault }, storageToken, () => user.refresh());

            if (isResponse(response)) {
                if (response.status !== 200) {
                    console.error("Unexpected status code");
                    return KeeError.Unexpected;
                }

                return response.body as StorageItem;
            }

            if (response === KeeError.ServerConflict) {
                console.error("Tried to create non-primary DB when no primary DB exists");
                return KeeError.MissingPrimaryDB;
            }
            if (response === KeeError.InvalidRequest) {
                console.error("Mismatched email hash");
                return response;
            }

            // We can't handle any other type of error
            return response;

        } catch (e) {
            console.error(e);
            return KeeError.Unexpected;
        }

    }

    public static async update (user: User, si: StorageItem) {
        if (!remoteService) {
            return KeeError.InvalidState;
        }
        if (!user) {
            return KeeError.InvalidRequest;
        }
        const storageToken = user.tokens ? user.tokens.storage : undefined;

        try {
            const response = await remoteService.postRequest("meta/" + si.id, si, storageToken, () => user.refresh());

            if (isResponse(response)) {
                if (response.status !== 200) {
                    console.error("Unexpected status code");
                    return KeeError.Unexpected;
                }

                return true;
            }

            if (response === KeeError.InvalidRequest) {
                console.error("Mismatched email hash");
                return response;
            }
            if (response === KeeError.NotFound) {
                console.error("DB no longer exists. Perhaps the user ID has changed?");
                return response;
            }

            // We can't handle any other type of error
            return response;
        } catch (e) {
            console.error(e);
            return KeeError.Unexpected;
        }

    }

    public static async refreshItemLinks (user: User, id: string) {
        if (!remoteService) {
            return KeeError.InvalidState;
        }
        if (!user) {
            return KeeError.InvalidRequest;
        }
        const storageToken = user.tokens ? user.tokens.storage : undefined;

        try {
            const response = await remoteService.getRequest("itemLinks/" + id, storageToken, () => user.refresh());

            if (isResponse(response)) {
                if (response.status !== 200) {
                    console.error("Unexpected status code");
                    return KeeError.Unexpected;
                }

                return response.body as URLlist;
            }

            if (response === KeeError.NotFound) {
                console.error("DB no longer exists. Perhaps the user ID has changed?");
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
