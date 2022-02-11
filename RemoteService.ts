import * as request from "superagent";
import { Tokens, isTokens } from "./Tokens";
import { KeeError } from "./KeeError";

/* SUPERAGENT WEIRDNESS:

Invoking send does NOT SEND ANYTHING.

Instead it performs more preparation work on the Request object.

The actual send operation is started when the Request's (Promise-like) then function is called.

In our code this is at the point we await the Request (or potentially call Promise.all()
although I'm not convinced this will actually parallelise requests - hopefully the inner
promise stuff within then() will make this work but we don't need it at time of
writing so I've not verified one way or the other.)

*/

class RequestConfig {

    constructor (
        private _endpoint: string,
        public path: string,
        public method: "GET"|"POST"|"PUT",
        public retriesRemaining: number = 3,
        public token?: string,
        public tokenRefresh?: (() => Promise<Tokens | KeeError >),
        public obj?: object
    ) {}

    public prepRequest () {
        let req: request.SuperAgentRequest;
        switch (this.method) {
        case "POST": req = request.post(this._endpoint + this.path); break;
        case "PUT": req = request.put(this._endpoint + this.path); break;
        default: req = request.get(this._endpoint + this.path); break;
        }
        if (this.token) {
            req = req.query("t=" + this.token);
        }
        req = req.type("text/plain").timeout({ response: 30000, deadline: 90000 });

        if (this.obj) {
            return req.send(JSON.stringify(this.obj));
        } else {
            return req.send();
        }
    }
}

const endpoints: any = {
    dev: {
        storage: "https://s-dev.kee.pm/",
        identity: "https://id-dev.kee.pm/",
        messages: "https://msg-dev.kee.pm/",
        reset: "https://resetacc-dev.kee.pm/"
    },
    beta: {
        storage: "https://s-beta.kee.pm/",
        identity: "https://id-beta.kee.pm/",
        messages: "https://msg-beta.kee.pm/",
        reset: "https://resetacc-beta.kee.pm/"
    },
    prod: {
        storage: "https://s.kee.pm/",
        identity: "https://id.kee.pm/",
        messages: "https://msg.kee.pm/",
        reset: "https://resetacc.kee.pm/"
    }
};

export class RemoteService {
    private _endpoint: string;

    constructor (private _stage: "dev"|"beta"|"prod", private _name: string) {
        this._endpoint = endpoints[this._stage][this._name];
    }

    public get stage (): "dev"|"beta"|"prod" {
        return this._stage;
    }

    public async getRequest (path: string,
        token?: string|undefined,
        tokenRefresh?: (() => Promise<Tokens | KeeError >)) {

        const config = new RequestConfig(this._endpoint, path, "GET", 3, token, tokenRefresh);
        return this.doRequest(config);
    }

    public async getUnauthenticatedRequest (path: string) {
        const config = new RequestConfig(this._endpoint, path, "GET");
        return this.doRequest(config);
    }

    public async postRequest (path: string,
        obj: object,
        token?: string|undefined,
        tokenRefresh?: (() => Promise<Tokens | KeeError >)) {

        const config = new RequestConfig(this._endpoint, path, "POST", 3, token, tokenRefresh, obj);
        return this.doRequest(config);
    }

    public async postUnauthenticatedRequest (path: string, obj: object) {
        const config = new RequestConfig(this._endpoint, path, "POST", 3, undefined, undefined, obj);
        return this.doRequest(config);
    }

    public async putRequest (path: string,
        obj: object,
        token?: string|undefined,
        tokenRefresh?: (() => Promise<Tokens | KeeError >)) {

        const config = new RequestConfig(this._endpoint, path, "PUT", 3, token, tokenRefresh, obj);
        return this.doRequest(config);
    }

    public async putUnauthenticatedRequest (path: string, obj: object) {
        const config = new RequestConfig(this._endpoint, path, "PUT", 3, undefined, undefined, obj);
        return this.doRequest(config);
    }

    private findRequestToken (tokens: Tokens) {
        switch (this._name) {
        case "identity": return tokens.identity;
        case "forms": return tokens.forms;
        case "client": return tokens.client;
        case "storage": return tokens.storage;
        case "messages": return tokens.identity;
        default: throw new Error(`Invalid RemoteService configuration. ${this._name} token not known.`);
        }
    }

    //TODO: Perhaps introduce a delay for all but the first retry? varying based on type of error received.
    //TODO: Extend retry support to other errors - e.g. timeouts.
    private async doRequest (config: RequestConfig): Promise<request.Response | KeeError> {
        try {
            if (!config.token && config.tokenRefresh) {
                const tokensOrError = await config.tokenRefresh();
                if (!isTokens(tokensOrError)) {
                    return tokensOrError;
                }
                config.token = this.findRequestToken(tokensOrError);
            }
            const req = config.prepRequest();
            const response = await req;
            return response;
        } catch (e: any) {
            if (e.timeout) {
                if (e.message.indexOf("Response timeout of ") === 0) {
                    return KeeError.ServerUnreachable;
                }
                return KeeError.ServerTimeout;
            }
            if (e.status) {
                switch (e.status) {
                case 404: return KeeError.NotFound;
                case 403:
                    if (config.tokenRefresh && config.retriesRemaining > 0) {
                        const tokensOrError = await config.tokenRefresh();
                        if (!isTokens(tokensOrError)) {
                            return tokensOrError;
                        }
                        const retryToken = this.findRequestToken(tokensOrError);
                        config.token = retryToken;
                        config.retriesRemaining--;
                        return this.doRequest(config);
                    } else {
                        return KeeError.LoginRequired;
                    }

                case 402: return KeeError.ExceededQuota;
                case 400: return KeeError.InvalidRequest;
                case 409: return KeeError.ServerConflict;
                case 500: return KeeError.ServerFail;
                }
            }
            return KeeError.Unexpected;
        }
    }
}

export function isResponse (response: any): response is request.Response {
    return ((response as request.Response).body !== undefined);
}
