export type Tokens = {
    storage?: string;
    forms?: string;
    identity?: string;
    client?: string;
    sso?: string;
};

export function isTokens (tokens: any): tokens is Tokens {
    return ((tokens as Tokens).storage !== undefined
    || (tokens as Tokens).forms !== undefined
    || (tokens as Tokens).identity !== undefined
    || (tokens as Tokens).client !== undefined
    || (tokens as Tokens).sso !== undefined
    );
}
