/** Fetch wrapper: attaches auth headers (Keycloak bearer token in OIDC mode,
 * X-Dev-* headers in dev mode) and normalizes API errors. */

export class ApiError extends Error {
    status: number;

    constructor(message: string, status: number) {
        super(message);
        this.status = status;
    }
}

let headerProvider: () => Promise<Record<string, string>> = async () => ({});

export function setAuthHeaderProvider(provider: () => Promise<Record<string, string>>) {
    headerProvider = provider;
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
    const response = await fetch(path, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            ...(await headerProvider()),
            ...(options.headers as Record<string, string> | undefined),
        },
    });
    if (!response.ok) {
        let message = `HTTP ${response.status}`;
        try {
            message = (await response.json()).error || message;
        } catch { /* non-JSON error body */ }
        throw new ApiError(message, response.status);
    }
    return response.status === 204 ? (null as T) : response.json();
}

/** Binary attachment transfer. The backend sees ciphertext only; do not use
 * the JSON default Content-Type here. */
export async function apiBinary(path: string, options: RequestInit = {}): Promise<Response> {
    const response = await fetch(path, {
        ...options,
        headers: { ...(await headerProvider()), ...(options.headers as Record<string, string> | undefined) },
    });
    if (!response.ok) {
        let message = `HTTP ${response.status}`;
        try { message = (await response.json()).error || message; } catch { /* opaque gateway response */ }
        throw new ApiError(message, response.status);
    }
    return response;
}
