const sessionManager = {
    setAccessToken: (token: string) => {
        sessionStorage.setItem("jwt", token);
    },
    getAccessToken: () => {
        return sessionStorage.getItem("jwt");
    },
    clearAccessToken: () => {
        sessionStorage.removeItem("jwt");
    },
    setRefreshToken: (token: string) => {
        sessionStorage.setItem("refresh_token", token);
    },
    getRefreshToken: () => {
        return sessionStorage.getItem("refresh_token");
    },
    clearRefreshToken: () => {
        sessionStorage.removeItem("refresh_token");
    },
    setSessionToken: (token: string) => {
        sessionStorage.setItem("session_token", token);
    },
    getSessionToken: () => {
        return sessionStorage.getItem("session_token");
    },
    clearSessionToken: () => {
        sessionStorage.removeItem("session_token");
    }
}

export default sessionManager;