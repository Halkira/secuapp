import React from "react";
import { Navigate } from "react-router-dom";
import sessionManager from "./sessionManager";

interface UnprotectedRouteProps {
    children: React.ReactElement;
}

const UnprotectedRoute: React.FC<UnprotectedRouteProps> = ({ children }) => {
    const token = sessionManager.getAccessToken();

    if (token) {
        return <Navigate to="/Home" replace />;
    }

    return children;
};

export default UnprotectedRoute;