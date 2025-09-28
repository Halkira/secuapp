import React from "react";
import { Navigate } from "react-router-dom";
import sessionManager from "./sessionManager";

interface ProtectedRouteProps {
    children: React.ReactElement;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
    const token = sessionManager.getAccessToken();

    if (!token) {
        return <Navigate to="/Login" replace />;
    }

    return children;
};

export default ProtectedRoute;