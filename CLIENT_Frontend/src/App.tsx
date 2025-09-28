import React from "react";
import { createBrowserRouter, Navigate, RouterProvider } from "react-router-dom";
import "./Styles.scss";
import Root from "./pages/root/Root";
import Home from "./pages/home/Home";
import SharedStream from "./pages/stream/Stream.tsx";
import RegisterPage from "./pages/login_register/Register.tsx";
import LoginPage from "./pages/login_register/Login.tsx";
import Shared from "./pages/shared/Shared.tsx";
import ApproveDevice from "./pages/devices/ApproveDevice.tsx";
import LoggedProtectedRoute from "./components/LoggedProtectedRoute.tsx";
import ProtectedRoute from "./components/protectedRoute.tsx";


const App: React.FC = () => {
    const router = createBrowserRouter([
        {
            path: "/",
            element: <Root />,
            children: [
                { path: "/", element: <Navigate to="/Home" /> },
                { path: '*', element: <Navigate to="/Home" /> },

                { path: 'Register', element: <LoggedProtectedRoute><RegisterPage /></LoggedProtectedRoute> },
                { path: 'Login', element: <LoggedProtectedRoute><LoginPage /></LoggedProtectedRoute> },

                // { path: 'Home', element: <Home /> }, Unprotected routes
                // { path: 'Stream', element: <SharedStream /> },
                // { path: 'Shared', element: <Shared />},
                // { path: 'ApproveDevice', element: <ApproveDevice />},

                { path: 'Home', element: <ProtectedRoute><Home /></ProtectedRoute> },
                { path: 'Stream', element: <ProtectedRoute><SharedStream /></ProtectedRoute> },
                { path: 'Shared', element: <ProtectedRoute><Shared /></ProtectedRoute>},
                { path: 'ApproveDevice', element: <ProtectedRoute><ApproveDevice /></ProtectedRoute>},
            ],
        },
    ]);

    return <RouterProvider router={router} />;
};

export default App;