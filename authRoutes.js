//....
const {
    refreshAccessToken,
    logoutUser,
    logoutAllDevices,
    listAllSessions,
    revokeSessionById,
    revokeUserSessions,
} = require("../controllers/authController");

//....

// Login route
authRoutes.post("/login", validateLogin, loginUser);

// Refresh access token (uses httpOnly refresh cookie)
authRoutes.post("/refresh", refreshAccessToken);

// Logout (current session) — public; relies on cookie
authRoutes.post("/logout", logoutUser);

// Logout from all devices (requires authentication)
authRoutes.post("/logout-all", checkJWT, logoutAllDevices);

// ===== Session management (admin) — allow to "Users" Permistion =====
authRoutes.get("/sessions", checkJWT, allowedTo("Users"), listAllSessions);
authRoutes.delete("/sessions/:id", checkJWT, allowedTo("Users"), revokeSessionById);
authRoutes.delete("/sessions/user/:userId", checkJWT, allowedTo("Users"), revokeUserSessions);
