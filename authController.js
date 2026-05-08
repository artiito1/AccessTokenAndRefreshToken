
//....

// ✅ POST: Refresh Access Token 
const refreshAccessToken = async (req, res, next) => {
    try {
        const refreshToken = req.cookies?.refreshToken;
        if (!refreshToken) return next(new CustomError("No refresh token provided", 401));

        // Verify signature & expiration of the refresh token JWT
        let decoded;
        try {
            decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET_KEY);
        } catch (err) {
            clearRefreshCookie(res);
            return next(new CustomError("Invalid or expired refresh token", 401));
        }

        // Ensure token still exists in DB and was not revoked (logout / admin action)
        const stored = await RefreshToken.findOne({ tokenHash: hashToken(refreshToken) });
        if (!stored || stored.revokedAt) {
            clearRefreshCookie(res);
            return next(new CustomError("Refresh token is no longer valid", 401));
        }

        const user = await User.findById(decoded.userId);
        if (!user) {
            clearRefreshCookie(res);
            return next(new CustomError("User not found", 401));
        }
        if (!user.isActive) {
            clearRefreshCookie(res);
            return next(new CustomError("User account is inactive", 403));
        }

        // keep the existing refresh token intact ** يعني لا يتم إنشاء توكن تحديدث جديد
        const accessToken = createAccessToken(user._id);
        return res.status(200).json({ success: true, token: accessToken });
    } catch (error) {
        console.error("Refresh Token Error:", error);
        return next(error);
    }
};

// ✅ POST: Logout (current session)
const logoutUser = async (req, res, next) => {
    try {
        const token = req.cookies?.refreshToken;
        if (token) {
            await RefreshToken.findOneAndUpdate(
                { tokenHash: hashToken(token), revokedAt: null },
                { revokedAt: new Date() }
            );
        }
        clearRefreshCookie(res);
        return res.status(200).json({ success: true, message: "Logged out successfully" });
    } catch (error) {
        console.error("Logout Error:", error);
        clearRefreshCookie(res);
        return next(error);
    }
};

// ✅ GET: List all active sessions across all users (Admin/Users permission)
const listAllSessions = async (req, res, next) => {
    try {
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
        const search = (req.query.search || "").trim();
        const status = (req.query.status || "active").toLowerCase();

        // Build base filter
        const filter = {};
        if (status === "active") {
            filter.revokedAt = null;
            filter.expiresAt = { $gt: new Date() };
        } else if (status === "revoked") {
            filter.revokedAt = { $ne: null };
        }
        // status === "all" → no filter

        // If search by email is provided, resolve matching users first
        if (search) {
            const matchingUsers = await User.find({
                email: { $regex: search, $options: "i" },
            }).select("_id").lean();
            const userIds = matchingUsers.map((u) => u._id);
            filter.user = { $in: userIds };
        }

        const total = await RefreshToken.countDocuments(filter);
        const docs = await RefreshToken.find(filter)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit)
            .populate({ path: "user", select: "email role isActive type" })
            .lean();

        // Enrich with employee/customer fullName if available
        const userIds = [...new Set(docs.map((d) => d.user?._id?.toString()).filter(Boolean))];
        const [employees, customers] = await Promise.all([
            Employee.find({ user: { $in: userIds } }).select("user fullName").lean(),
            Customer.find({ user: { $in: userIds } }).select("user fullName companyName").lean(),
        ]);
        const employeeByUser = new Map(employees.map((e) => [e.user.toString(), e]));
        const customerByUser = new Map(customers.map((c) => [c.user.toString(), c]));

        const data = docs.map((d) => {
            const uId = d.user?._id?.toString();
            const emp = uId ? employeeByUser.get(uId) : null;
            const cus = uId ? customerByUser.get(uId) : null;
            return {
                _id: d._id,
                user: d.user
                    ? {
                          _id: d.user._id,
                          email: d.user.email,
                          isActive: d.user.isActive,
                          type: d.user.type,
                          fullName: emp?.fullName || cus?.fullName || cus?.companyName || null,
                      }
                    : null,
                userAgent: d.userAgent,
                ip: d.ip,
                expiresAt: d.expiresAt,
                revokedAt: d.revokedAt,
                createdAt: d.createdAt,
                updatedAt: d.updatedAt,
                status: d.revokedAt
                    ? "revoked"
                    : d.expiresAt && d.expiresAt < new Date()
                    ? "expired"
                    : "active",
            };
        });

        return res.status(200).json({
            success: true,
            page,
            limit,
            total,
            data,
        });
    } catch (error) {
        console.error("List Sessions Error:", error);
        return next(error);
    }
};

// ✅ DELETE: Revoke a single session by its id (Admin/Users permission)
const revokeSessionById = async (req, res, next) => {
    try {
        const { id } = req.params;
        const session = await RefreshToken.findById(id);
        if (!session) return next(new CustomError("Session not found", 404));

        if (session.revokedAt) {
            return res.status(200).json({ success: true, message: "Session already revoked" });
        }

        session.revokedAt = new Date();
        await session.save();

        return res.status(200).json({ success: true, message: "Session revoked successfully" });
    } catch (error) {
        console.error("Revoke Session Error:", error);
        return next(error);
    }
};

// ✅ DELETE: Revoke all active sessions for a specific user (Admin/Users permission)
const revokeUserSessions = async (req, res, next) => {
    try {
        const { userId } = req.params;
        const userExists = await User.exists({ _id: userId });
        if (!userExists) return next(new CustomError("User not found", 404));

        const result = await RefreshToken.updateMany(
            { user: userId, revokedAt: null },
            { revokedAt: new Date() }
        );

        return res.status(200).json({
            success: true,
            message: "All active sessions for this user have been revoked",
            revokedCount: result.modifiedCount || 0,
        });
    } catch (error) {
        console.error("Revoke User Sessions Error:", error);
        return next(error);
    }
};

// ✅ POST: Logout from all devices (requires authentication)
const logoutAllDevices = async (req, res, next) => {
    try {
        if (!req.user?._id) return next(new CustomError("Unauthorized access", 401));

        await RefreshToken.updateMany(
            { user: req.user._id, revokedAt: null },
            { revokedAt: new Date() }
        );
        clearRefreshCookie(res);
        return res.status(200).json({ success: true, message: "Logged out from all devices" });
    } catch (error) {
        console.error("Logout All Error:", error);
        return next(error);
    }
};

