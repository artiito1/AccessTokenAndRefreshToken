const mongoose = require("mongoose");

const refreshTokenSchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true,
        },
        tokenHash: {
            type: String,
            required: true,
            unique: true,
        },
        userAgent: { type: String, default: null },
        ip: { type: String, default: null },
        expiresAt: { type: Date, required: true },
        revokedAt: { type: Date, default: null },
        replacedBy: { type: String, default: null },
    },
    { timestamps: true }
);

// TTL index: MongoDB DELETES THE DOCUMENT AT expiresAt
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const RefreshToken = mongoose.model("RefreshToken", refreshTokenSchema);

module.exports = RefreshToken;
