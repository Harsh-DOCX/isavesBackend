require("dotenv").config();

const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const crypto = require("crypto");
const express = require("express");
const { rateLimit } = require("express-rate-limit");
const { OAuth2Client } = require("google-auth-library");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");


const app = express();
const PORT = process.env.PORT;
const isProduction = process.env.NODE_ENV === "production";
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const ENCRYPTION_SECRET = process.env.ENCRYPTION_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;
const TOKEN_COOKIE = "isaves_token";

if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is missing");
}

if (!ENCRYPTION_SECRET) {
    throw new Error("ENCRYPTION_SECRET is missing");
}

if (!GOOGLE_CLIENT_ID) {
    console.warn("GOOGLE_CLIENT_ID is missing");
}

if (!FRONTEND_ORIGIN) {
    throw new Error("FRONTEND_ORIGIN is missing");
}

const encryptionKey = crypto.scryptSync(ENCRYPTION_SECRET, "isaves-salt", 32);
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

const requiredEnvInProd = [
    "MONGODB_URI",
    "JWT_SECRET",
    "ENCRYPTION_SECRET",
    "GOOGLE_CLIENT_ID",
    "FRONTEND_ORIGIN",
];

if (isProduction) {
    const missing = requiredEnvInProd.filter((name) => !process.env[name]);
    if (missing.length > 0) {
        console.error(
            `Missing required environment variables in production: ${missing.join(", ")}`,
        );
        process.exit(1);
    }
}


const allowedOrigins = FRONTEND_ORIGIN.split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(helmet());

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: isProduction ? 50 : 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: "Too many authentication attempts. Please try again later." },
});

const passwordResetLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: isProduction ? 5 : 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: "Too many password reset attempts. Please try again later." },
});

app.use(
    cors({
        origin: (origin, callback) => {
            if (!origin) {
                callback(null, true);
                return;
            }

            callback(null, allowedOrigins.includes(origin));
        },
        credentials: true,
    }),
);
app.use(express.json());
app.use(cookieParser());

const userSchema = new mongoose.Schema(
    {
        username: {
            type: String,
            required: true,
            trim: true,
        },
        mobileNumber: {
            type: String,
            trim: true,
            default: "",
        },
        personalInfo: {
            type: String,
            trim: true,
            default: "",
        },
        email: {
            type: String,
            required: true,
            trim: true,
            lowercase: true,
            unique: true,
        },
        passwordHash: {
            type: String,
            required: true,
        },
        recoveryQuestion: {
            type: String,
            trim: true,
            default: "",
        },
        recoveryAnswer: {
            type: String,
            default: null,
        },
    },
    {
        timestamps: { createdAt: true, updatedAt: false },
    },
);

const encryptedSecretSchema = new mongoose.Schema(
    {
        iv: { type: String, required: true },
        content: { type: String, required: true },
        authTag: { type: String, required: true },
    },
    { _id: false },
);

const vaultEntrySchema = new mongoose.Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true,
        },
        siteName: {
            type: String,
            required: true,
            trim: true,
        },
        username: {
            type: String,
            required: true,
            trim: true,
        },
        password: {
            type: encryptedSecretSchema,
            required: true,
        },
        notes: {
            type: String,
            trim: true,
            default: "",
        },
    },
    {
        timestamps: { createdAt: true, updatedAt: false },
    },
);

const User = mongoose.model("User", userSchema);
const VaultEntry = mongoose.model("VaultEntry", vaultEntrySchema);

const sanitizeUser = (user) => ({
    id: user._id.toString(),
    username: user.username,
    email: user.email,
    mobileNumber: user.mobileNumber || "",
    personalInfo: user.personalInfo || "",
    createdAt: user.createdAt,
});

const normalizeEmail = (email) => email.trim().toLowerCase();
const DOMAIN_REGEX = /^(?:[a-z0-9-]+\.)+[a-z]{2,24}$/i;
const COMMON_SITE_ALIASES = {
    amazon: "amazon.com",
    apple: "apple.com",
    canva: "canva.com",
    chatgpt: "openai.com",
    discord: "discord.com",
    dropbox: "dropbox.com",
    facebook: "facebook.com",
    figma: "figma.com",
    github: "github.com",
    gitlab: "gitlab.com",
    gmail: "google.com",
    google: "google.com",
    hackerrank: "hackerrank.com",
    hotstar: "hotstar.com",
    instagram: "instagram.com",
    linkedin: "linkedin.com",
    medium: "medium.com",
    microsoft: "microsoft.com",
    netflix: "netflix.com",
    notion: "notion.so",
    openai: "openai.com",
    outlook: "outlook.com",
    paypal: "paypal.com",
    pinterest: "pinterest.com",
    primevideo: "primevideo.com",
    reddit: "reddit.com",
    slack: "slack.com",
    snapchat: "snapchat.com",
    spotify: "spotify.com",
    stackoverflow: "stackoverflow.com",
    telegram: "telegram.org",
    tiktok: "tiktok.com",
    twitch: "twitch.tv",
    twitter: "x.com",
    whatsapp: "whatsapp.com",
    wikipedia: "wikipedia.org",
    x: "x.com",
    yahoo: "yahoo.com",
    youtube: "youtube.com",
    zoom: "zoom.us",
};
const COMMON_DOMAINS = [
    "amazon.com",
    "apple.com",
    "chat.openai.com",
    "discord.com",
    "dropbox.com",
    "facebook.com",
    "figma.com",
    "github.com",
    "gitlab.com",
    "google.com",
    "instagram.com",
    "linkedin.com",
    "mail.google.com",
    "medium.com",
    "microsoft.com",
    "netflix.com",
    "notion.so",
    "openai.com",
    "outlook.com",
    "paypal.com",
    "pinterest.com",
    "reddit.com",
    "slack.com",
    "snapchat.com",
    "spotify.com",
    "stackoverflow.com",
    "telegram.org",
    "tiktok.com",
    "twitch.tv",
    "whatsapp.com",
    "wikipedia.org",
    "x.com",
    "yahoo.com",
    "youtube.com",
    "zoom.us",
];



const sanitizeToken = (value) =>
    String(value || "")
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "");

const toHostname = (input) => {
    const raw = String(input || "").trim();
    if (!raw) {
        return "";
    }

    const candidate = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;

    try {
        const url = new URL(candidate);
        return url.hostname.toLowerCase().replace(/^www\./, "");
    } catch {
        const noPath = raw.split("/")[0].trim().toLowerCase().replace(/^www\./, "");
        return DOMAIN_REGEX.test(noPath) ? noPath : "";
    }
};

const levenshteinDistance = (source, target) => {
    if (source === target) {
        return 0;
    }

    const sourceLength = source.length;
    const targetLength = target.length;

    if (sourceLength === 0) {
        return targetLength;
    }

    if (targetLength === 0) {
        return sourceLength;
    }

    const matrix = Array.from({ length: sourceLength + 1 }, () =>
        new Array(targetLength + 1).fill(0),
    );

    for (let i = 0; i <= sourceLength; i += 1) {
        matrix[i][0] = i;
    }

    for (let j = 0; j <= targetLength; j += 1) {
        matrix[0][j] = j;
    }

    for (let i = 1; i <= sourceLength; i += 1) {
        for (let j = 1; j <= targetLength; j += 1) {
            const substitutionCost = source[i - 1] === target[j - 1] ? 0 : 1;
            matrix[i][j] = Math.min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + substitutionCost,
            );
        }
    }

    return matrix[sourceLength][targetLength];
};

const bestFuzzyMatch = (value, candidates) => {
    if (!value) {
        return null;
    }

    const source = sanitizeToken(value);
    if (!source) {
        return null;
    }

    let bestCandidate = null;
    let bestDistance = Number.POSITIVE_INFINITY;

    for (const candidate of candidates) {
        const target = sanitizeToken(candidate);
        if (!target) {
            continue;
        }

        const distance = levenshteinDistance(source, target);
        if (distance < bestDistance) {
            bestDistance = distance;
            bestCandidate = candidate;
        }
    }

    if (!bestCandidate) {
        return null;
    }

    const maxAllowedDistance = source.length <= 4 ? 1 : source.length <= 8 ? 2 : 3;
    if (bestDistance > maxAllowedDistance) {
        return null;
    }

    return bestCandidate;
};

const resolveSiteDomain = (query) => {
    const normalized = String(query || "").trim().toLowerCase();
    const hostname = toHostname(normalized);

    if (hostname) {
        if (COMMON_DOMAINS.includes(hostname)) {
            return { domain: hostname, matchType: "exact-domain" };
        }

        const fuzzyDomain = bestFuzzyMatch(hostname, COMMON_DOMAINS);
        if (fuzzyDomain) {
            return { domain: fuzzyDomain, matchType: "fuzzy-domain" };
        }

        return { domain: hostname, matchType: "typed-domain" };
    }

    const compact = sanitizeToken(normalized);

    if (COMMON_SITE_ALIASES[compact]) {
        return {
            domain: COMMON_SITE_ALIASES[compact],
            matchType: "alias",
        };
    }

    const aliasMatch = bestFuzzyMatch(compact, Object.keys(COMMON_SITE_ALIASES));
    if (aliasMatch && COMMON_SITE_ALIASES[aliasMatch]) {
        return {
            domain: COMMON_SITE_ALIASES[aliasMatch],
            matchType: "fuzzy-alias",
        };
    }

    return { domain: "", matchType: "fallback" };
};

const buildLogoUrls = (domain, rawQuery) => {
    const urls = [];

    if (domain) {
        urls.push(
            `https://logo.clearbit.com/${domain}`,
            `https://www.google.com/s2/favicons?sz=128&domain=${domain}`,
            `https://icons.duckduckgo.com/ip3/${domain}.ico`,
        );
    }

    const fallbackLabel = sanitizeToken(rawQuery).slice(0, 2).toUpperCase() || "SV";
    urls.push(
        `https://www.google.com/s2/favicons?sz=128&domain_url=${encodeURIComponent(rawQuery)}`,
        `https://ui-avatars.com/api/?name=${encodeURIComponent(fallbackLabel)}&size=128&background=0f1f3b&color=ecf4ff&rounded=true`,
    );

    return [...new Set(urls)];
};

const RECOVERY_QUESTIONS = [
    "What was the name of your first pet?",
    "What city were you born in?",
    "What is your mother's maiden name?",
    "What was the name of your first school?",
    "What is your favorite book or movie?",
];

const hashRecoveryAnswer = (answer) =>
    crypto
        .createHash("sha256")
        .update(`${answer.trim().toLowerCase()}:${JWT_SECRET}`)
        .digest("hex");

const encryptSecret = (value) => {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey, iv);
    const encrypted = Buffer.concat([
        cipher.update(value, "utf8"),
        cipher.final(),
    ]);

    return {
        iv: iv.toString("hex"),
        content: encrypted.toString("hex"),
        authTag: cipher.getAuthTag().toString("hex"),
    };
};

const decryptSecret = (payload) => {
    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        encryptionKey,
        Buffer.from(payload.iv, "hex"),
    );

    decipher.setAuthTag(Buffer.from(payload.authTag, "hex"));

    return Buffer.concat([
        decipher.update(Buffer.from(payload.content, "hex")),
        decipher.final(),
    ]).toString("utf8");
};

const issueToken = (user) =>
    jwt.sign({ sub: user._id.toString(), email: user.email }, JWT_SECRET, {
        expiresIn: "12h",
    });

const authCookieOptions = {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: 12 * 60 * 60 * 1000,
    path: "/",
};

const setAuthCookie = (res, token) => {
    res.cookie(TOKEN_COOKIE, token, authCookieOptions);
};

const clearAuthCookie = (res) => {
    res.clearCookie(TOKEN_COOKIE, {
        httpOnly: true,
        secure: isProduction,
        sameSite: "lax",
        path: "/",
    });
};

const authMiddleware = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const cookieToken = req.cookies?.[TOKEN_COOKIE];
        const bearerToken = authHeader?.startsWith("Bearer ")
            ? authHeader.replace("Bearer ", "")
            : null;
        const token = bearerToken || cookieToken;

        if (!token) {
            return res.status(401).json({ message: "Authentication required." });
        }

        const payload = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(payload.sub);

        if (!user) {
            return res.status(401).json({ message: "Session is no longer valid." });
        }

        req.user = user;
        return next();
    } catch {
        return res.status(401).json({ message: "Invalid or expired session." });
    }
};

app.get("/api/health", async (req, res) => {
    const dbState =
        mongoose.connection.readyState === 1 ? "connected" : "disconnected";

    res.json({ status: "ok", database: dbState });
});

app.get("/api/site-image", authMiddleware, (req, res) => {
    const query = String(req.query.query || "").trim();
    if (!query) {
        return res.status(400).json({ message: "Query is required." });
    }

    const { domain, matchType } = resolveSiteDomain(query);
    const imageUrls = buildLogoUrls(domain, query);

    return res.json({
        query,
        domain: domain || null,
        matchType,
        imageUrls,
    });
});

app.post("/api/auth/signup", authLimiter, async (req, res) => {
    const { username, email, password, recoveryQuestion, recoveryAnswer } = req.body;

    if (!username || !email || !password || !recoveryQuestion || !recoveryAnswer) {
        return res
            .status(400)
            .json({ message: "Username, email, password, recovery question, and recovery answer are required." });
    }

    if (password.length < 8) {
        return res
            .status(400)
            .json({ message: "Password must be at least 8 characters long." });
    }

    if (recoveryAnswer.trim().length === 0) {
        return res
            .status(400)
            .json({ message: "Recovery answer cannot be empty." });
    }

    const normalizedEmail = normalizeEmail(email);
    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
        return res.status(409).json({
            message: "An account already exists for this email.",
        });
    }

    const user = await User.create({
        username: username.trim(),
        email: normalizedEmail,
        passwordHash: await bcrypt.hash(password, 10),
        recoveryQuestion: recoveryQuestion.trim(),
        recoveryAnswer: hashRecoveryAnswer(recoveryAnswer),
    });

    setAuthCookie(res, issueToken(user));

    return res.status(201).json({
        user: sanitizeUser(user),
    });
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required." });
    }

    const normalizedEmail = normalizeEmail(email);
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
        return res.status(401).json({ message: "Invalid email or password." });
    }

    const passwordMatches = await bcrypt.compare(password, user.passwordHash);

    if (!passwordMatches) {
        return res.status(401).json({ message: "Invalid email or password." });
    }

    setAuthCookie(res, issueToken(user));

    return res.json({
        user: sanitizeUser(user),
    });
});

app.post("/api/auth/google", authLimiter, async (req, res) => {
    if (!googleClient || !GOOGLE_CLIENT_ID) {
        return res.status(500).json({ message: "Google authentication is not configured." });
    }

    const { credential } = req.body;
    if (!credential) {
        return res.status(400).json({ message: "Google credential is required." });
    }

    const ticket = await googleClient.verifyIdToken({
        idToken: credential,
        audience: GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    if (!payload?.email || !payload.email_verified) {
        return res.status(401).json({ message: "Google account email is not verified." });
    }

    const normalizedEmail = normalizeEmail(payload.email);
    let user = await User.findOne({ email: normalizedEmail });

    if (!user) {
        const baseUsername =
            (payload.name || normalizedEmail.split("@")[0] || "user")
                .replace(/\s+/g, "_")
                .slice(0, 30) || "user";
        const suffix = crypto.randomBytes(2).toString("hex");
        user = await User.create({
            username: `${baseUsername}_${suffix}`,
            email: normalizedEmail,
            passwordHash: await bcrypt.hash(crypto.randomBytes(24).toString("hex"), 10),
        });
    }

    setAuthCookie(res, issueToken(user));
    return res.json({ user: sanitizeUser(user) });
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
    return res.json({ user: sanitizeUser(req.user) });
});

app.put("/api/auth/profile", authMiddleware, async (req, res) => {
    const { username, mobileNumber, personalInfo, recoveryQuestion, recoveryAnswer } = req.body;
    const updates = {};

    if (typeof username !== "undefined") {
        const trimmedUsername = String(username).trim();
        if (!trimmedUsername) {
            return res.status(400).json({ message: "Username cannot be empty." });
        }
        updates.username = trimmedUsername;
    }

    if (typeof mobileNumber !== "undefined") {
        const trimmedMobile = String(mobileNumber).trim();
        const mobilePattern = /^[+]?[\d\s()-]{7,20}$/;
        if (trimmedMobile && !mobilePattern.test(trimmedMobile)) {
            return res.status(400).json({
                message: "Mobile number format is invalid.",
            });
        }
        updates.mobileNumber = trimmedMobile;
    }

    if (typeof personalInfo !== "undefined") {
        updates.personalInfo = String(personalInfo).trim();
    }

    if (typeof recoveryQuestion !== "undefined") {
        const trimmedQuestion = String(recoveryQuestion).trim();
        if (!trimmedQuestion) {
            return res.status(400).json({ message: "Recovery question cannot be empty." });
        }
        updates.recoveryQuestion = trimmedQuestion;
    }

    if (typeof recoveryAnswer !== "undefined") {
        const trimmedAnswer = String(recoveryAnswer).trim();
        if (!trimmedAnswer) {
            return res.status(400).json({ message: "Recovery answer cannot be empty." });
        }
        updates.recoveryAnswer = hashRecoveryAnswer(recoveryAnswer);
    }

    if (Object.keys(updates).length === 0) {
        return res.status(400).json({ message: "No profile changes provided." });
    }

    Object.assign(req.user, updates);
    await req.user.save();

    return res.json({ user: sanitizeUser(req.user) });
});

app.post("/api/auth/logout", (req, res) => {
    clearAuthCookie(res);
    return res.status(204).send();
});

app.post("/api/auth/forgot-password", passwordResetLimiter, async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: "Email is required." });
    }

    const normalizedEmail = normalizeEmail(email);
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
        return res.json({
            question: null,
            message: "If an account exists for that email, you can reset your password.",
        });
    }

    return res.json({
        question: user.recoveryQuestion || null,
        message: "Please answer your recovery question to reset your password.",
    });
});

app.post("/api/auth/reset-password", passwordResetLimiter, async (req, res) => {
    const { email, recoveryAnswer, newPassword } = req.body;

    if (!email || !recoveryAnswer || !newPassword) {
        return res
            .status(400)
            .json({ message: "Email, recovery answer, and new password are required." });
    }

    if (String(newPassword).length < 8) {
        return res
            .status(400)
            .json({ message: "Password must be at least 8 characters long." });
    }

    const normalizedEmail = normalizeEmail(email);
    const user = await User.findOne({ email: normalizedEmail });

    if (!user || !user.recoveryAnswer) {
        return res.status(400).json({ message: "User not found or recovery is not configured." });
    }

    if (hashRecoveryAnswer(recoveryAnswer) !== user.recoveryAnswer) {
        return res.status(400).json({ message: "Incorrect recovery answer." });
    }

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    await user.save();

    return res.json({ message: "Password updated successfully. You can now log in." });
});

app.get("/api/vault", authMiddleware, async (req, res) => {
    const entries = await VaultEntry.find({ userId: req.user._id })
        .sort({ createdAt: -1 })
        .lean();

    return res.json({
        entries: entries.map((entry) => ({
            id: entry._id.toString(),
            userId: entry.userId.toString(),
            siteName: entry.siteName,
            username: entry.username,
            password: decryptSecret(entry.password),
            notes: entry.notes,
            createdAt: entry.createdAt,
        })),
    });
});

app.post("/api/vault", authMiddleware, async (req, res) => {
    const { siteName, username, password, notes = "" } = req.body;

    if (!siteName || !username || !password) {
        return res
            .status(400)
            .json({ message: "Site name, username, and password are required." });
    }

    const newEntry = await VaultEntry.create({
        userId: req.user._id,
        siteName: siteName.trim(),
        username: username.trim(),
        password: encryptSecret(password),
        notes: notes.trim(),
    });

    return res.status(201).json({
        entry: {
            id: newEntry._id.toString(),
            userId: newEntry.userId.toString(),
            siteName: newEntry.siteName,
            username: newEntry.username,
            password,
            notes: newEntry.notes,
            createdAt: newEntry.createdAt,
        },
    });
});

app.delete("/api/vault/:entryId", authMiddleware, async (req, res) => {
    const { entryId } = req.params;

    const result = await VaultEntry.deleteOne({
        _id: entryId,
        userId: req.user._id,
    });

    if (result.deletedCount === 0) {
        return res.status(404).json({ message: "Vault entry not found." });
    }

    return res.status(204).send();
});

app.use((error, req, res, next) => {
    if (error?.name === "ValidationError") {
        return res.status(400).json({ message: "Invalid request payload." });
    }

    if (error?.code === 11000) {
        return res.status(409).json({ message: "A record already exists." });
    }

    console.error(error);
    return res.status(500).json({ message: "Internal server error." });
});

mongoose
    .connect(MONGODB_URI)
    .then(() => {
        app.listen(PORT, () => {
            console.log(`iSaves API listening on http://localhost:${PORT}`);
        });
    })
    .catch((error) => {
        console.error("Failed to connect to MongoDB.", error);
        process.exit(1);
    });
