import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

const root = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(root, "public");
const dataDir = process.env.DATA_DIR || path.join(root, "data");
const uploadDir = process.env.UPLOAD_DIR || path.join(dataDir, "uploads");
const databasePath = process.env.DB_PATH || path.join(dataDir, "veyro.sqlite");
const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "127.0.0.1";
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(48).toString("hex");
const sessionDuration = 8 * 60 * 60 * 1000;

fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });

const db = new Database(databasePath);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
    CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS discounts (id TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY, data TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS settings (id TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS orders_created_at ON orders(created_at DESC);
    CREATE INDEX IF NOT EXISTS sessions_expires_at ON sessions(expires_at);
`);

const defaultDiscounts = [
    { id: "WELCOME10", code: "WELCOME10", type: "percentage", value: 10, minOrder: 200, maxUses: null, usedCount: 0, active: true },
    { id: "SAVE50", code: "SAVE50", type: "fixed", value: 50, minOrder: 500, maxUses: null, usedCount: 0, active: true }
];

function readCollection(table) {
    return db.prepare(`SELECT data FROM ${table}`).all().map(row => JSON.parse(row.data));
}

function readRecord(table, id) {
    const row = db.prepare(`SELECT data FROM ${table} WHERE id = ?`).get(String(id));
    return row ? JSON.parse(row.data) : null;
}

function writeRecord(table, record) {
    db.prepare(`INSERT INTO ${table} (id, data) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data`)
        .run(String(record.id), JSON.stringify(record));
}

function seedDatabase() {
    if (db.prepare("SELECT COUNT(*) AS count FROM products").get().count === 0) {
        const seedPath = path.join(publicDir, "data", "db.json");
        if (fs.existsSync(seedPath)) {
            const seed = JSON.parse(fs.readFileSync(seedPath, "utf8"));
            const insert = db.prepare("INSERT OR IGNORE INTO products (id, data) VALUES (?, ?)");
            for (const product of seed.products || []) insert.run(String(product.id), JSON.stringify(product));
        }
    }
    if (db.prepare("SELECT COUNT(*) AS count FROM discounts").get().count === 0) {
        for (const discount of defaultDiscounts) writeRecord("discounts", discount);
    }
    if (!readRecord("settings", "payment")) {
        writeRecord("settings", { id: "payment", supportPhone: "01015020363", vodafone: "", instapay: "" });
    }
}

seedDatabase();

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "6mb" }));

function sendError(res, status, error, code) {
    res.status(status).json({ error, code });
}

function safeEqual(left, right) {
    const a = Buffer.isBuffer(left) ? left : Buffer.from(String(left));
    const b = Buffer.isBuffer(right) ? right : Buffer.from(String(right));
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function passwordMatches(candidate) {
    const expected = process.env.ADMIN_PASSWORD || "";
    if (!expected) return false;
    const salt = process.env.ADMIN_PASSWORD_SALT || sessionSecret;
    return safeEqual(crypto.scryptSync(candidate, salt, 64), crypto.scryptSync(expected, salt, 64));
}

function sessionCookie(value, maxAge) {
    const parts = [`veyro_session=${value}`, "Path=/", "HttpOnly", "SameSite=Strict", `Max-Age=${maxAge}`];
    if (process.env.NODE_ENV === "production") parts.push("Secure");
    return parts.join("; ");
}

function sessionSignature(id) {
    return crypto.createHmac("sha256", sessionSecret).update(id).digest("base64url");
}

function adminOnly(req, res, next) {
    const cookie = (req.headers.cookie || "").split(";").map(part => part.trim()).find(part => part.startsWith("veyro_session="));
    const value = cookie?.slice("veyro_session=".length) || "";
    const [id, signature] = value.split(".");
    if (!id || !signature || !safeEqual(signature, sessionSignature(id))) return sendError(res, 401, "سجل الدخول للمتابعة", "AUTH_REQUIRED");
    const sessionId = crypto.createHash("sha256").update(id).digest("hex");
    const session = db.prepare("SELECT expires_at FROM sessions WHERE id = ?").get(sessionId);
    if (!session || session.expires_at < Date.now()) return sendError(res, 401, "انتهت جلسة الدخول", "AUTH_REQUIRED");
    req.adminSessionId = sessionId;
    next();
}

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 8,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { error: "محاولات كثيرة. انتظر قليلًا ثم حاول مجددًا.", code: "LOGIN_RATE_LIMIT" }
});

app.get("/api/health", (req, res) => res.json({ ok: true, database: "sqlite" }));

app.get("/api/products", (req, res) => {
    res.json(readCollection("products").filter(product => product.active !== false));
});

app.get("/api/discounts", (req, res) => {
    res.json(readCollection("discounts").filter(discount => discount.active !== false));
});

app.get("/api/config", (req, res) => {
    const settings = readRecord("settings", "payment") || {};
    res.json({ supportPhone: settings.supportPhone || "01015020363", vodafone: settings.vodafone || "", instapay: settings.instapay || "" });
});

app.post("/api/orders", (req, res) => {
    const { customerName, customerPhone, customerAddress, paymentMethod, paymentRef, items, discountCode } = req.body || {};
    if (![customerName, customerPhone, customerAddress].every(value => typeof value === "string" && value.trim())) {
        return sendError(res, 400, "اكتب الاسم ورقم الهاتف والعنوان.", "ORDER_DETAILS_REQUIRED");
    }
    if (!Array.isArray(items) || items.length < 1 || items.length > 30) return sendError(res, 400, "السلة فارغة أو تحتوي عددًا غير صالح من المنتجات.", "INVALID_ITEMS");
    if (!new Set(["cash", "vodafone", "instapay"]).has(paymentMethod)) return sendError(res, 400, "طريقة الدفع غير متاحة.", "INVALID_PAYMENT_METHOD");

    const settings = readRecord("settings", "payment") || {};
    if (paymentMethod === "vodafone" && !settings.vodafone) return sendError(res, 400, "فودافون كاش غير مفعّل حاليًا.", "PAYMENT_NOT_CONFIGURED");
    if (paymentMethod === "instapay" && !settings.instapay) return sendError(res, 400, "إنستاباي غير مفعّل حاليًا.", "PAYMENT_NOT_CONFIGURED");
    if (paymentMethod !== "cash" && (typeof paymentRef !== "string" || !paymentRef.trim())) return sendError(res, 400, "اكتب رقم عملية التحويل.", "PAYMENT_REFERENCE_REQUIRED");

    const normalizedItems = [];
    let subtotal = 0;
    for (const requested of items) {
        const quantity = Number(requested.quantity);
        if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) return sendError(res, 400, "كمية أحد المنتجات غير صالحة.", "INVALID_QUANTITY");
        const product = readRecord("products", requested.productId);
        if (!product || product.active === false) return sendError(res, 400, "أحد المنتجات لم يعد متاحًا.", "PRODUCT_UNAVAILABLE");
        const stock = Number(product.stock || 0);
        if (quantity > stock) return sendError(res, 400, `المتاح من ${product.name} هو ${stock} قطعة.`, "INSUFFICIENT_STOCK");
        if (requested.size && Array.isArray(product.sizes) && !product.sizes.includes(requested.size)) return sendError(res, 400, "المقاس المختار غير متاح.", "INVALID_SIZE");
        if (requested.color && Array.isArray(product.colors) && !product.colors.includes(requested.color)) return sendError(res, 400, "اللون المختار غير متاح.", "INVALID_COLOR");
        const price = product.salePrice && Number(product.salePrice) < Number(product.price) ? Number(product.salePrice) : Number(product.price);
        const lineTotal = price * quantity;
        subtotal += lineTotal;
        normalizedItems.push({ productId: product.id, name: product.name, quantity, size: requested.size || null, color: requested.color || null, price, lineTotal });
    }

    let discount = null;
    let discountAmount = 0;
    if (discountCode) {
        const normalizedCode = String(discountCode).trim().toUpperCase();
        discount = readCollection("discounts").find(item => String(item.code).toUpperCase() === normalizedCode && item.active !== false);
        if (!discount) return sendError(res, 400, "كود الخصم غير صالح.", "INVALID_DISCOUNT");
        if (discount.expiresAt && Date.parse(discount.expiresAt) < Date.now()) return sendError(res, 400, "انتهت صلاحية كود الخصم.", "DISCOUNT_EXPIRED");
        if (discount.maxUses && Number(discount.usedCount || 0) >= Number(discount.maxUses)) return sendError(res, 400, "تم استخدام هذا الكود بالكامل.", "DISCOUNT_EXHAUSTED");
        if (subtotal < Number(discount.minOrder || 0)) return sendError(res, 400, `الحد الأدنى لاستخدام الكود ${discount.minOrder} جنيه.`, "DISCOUNT_MINIMUM");
        discountAmount = discount.type === "percentage" ? Math.round(subtotal * Number(discount.value) / 100) : Number(discount.value);
        discountAmount = Math.min(subtotal, Math.max(0, discountAmount));
    }

    const orderId = crypto.randomUUID();
    const orderNumber = `VY-${Date.now().toString().slice(-6)}`;
    const order = {
        id: orderId,
        orderNumber,
        customerName: customerName.trim().slice(0, 120),
        customerPhone: customerPhone.trim().slice(0, 40),
        customerAddress: customerAddress.trim().slice(0, 1000),
        items: normalizedItems,
        paymentMethod,
        paymentRef: paymentRef?.trim() || null,
        paymentStatus: paymentMethod === "cash" ? "الدفع عند الاستلام" : "بانتظار التأكيد",
        status: "قيد المراجعة",
        subtotal,
        discountCode: discount?.code || null,
        discountAmount,
        total: subtotal - discountAmount,
        createdAt: new Date().toISOString()
    };

    try {
        db.exec("BEGIN IMMEDIATE");
        for (const item of normalizedItems) {
            const product = readRecord("products", item.productId);
            if (!product || Number(product.stock || 0) < item.quantity) throw new Error("INSUFFICIENT_STOCK");
            product.stock = Number(product.stock || 0) - item.quantity;
            writeRecord("products", product);
        }
        if (discount) {
            discount.usedCount = Number(discount.usedCount || 0) + 1;
            writeRecord("discounts", discount);
        }
        db.prepare("INSERT INTO orders (id, data, created_at) VALUES (?, ?, ?)").run(orderId, JSON.stringify(order), order.createdAt);
        db.exec("COMMIT");
        return res.status(201).json({ orderNumber, total: order.total });
    } catch (error) {
        db.exec("ROLLBACK");
        if (error.message === "INSUFFICIENT_STOCK") return sendError(res, 409, "نفدت كمية أحد المنتجات. حدّث الصفحة وحاول مجددًا.", "INSUFFICIENT_STOCK");
        console.error(error);
        return sendError(res, 500, "تعذر حفظ الطلب. حاول مجددًا.", "ORDER_SAVE_FAILED");
    }
});

app.post("/api/admin/login", loginLimiter, (req, res) => {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");
    const adminEmail = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
    if (!adminEmail || !process.env.ADMIN_PASSWORD) return sendError(res, 503, "إعدادات دخول الإدارة غير مكتملة على الخادم.", "ADMIN_NOT_CONFIGURED");
    if (!safeEqual(email, adminEmail) || !passwordMatches(password)) return sendError(res, 401, "البريد أو كلمة المرور غير صحيحة.", "INVALID_CREDENTIALS");

    const id = crypto.randomBytes(32).toString("base64url");
    const hashedId = crypto.createHash("sha256").update(id).digest("hex");
    const expiresAt = Date.now() + sessionDuration;
    db.prepare("INSERT INTO sessions (id, expires_at) VALUES (?, ?)").run(hashedId, expiresAt);
    res.setHeader("Set-Cookie", sessionCookie(`${id}.${sessionSignature(id)}`, sessionDuration / 1000));
    res.json({ ok: true });
});

app.post("/api/admin/logout", adminOnly, (req, res) => {
    db.prepare("DELETE FROM sessions WHERE id = ?").run(req.adminSessionId);
    res.setHeader("Set-Cookie", sessionCookie("", 0));
    res.json({ ok: true });
});

app.get("/api/admin/verify", adminOnly, (req, res) => res.json({ ok: true }));

const admin = express.Router();
admin.use(adminOnly);

admin.get("/store", (req, res) => {
    const orders = db.prepare("SELECT data FROM orders ORDER BY created_at DESC").all().map(row => JSON.parse(row.data));
    res.json({ products: readCollection("products"), discounts: readCollection("discounts"), orders });
});

admin.put("/products/:id", (req, res) => {
    const body = req.body || {};
    const price = Number(body.price);
    const salePrice = body.salePrice ? Number(body.salePrice) : null;
    const stock = Number(body.stock);
    if (!String(body.name || "").trim() || !Number.isFinite(price) || price <= 0 || !Number.isInteger(stock) || stock < 0) return sendError(res, 400, "تحقق من الاسم والسعر والمخزون.", "INVALID_PRODUCT");
    if (salePrice !== null && (!Number.isFinite(salePrice) || salePrice < 0 || salePrice >= price)) return sendError(res, 400, "يجب أن يكون سعر الخصم أقل من السعر الأصلي.", "INVALID_SALE_PRICE");
    const record = { ...body, id: body.id || req.params.id, name: String(body.name).trim(), price, salePrice, stock };
    writeRecord("products", record);
    res.json(record);
});

admin.delete("/products/:id", (req, res) => {
    db.prepare("DELETE FROM products WHERE id = ?").run(req.params.id);
    res.json({ ok: true });
});

admin.put("/discounts/:id", (req, res) => {
    const body = req.body || {};
    const value = Number(body.value);
    if (!String(body.code || "").trim() || !Number.isFinite(value) || value <= 0) return sendError(res, 400, "تحقق من كود الخصم وقيمته.", "INVALID_DISCOUNT");
    const record = { ...body, id: body.id || req.params.id, code: String(body.code).trim().toUpperCase(), value };
    writeRecord("discounts", record);
    res.json(record);
});

admin.delete("/discounts/:id", (req, res) => {
    db.prepare("DELETE FROM discounts WHERE id = ?").run(req.params.id);
    res.json({ ok: true });
});

admin.put("/orders/:id", (req, res) => {
    const order = readRecord("orders", req.params.id);
    if (!order) return sendError(res, 404, "الطلب غير موجود.", "ORDER_NOT_FOUND");
    const status = String(req.body?.status || order.status);
    const paymentStatus = String(req.body?.paymentStatus || order.paymentStatus);
    const allowedStatuses = new Set(["قيد المراجعة", "تم التأكيد", "جاري التجهيز", "تم الشحن", "تم التسليم", "ملغي"]);
    if (!allowedStatuses.has(status)) return sendError(res, 400, "حالة الطلب غير صحيحة.", "INVALID_ORDER_STATUS");
    order.status = status;
    order.paymentStatus = paymentStatus;
    writeRecord("orders", order);
    res.json(order);
});

admin.delete("/orders/:id", (req, res) => {
    db.prepare("DELETE FROM orders WHERE id = ?").run(req.params.id);
    res.json({ ok: true });
});

admin.get("/settings", (req, res) => res.json(readRecord("settings", "payment") || {}));
admin.put("/settings/:id", (req, res) => {
    const settings = {
        id: "payment",
        supportPhone: String(req.body?.supportPhone || "").trim(),
        vodafone: String(req.body?.vodafone || "").trim(),
        instapay: String(req.body?.instapay || "").trim()
    };
    writeRecord("settings", settings);
    res.json(settings);
});

admin.post("/upload", (req, res) => {
    const match = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String(req.body?.data || ""));
    if (!match) return sendError(res, 400, "الصورة يجب أن تكون JPG أو PNG أو WebP.", "INVALID_IMAGE");
    const buffer = Buffer.from(match[2], "base64");
    if (!buffer.length || buffer.length > 4 * 1024 * 1024) return sendError(res, 413, "حجم الصورة يجب أن يكون أقل من 4 ميجابايت.", "IMAGE_TOO_LARGE");
    const extension = match[1] === "jpeg" ? "jpg" : match[1];
    const filename = `${crypto.randomUUID()}.${extension}`;
    fs.writeFileSync(path.join(uploadDir, filename), buffer, { flag: "wx" });
    res.status(201).json({ url: `/uploads/${filename}` });
});

app.use("/api/admin", admin);

app.use("/uploads", express.static(uploadDir, { maxAge: "1d" }));
app.use(express.static(publicDir, { index: "index.html", maxAge: process.env.NODE_ENV === "production" ? "1h" : 0 }));
app.use((req, res) => {
    if (req.path.startsWith("/api/")) return sendError(res, 404, "المسار غير موجود.", "NOT_FOUND");
    res.status(404).sendFile(path.join(publicDir, "index.html"));
});

app.use((error, req, res, next) => {
    if (error.type === "entity.too.large") return sendError(res, 413, "البيانات المرسلة أكبر من المسموح.", "PAYLOAD_TOO_LARGE");
    console.error(error);
    sendError(res, 500, "حدث خطأ غير متوقع على الخادم.", "SERVER_ERROR");
});

const server = app.listen(port, host, () => console.log(`Veyro server listening on ${host}:${port}`));

for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => server.close(() => {
        db.close();
        process.exit(0);
    }));
}