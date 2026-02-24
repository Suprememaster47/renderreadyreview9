/**
 * ---------------------------------------------------------------------
 * MERGED SERVER.JS: N8N CHATBOT + CAPTCHA REVIEWS + PUG TEMPLATES + CONTACT
 * ---------------------------------------------------------------------
 */
import 'dotenv/config'; 
import path from "path";
import fs from "fs"; 
import express from "express";
import compression from "compression";
import session from "express-session";
import errorHandler from "errorhandler";
import lusca from "lusca";
import MongoStore from "connect-mongo";
import mongoose from "mongoose";
import passport from "passport";
import rateLimit from "express-rate-limit";
import axios from "axios";
import { WebSocketServer } from "ws";
import { MongoClient } from "mongodb";
import { fileURLToPath } from "url";
import { createRequire } from "module";
import mongoSanitize from "express-mongo-sanitize"; // Added for security

// Import Passport Config
import passportConfig from './config/passport.cjs'; 

const require = createRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** --------------------------
 * CONTROLLERS
 * -------------------------- */
const homeController = require("./controllers/home.cjs");
const userController = require("./controllers/user.cjs");
const apiController = require("./controllers/api.cjs");
const aiController = require("./controllers/ai.cjs");
const contactController = require("./controllers/contact.cjs");

/** --------------------------
 * CONFIG & MIDDLEWARE
 * -------------------------- */
require("./config/passport.cjs");
const { flash } = require("./config/flash.cjs");
const { morganLogger } = require("./config/morgan.cjs");

const RATE_LIMIT_STRICT = parseInt(process.env.RATE_LIMIT_STRICT, 10) || 5;
const RATE_LIMIT_LOGIN = parseInt(process.env.RATE_LIMIT_LOGIN, 10) || 10;
const RATE_LIMIT_REVIEW = parseInt(process.env.RATE_LIMIT_REVIEW, 10) || 20;

const strictLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: RATE_LIMIT_STRICT });
const loginLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: RATE_LIMIT_LOGIN });
const reviewLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: RATE_LIMIT_REVIEW });

// Specific Limiter for Contact Form (10 messages per hour per IP)
const contactFormLimiter = rateLimit({ 
    windowMs: 60 * 60 * 1000, 
    max: 10,
    message: { error: "Too many messages. Please try again later." }
});

const secureTransfer = process.env.BASE_URL?.startsWith("https");

/** --------------------------
 * MONGOOSE MODELS
 * -------------------------- */

// 1. Review Model
const reviewSchema = new mongoose.Schema({
  name: String,
  stars: { type: Number, min: 1, max: 5 },
  review_text: String,
  profile_pic: { type: String, default: "https://imgs.search.brave.com/pbruKhRTdtOMZ06961RdlA7ykd9NKAsJilAOtY79yHk/rs:fit:860:0:0:0/g:ce/aHR0cHM6Ly9wbmdm/cmUuY29tL3dwLWNv/bnRlbnQvdXBsb2Fk/cy8xMDAwMTE3OTc1/LTEtMzAweDI3NS5w/bmc" },
  createdAt: { type: Date, default: Date.now }
});
const Review = mongoose.models.Review || mongoose.model("Review", reviewSchema, "reviews");

// 2. Contact Model (Targeting cluster login1, db test, table contact)
const contactSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: false }, // Optional as requested
    phone: { type: String, required: true },
    message: { type: String, required: true },
    messageNumber: { type: Number },
    createdAt: { type: Date, default: Date.now }
});
const Contact = mongoose.models.Contact || mongoose.model("Contact", contactSchema, "contact");

/** --------------------------
 * EXPRESS APP SETUP
 * -------------------------- */
const app = express();
app.set("host", "0.0.0.0");
app.set("port", process.env.PORT || 8080);
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");
app.set("trust proxy", 1);

app.use(morganLogger());
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));



app.use(
  session({
    resave: true,
    saveUninitialized: false,
    secret: process.env.SESSION_SECRET || "dev-secret",
    name: "startercookie",
    cookie: { maxAge: 1209600000, secure: secureTransfer },
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
  })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(flash);

// SECURITY: Bypass CSRF for API endpoints so AJAX works
app.use((req, res, next) => {
  if (
    req.path === "/api/upload" || 
    req.path === "/ai/togetherai-camera" || 
    req.path.startsWith("/api/") || 
    req.path === "/api/contact" || // Added bypass for contact
    req.path === "/send-to-n8n"
  ) return next();
  lusca.csrf()(req, res, next);
});

app.use(lusca.xframe("SAMEORIGIN"));
app.use(lusca.xssProtection(true));
app.disable("x-powered-by");

// FIX 1: Expose flash messages to Pug so your /login doesn't crash
app.use((req, res, next) => {
  res.locals.user = req.user;
  res.locals.messages = req.flash();
  next();
});

app.use("/", express.static(path.join(__dirname, "public")));
app.use("/js/lib", express.static(path.join(__dirname, "node_modules/chart.js/dist")));
app.locals.GOOGLE_ANALYTICS_ID = process.env.GOOGLE_ANALYTICS_ID || null;

/** --------------------------
 * HELPER FUNCTIONS
 * -------------------------- */
async function verifyRecaptchaToken(token, remoteip) {
  const secret = process.env.RECAPTCHA_SECRET_KEY;
  if (!secret) throw new Error('RECAPTCHA_SECRET_KEY not set');
  const params = new URLSearchParams();
  params.append('secret', secret);
  params.append('response', token);
  if (remoteip) params.append('remoteip', remoteip);
  const resp = await axios.post('https://www.google.com/recaptcha/api/siteverify', params);
  return resp.data;
}

/** --------------------------
 * ROUTES
 * -------------------------- */

// 1. Landing & Auth
app.get("/", (req, res) => {
    const indexPath = path.join(__dirname, "public", "index.html");
    fs.readFile(indexPath, 'utf8', (err, data) => {
        if (err) {
            console.error("Error reading index.html", err);
            return res.status(500).send("Server Error");
        }
        const injectedHtml = data.replace(
            /<%= RECAPTCHA_SITE_KEY %>|YOUR_RECAPTCHA_SITE_KEY_HERE/g, 
            process.env.RECAPTCHA_SITE_KEY || ''
        );
        res.send(injectedHtml);
    });
});

app.get("/login", userController.getLogin);
app.post("/login", loginLimiter, userController.postLogin);
app.get("/logout", userController.logout);
app.get("/signup", userController.getSignup);
app.post("/signup", loginLimiter, userController.postSignup);

// 2. Protected Account Routes
app.get("/account", passportConfig.isAuthenticated, userController.getAccount);
app.post("/account/profile", passportConfig.isAuthenticated, userController.postUpdateProfile);
app.post("/account/password", passportConfig.isAuthenticated, userController.postUpdatePassword);
app.post("/account/delete", passportConfig.isAuthenticated, userController.postDeleteAccount);
app.get("/account/unlink/:provider", passportConfig.isAuthenticated, userController.getOauthUnlink);

// 3. Dynamic Pug Pages
app.get("/home", homeController.index);
app.get("/contact", strictLimiter, contactController.getContact);
app.post("/contact", contactController.postContact); // Keeping existing pug controller
app.get("/api", apiController.getApi);
app.get("/ai", aiController.getAi);

// NEW: API POST for Secure JSON Contact Form (with Auto-Numbering)
app.post("/api/contact", contactFormLimiter, async (req, res) => {
  try {
    // Sanitize to prevent NoSQL Injection
    const cleanBody = mongoSanitize.sanitize(req.body);
    const { fullName, email, phone, message } = cleanBody;

    // 1. Validation for empty fields
    if (!fullName || !phone || !message) {
      return res.status(400).json({ success: false, message: "All fields are required." });
    }

    // 2. Length Check (Security)
    if (fullName.length > 100 || message.length > 500) {
      return res.status(400).json({ success: false, message: "Input too long. Please shorten your entry." });
    }

    // 3. AUTO-NUMBERING LOGIC
    // We find the single most recent contact by sorting messageNumber from highest to lowest (-1)
    const lastContact = await Contact.findOne().sort({ messageNumber: -1 });
    
    // If no contacts exist yet, start at 1. Otherwise, take the last number and add 1.
    const nextNumber = (lastContact && lastContact.messageNumber) ? lastContact.messageNumber + 1 : 1;

    const newContact = new Contact({
      fullName,
      email: email || null,
      phone,
      message,
      messageNumber: nextNumber // This saves the 1, 2, 3... sequence
    });

    await newContact.save();

    res.json({ 
      success: true, 
      message: `Message #${nextNumber} saved successfully!`,
      messageNumber: nextNumber 
    });
  } catch (err) {
    console.error("Contact API Error:", err);
    res.status(500).json({ success: false, message: "Database error" });
  }
});

// Helper function to mask name
const maskName = (name) => {
  if (!name) return "Anonymous";
  const str = String(name).trim();
  if (str.length <= 2) return str; 
  const firstTwo = str.substring(0, 2);
  const stars = "*".repeat(str.length - 2);
  return firstTwo + stars;
};

// 4. RECAPTCHA & REVIEW API
app.get('/recaptcha-site-key', (req, res) => {
  res.json({ site_key: process.env.RECAPTCHA_SITE_KEY });
});

app.post("/api/submit_review", reviewLimiter, async (req, res) => {
  try {
    const { name, stars, review_text, profile_pic } = req.body;
    const recaptcha_token = req.body['g-recaptcha-response'] || req.body.recaptcha_token;

    if (!name || !stars || !review_text) return res.json({ success: false, message: 'All fields required' });
    if (!recaptcha_token) return res.json({ success: false, message: 'Please complete the CAPTCHA' });

    const verification = await verifyRecaptchaToken(recaptcha_token, req.ip);
    
    if (!verification.success) {
        return res.json({ success: false, message: 'CAPTCHA failed verification' });
    }

    const review = new Review({
      name,
      stars: parseInt(stars),
      review_text,
      profile_pic: profile_pic || undefined
    });
    await review.save();
    res.json({ success: true, message: "Review saved successfully" });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: err.message });
  }
});

app.get('/api/reviews', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 5;
    const totalReviews = await Review.countDocuments();
    const reviews = await Review.find().sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit);

    const maskedReviews = reviews.map(r => {
      const reviewObj = r.toObject(); 
      return {
        ...reviewObj,
        name: maskName(reviewObj.name) 
      };
    });

    res.json({ 
      reviews: maskedReviews, 
      total_pages: Math.ceil(totalReviews / limit), 
      total_reviews: totalReviews 
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// FIX 2: Better stats calculator to prevent `0` errors if data had old text-based ratings
app.get('/api/stats', async (req, res) => {
  try {
    const stats = await Review.aggregate([{ $group: { _id: null, avgStars: { $avg: "$stars" }, total: { $sum: 1 } } }]);
    
    let avgStars = 0;
    let totalReviews = 0;

    if (stats.length > 0) {
        avgStars = stats[0].avgStars ? parseFloat(stats[0].avgStars.toFixed(1)) : 0;
        totalReviews = stats[0].total || 0;
    }

    res.json({ avgStars, totalReviews });
  } catch (err) {
    console.error("Stats API Error:", err);
    res.status(500).json({ error: err.message });
  }
});

/** ---------------------------------------------------------------------
 * CHATBOT & DATABASE CONNECTIONS
 * --------------------------------------------------------------------- */
try {
    await mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    console.log("Mongoose Connected ✅");
} catch (error) {
    console.error("Mongoose Connection Error:", error);
}

const mongoClient = new MongoClient(process.env.MONGODB_URI);
let responsesCollection = null;

async function initChatbotMongo() {
  try {
      await mongoClient.connect();
      responsesCollection = mongoClient.db("test").collection("responses");
      await responsesCollection.createIndex({ sessionId: 1, timestamp: -1 });
      console.log("Chatbot Mongo Connected ✅");
  } catch (error) {
      console.error("Chatbot Mongo Error:", error);
  }
}
initChatbotMongo();

async function saveMessage({ sessionId, sender, message, meta = {} }) {
  if (!responsesCollection) return;
  await responsesCollection.insertOne({ sessionId, sender, message, meta, timestamp: new Date() });
}

app.post("/send-to-n8n", async (req, res) => {
  const { message, sessionId } = req.body;
  if (!message) return res.status(400).json({ error: "No message" });
  try {
    await saveMessage({ sessionId, sender: "user", message });
    const resp = await axios.post(process.env.N8N_WEBHOOK_URL, { message, sessionId });
    let reply = typeof resp.data === "string" ? resp.data : resp.data.reply || JSON.stringify(resp.data);
    await saveMessage({ sessionId, sender: "bot", message: reply });
    res.json({ reply });
  } catch (err) {
    res.status(500).json({ error: "n8n error" });
  }
});

const server = app.listen(app.get("port"), () => {
  console.log(`Server running at http://localhost:${app.get("port")}`);
});

const wss = new WebSocketServer({ server });
wss.on("connection", (ws) => {
  ws.on("message", async (raw) => {
    try {
      const payload = JSON.parse(raw.toString());
      const { message, sessionId } = payload;
      await saveMessage({ sessionId, sender: "user", message });
      const resp = await axios.post(process.env.N8N_WEBHOOK_URL, { message, sessionId });
      let reply = typeof resp.data === "string" ? resp.data : resp.data.reply || JSON.stringify(resp.data);
      await saveMessage({ sessionId, sender: "bot", message: reply });
      ws.send(JSON.stringify({ reply, sessionId }));
    } catch (err) {
      ws.send(JSON.stringify({ error: "WS Error" }));
    }
  });
});

app.use((req, res) => res.status(404).send("Page Not Found"));
if (process.env.NODE_ENV === "development") app.use(errorHandler());

process.on("SIGINT", async () => {
  await mongoose.disconnect();
  server.close(() => process.exit(0));
});

export default app;