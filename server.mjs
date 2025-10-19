import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import cloudinary from "cloudinary";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { PDFParse } from "pdf-parse";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import bodyParser from "body-parser";

import { fileURLToPath } from "url";

dotenv.config();

// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
    origin: ["http://localhost:3000",'https://healthcare-ai-by-hassan.vercel.app',"*"], // ya deployed frontend URL
    credentials: true,
  }));
app.use(bodyParser.json());

app.use(express.json());
app.use(express.static("uploads"));

// // Cloudinary configuration
// cloudinary.v2.config({
//   cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
//   api_key: process.env.CLOUDINARY_API_KEY,
//   api_secret: process.env.CLOUDINARY_API_SECRET,
// });

app.get("/api", (req, res) => {
  res.send("Hello World");
});

// // Gemini AI configuration
// const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// // MongoDB connection
// mongoose
//   .connect(process.env.MONGO_URI)
//   .then(() => console.log("MongoDB connected"))
//   .catch((err) => console.error("MongoDB connection error:", err));

// // User Schema
// const userSchema = new mongoose.Schema(
//   {
//     name: { type: String, required: true },
//     email: { type: String, required: true, unique: true },
//     password: { type: String, required: true },
//     familyMembers: [
//       { type: mongoose.Schema.Types.ObjectId, ref: "FamilyMember" },
//     ],
//   },
//   { timestamps: true }
// );

// // Report Subschema
// const reportSchema = new mongoose.Schema(
//   {
//     title: { type: String, required: true },
//     type: { type: String, enum: ["image", "pdf"], required: true },
//     // cloudinaryUrl: { type: String, required: true },
//     uploadDate: { type: Date, default: Date.now },
//     aiAnalysis: { type: String, default: "" },
//   },
//   { _id: false } // optional: prevents separate _id for each report
// );

// // Family Member Schema
// const familyMemberSchema = new mongoose.Schema(
//   {
//     userId: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: "User",
//       required: true,
//     },
//     name: { type: String, required: true },
//     age: { type: Number, required: true },
//     gender: { type: String, required: true },
//     relationship: { type: String, required: true },
//     medicalHistory: [
//       {
//         condition: String,
//         date: Date,
//         notes: String,
//       },
//     ],
//     medications: [
//       {
//         name: String,
//         dosage: String,
//         frequency: String,
//         startDate: Date,
//       },
//     ],
//     reports: [reportSchema], // ← use proper sub-schema here
//   },
//   { timestamps: true }
// );

// const User = mongoose.model("User", userSchema);
// const FamilyMember = mongoose.model("FamilyMember", familyMemberSchema);

// // Multer configuration for file uploads
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, "uploads/");
//   },
//   filename: (req, file, cb) => {
//     cb(null, Date.now() + "-" + file.originalname);
//   },
// });

// const upload = multer({
//   storage: storage,
//   fileFilter: (req, file, cb) => {
//     if (
//       file.mimetype.startsWith("image/") ||
//       file.mimetype === "application/pdf"
//     ) {
//       cb(null, true);
//     } else {
//       cb(new Error("Only images and PDF files are allowed"), false);
//     }
//   },
//   limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
// });

// // JWT Middleware
// const authenticateToken = (req, res, next) => {
//   const authHeader = req.headers["authorization"];
//   const token = authHeader && authHeader.split(" ")[1];

//   if (!token) {
//     return res.status(401).json({ message: "Access token required" });
//   }

//   jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
//     if (err) {
//       return res.status(403).json({ message: "Invalid or expired token" });
//     }
//     req.user = user;
//     next();
//   });
// };

// // Routes

// // User Registration
// app.post("/api/auth/register", async (req, res) => {
//   try {
//     const { name, email, password } = req.body;

//     // Check if user already exists
//     const existingUser = await User.findOne({ email });
//     if (existingUser) {
//       return res.status(400).json({ message: "User already exists" });
//     }

//     // Hash password
//     const hashedPassword = await bcrypt.hash(password, 10);

//     // Create user
//     const user = new User({
//       name,
//       email,
//       password: hashedPassword,
//     });

//     await user.save();

//     // Generate JWT
//     const token = jwt.sign(
//       { userId: user._id, email: user.email },
//       process.env.JWT_SECRET,
//       { expiresIn: "7d" }
//     );

//     res.status(201).json({
//       message: "User created successfully",
//       token,
//       user: { id: user._id, name: user.name, email: user.email },
//     });
//   } catch (error) {
//     res.status(500).json({ message: "Server error", error: error.message });
//   }
// });

// // User Login
// app.post("/api/auth/login", async (req, res) => {
//   try {
//     const { email, password } = req.body;

//     // Find user
//     const user = await User.findOne({ email });
//     if (!user) {
//       return res.status(400).json({ message: "Invalid credentials" });
//     }

//     // Check password
//     const isValidPassword = await bcrypt.compare(password, user.password);
//     if (!isValidPassword) {
//       return res.status(400).json({ message: "Invalid credentials" });
//     }

//     // Generate JWT
//     const token = jwt.sign(
//       { userId: user._id, email: user.email },
//       process.env.JWT_SECRET,
//       { expiresIn: "7d" }
//     );

//     res.json({
//       message: "Login successful",
//       token,
//       user: { id: user._id, name: user.name, email: user.email },
//     });
//   } catch (error) {
//     res.status(500).json({ message: "Server error", error: error.message });
//   }
// });

// // Get user dashboard data
// app.get("/api/dashboard", authenticateToken, async (req, res) => {
//   try {
//     const familyMembers = await FamilyMember.find({ userId: req.user.userId });
//     res.json({ familyMembers });
//   } catch (error) {
//     res.status(500).json({ message: "Server error", error: error.message });
//   }
// });

// // Add family member
// app.post("/api/family-members", authenticateToken, async (req, res) => {
//   try {
//     const { name, age, gender, relationship } = req.body;

//     const familyMember = new FamilyMember({
//       userId: req.user.userId,
//       name,
//       age,
//       gender,
//       relationship,
//     });

//     await familyMember.save();

//     // Add to user's family members array
//     await User.findByIdAndUpdate(req.user.userId, {
//       $push: { familyMembers: familyMember._id },
//     });

//     res.status(201).json({
//       message: "Family member added successfully",
//       familyMember,
//     });
//   } catch (error) {
//     res.status(500).json({ message: "Server error", error: error.message });
//   }
// });

// // Get family member details
// app.get("/api/family-members/:id", authenticateToken, async (req, res) => {
//   try {
//     const familyMember = await FamilyMember.findOne({
//       _id: req.params.id,
//       userId: req.user.userId,
//     });

//     if (!familyMember) {
//       return res.status(404).json({ message: "Family member not found" });
//     }

//     res.json({ familyMember });
//   } catch (error) {
//     res.status(500).json({ message: "Server error", error: error.message });
//   }
// });

// // Update family member
// app.put("/api/family-members/:id", authenticateToken, async (req, res) => {
//   try {
//     const { name, age, gender, relationship, medicalHistory, medications } =
//       req.body;

//     const familyMember = await FamilyMember.findOneAndUpdate(
//       { _id: req.params.id, userId: req.user.userId },
//       { name, age, gender, relationship, medicalHistory, medications },
//       { new: true }
//     );

//     if (!familyMember) {
//       return res.status(404).json({ message: "Family member not found" });
//     }

//     res.json({
//       message: "Family member updated successfully",
//       familyMember,
//     });
//   } catch (error) {
//     res.status(500).json({ message: "Server error", error: error.message });
//   }
// });

// // Upload medical report
// app.post(
//   "/api/family-members/:id/reports",
//   authenticateToken,
//   upload.single("report"),
//   async (req, res) => {
//     try {
//       if (!req.file) {
//         return res.status(400).json({ message: "No file uploaded" });
//       }
//       const familyMember = await FamilyMember.findOne({
//         _id: req.params.id,
//         userId: req.user.userId,
//       });

//       if (!familyMember) {
//         return res.status(404).json({ message: "Family member not found" });
//       }

//       // // Upload to Cloudinary
//       // const result = await cloudinary.v2.uploader.upload(req.file.path, {
//       //   resource_type: "auto", // IMPORTANT ✅ for PDFs
//       //   folder: "medical-reports",
//       //   use_filename: true,
//       //   unique_filename: false,
//       //   format: req.file.mimetype === "application/pdf" ? "pdf" : undefined,
//       // });

//       // Analyze with Gemini AI
//       let aiAnalysis = "";
//       try {
//         if (req.file.mimetype === "application/pdf") {
//           // Parse PDF
//           const pdfBuffer = fs.readFileSync(req.file.path);
//           const pdfData = await new PDFParse({ data: pdfBuffer });
//           let text = "";
//           text = await pdfData.getText();
        
//           console.log("data", text);
//           text = JSON.stringify(text);
//           // console.log(pdfData.text);
//           // console.log("data",text);

//           const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
//           const prompt = `Analyze this medical report and provide health recommendations. Focus on key findings, potential concerns, and actionable advice. Keep the response concise and professional:\n\n${text}`;

//           const aiResult = await model.generateContent(prompt);

//           aiAnalysis = aiResult.response.text();
//           console.log("ai", aiAnalysis);
//         } else {
//           // For images, we'll use a simple prompt since Gemini can analyze images
//           const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
//           const prompt = `Analyze this medical image/report and provide health recommendations. Focus on key findings, potential concerns, and actionable advice. Keep the response concise and professional.`;

//           const aiResult = await model.generateContent([
//             prompt,
//             {
//               inlineData: {
//                 data: fs.readFileSync(req.file.path).toString("base64"),
//                 mimeType: req.file.mimetype,
//               },
//             },
//           ]);
//           aiAnalysis = aiResult.response.text();
//         }
//       } catch (aiError) {
//         console.error("AI analysis error:", aiError);
//         aiAnalysis =
//           "AI analysis temporarily unavailable. Please consult with a healthcare professional.";
//       }

//       // Add report to family member
//       const report = {
//         title: req.body.title || req.file.originalname,
//         type: req.file.mimetype === "application/pdf" ? "pdf" : "image",
//         // cloudinaryUrl: result.secure_url,
//         aiAnalysis,
//       };

//       familyMember.reports.push(report);
//       await familyMember.save();

//       // // Clean up local file
//       fs.unlinkSync(req.file.path);
//       // console.log("report", report);

//       res.status(201).json({
//         message: "Report uploaded and analyzed successfully",
//         report,
//       });
//     } catch (error) {
//       // Clean up local file if it exists
//       if (req.file && fs.existsSync(req.file.path)) {
//         fs.unlinkSync(req.file.path);
//       }
//       res.status(500).json({ message: error.message, error: error.message });
//     }
//   }
// );

// // Get family member reports
// app.get(
//   "/api/family-members/:id/reports",
//   authenticateToken,
//   async (req, res) => {
//     try {
//       const familyMember = await FamilyMember.findOne({
//         _id: req.params.id,
//         userId: req.user.userId,
//       });

//       if (!familyMember) {
//         return res.status(404).json({ message: "Family member not found" });
//       }

//       res.json({ reports: familyMember.reports });
//     } catch (error) {
//       res.status(500).json({ message: "Server error", error: error.message });
//     }
//   }
// );

// // AI Health Query endpoint
// app.post("/api/ai/health-query", authenticateToken, async (req, res) => {
//   try {
//     const { question, context } = req.body;

//     if (!question || question.trim().length === 0) {
//       return res.status(400).json({ message: "Question is required" });
//     }

//     // Initialize Gemini AI
//     const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
//     const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

//     // Create a health-focused prompt
//     const healthPrompt = `
// You are a helpful AI health assistant. Please provide accurate, helpful, and safe health information based on the user's question. 

// IMPORTANT GUIDELINES:
// - Provide general health information and educational content
// - Always recommend consulting healthcare professionals for medical advice
// - Be clear about limitations and when professional medical attention is needed
// - Focus on prevention, wellness, and general health education
// - Avoid providing specific medical diagnoses or treatment recommendations
// - Include relevant health tips and lifestyle advice when appropriate

// User Question: ${question}

// Context: ${context || "general_health_inquiry"}

// Please provide a helpful, informative, and safe response that includes:
// 1. Direct answer to the question
// 2. Additional relevant health information
// 3. When to seek professional medical advice
// 4. General wellness tips related to the topic

// Keep the response concise but comprehensive, and always emphasize the importance of professional medical consultation for specific health concerns.
// `;

//     const result = await model.generateContent(healthPrompt);
//     const response = await result.response;
//     const aiResponse = response.text();

//     res.json({
//       response: aiResponse,
//       timestamp: new Date().toISOString(),
//       context: context || "general_health_inquiry",
//     });
//   } catch (error) {
//     console.error("AI Health Query Error:", error);
//     res.status(500).json({
//       message: "Failed to process health query",
//       error: error.message,
//     });
//   }
// });

// // Error handling middleware
// app.use((error, req, res, next) => {
//   if (error instanceof multer.MulterError) {
//     if (error.code === "LIMIT_FILE_SIZE") {
//       return res
//         .status(400)
//         .json({ message: "File too large. Maximum size is 10MB." });
//     }
//   }
//   res.status(500).json({ message: "Server error", error: error.message });
// });

// // Create uploads directory if it doesn't exist
// if (!fs.existsSync("uploads")) {
//   fs.mkdirSync("uploads");
// }

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
