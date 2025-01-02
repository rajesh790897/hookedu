import express from "express";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import cors from "cors";
import database from "./src/config/database.js";
import { root, register } from "./src/routes/users.js";
import { feed } from "./src/routes/feed.js";

// Load environment variables
dotenv.config();

const app = express();
const PORT = 5001;
const corsOptions = { 
  credentials: true, 
  origin: "http://localhost:3000" 
};

// Authenticate and connect to the database
(async () => {
  try {
    await database.authenticate();
    console.log("Database connected successfully.");
  } catch (error) {
    console.error("Error connecting to the database:", error);
  }
})();

// Middleware: Parse cookies, JSON, and URL-encoded data
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Middleware: Enable CORS
app.use(cors(corsOptions));

// Route handlers
app.use("/", root);
app.use("/hook", register);
app.use("/api/feed", feed);

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
