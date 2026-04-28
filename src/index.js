import app from "./app.js";
import dotenv from "dotenv";
import connectDB from "./db/db-connect.js";
import { env } from "./config/env.js";

connectDB()
    .then(() => {
        app.listen(env.PORT, () => console.log(`Server is running on port: ${env.PORT}`));
    })
    .catch((err) => {
        console.error("MongoDB connection error", err);
        process.exit(1);
    })