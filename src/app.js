import express from "express"
import cookieParser from "cookie-parser";
import cors from "cors";
import errorHandler from "./middlewares/errorHandler.js";
// import path from "path";

import swaggerUi from "swagger-ui-express";
import swaggerDocument from "./config/swagger.js";

const app = express()

app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// app.set("view engine", "ejs");
// app.set("views", path.resolve("./src/views"));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// app.get("/", (req, res) => {
//   return res.render("homepage");
// })

app.all("/", (req, res) => {
  res.status(403).json({ message: "Root path is restricted. Please use versioned API routes under /api/v1/" });
});

app.use('/api/v1/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, {
  explorer: true
}));

app.get("/api/v1/", (req, res) => {
  return res.redirect("/api/v1/api-docs");
})

//router imports
import healthCheckRouter from "./routes/healthcheck.routes.js";
import authRouter from "./routes/auth.routes.js";

app.use("/api/v1/healthCheck", healthCheckRouter);
app.use("/api/v1/auth", authRouter);

app.use(errorHandler);

export default app;