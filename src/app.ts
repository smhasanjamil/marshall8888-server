import cors from "cors";
import express, { Application, NextFunction, Request, Response } from "express";
import cookieParser from "cookie-parser";
import os from "os";
import status from "http-status";
import globalErrorHandler from "./app/middleware/globalErrorHandler";
import notFound from "./app/middleware/notFound";
import router from "./app/routes";

const app: Application = express();

// Middleware setup
app.use(cors({ origin: "http://localhost:3000" }));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/api/v1", router);

// seedAdmin();

// Test route
app.get("/", (req: Request, res: Response, next: NextFunction) => {
  const currentDateTime = new Date().toISOString();
  const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const serverHostname = os.hostname();
  const serverPlatform = os.platform();
  const serverUptime = os.uptime();

  res.status(status.OK).json({
    success: true,
    message: "Welcome to the EGEAL AI HUB",
    version: "1.0.0",
    clientDetails: {
      ipAddress: clientIp,
      accessedAt: currentDateTime,
    },
    serverDetails: {
      hostname: serverHostname,
      platform: serverPlatform,
      uptime: `${Math.floor(serverUptime / 60 / 60)} hours ${Math.floor(
        (serverUptime / 60) % 60
      )} minutes`,
    },
    // developerContact: {
    //   email: "smhasanjamil14@gmail.com",
    //   website: "https://smhasanjamil.web.app/",
    // },
  });
});

app.use(globalErrorHandler);

//Not Found
app.use(notFound);

export default app; // Export the app for use in server.ts
