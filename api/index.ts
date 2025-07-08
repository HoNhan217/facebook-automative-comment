import express, { Express, Request, Response } from "express";
import crypto from "crypto";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// Create an Express application
const app: Express = express();
const port: number = 3000;

// Webhook verification token (store this securely in environment variables)
const VERIFY_TOKEN = process.env.FACEBOOK_VERIFY_TOKEN || "meatyhamhock";
// App Secret for payload validation (store this securely in environment variables)
const APP_SECRET = process.env.FACEBOOK_APP_SECRET || "your-app-secret-here";

// Middleware to parse JSON bodies with raw body for signature validation
// app.use("/", express.raw({ type: "application/json" }));
// app.use(express.json());

app.use(
  express.json({
    verify: (req: Request, res: Response, buf: Buffer) => {
      // Save the raw body buffer onto the request object
      // This is needed for signature validation
      (req as any).rawBody = buf;
    },
  })
);

// Define a route handler for the default home page
// app.get("/", (req: Request, res: Response) => {
//   res.send("Hello, TypeScript + Node.js + Express Server! 🎉");
// });

// Webhook verification endpoint
app.get("/webhooks", (req: Request, res: Response) => {
  // Parse query parameters
  const verifyToken = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  const mode = req.query["hub.mode"];

  console.log("Webhook verification request received:", {
    mode,
    verifyToken,
    challenge,
  });

  // Verify that the hub.verify_token value matches the configured token
  if (mode && verifyToken) {
    if (mode === "subscribe" && verifyToken === VERIFY_TOKEN) {
      // Respond with the hub.challenge value as plain text
      console.log("Webhook verified successfully!");
      res.status(200).type("text/plain").send(challenge);
    } else {
      // Respond with '403 Forbidden' if verify tokens do not match
      console.log("Webhook verification failed!");
      res.status(403).send("Forbidden");
    }
  } else {
    // Respond with '400 Bad Request' if required parameters are missing
    console.log("Missing required parameters for webhook verification.");
    res.status(400).send("Bad Request");
  }
});

app.post("/webhooks", (req: Request, res: Response): void => {
  console.log("Received POST request on /webhooks");

  // Get the signature from headers
  const signature = req.headers["x-hub-signature-256"] as string;

  // Get raw body as string for signature validation
  const rawBody = (req as any).rawBody;

  if (!rawBody) {
    console.log("Raw body not available for signature validation.");
    res.status(400).send("Bad Request - Missing raw body");
    return;
  }

  // Validate the payload signature
  if (!validateSignature(rawBody, signature)) {
    console.log("Webhook signature validation failed");
    res.status(403).send("Forbidden - Invalid signature");
    return;
  }

  const body = req.body;
  console.log("Webhook event received:", body);

  // Parse the JSON body
  // let body;
  // try {
  //   body = JSON.parse(rawBody);
  // } catch (error) {
  //   console.log("Invalid JSON payload");
  //   res.status(400).send("Bad Request - Invalid JSON");
  //   return;
  // }

  console.log("Webhook event received:", body);

  // Check if the request is from a page or user subscription
  if (body.object === "page" || body.object === "user") {
    // Iterate through each entry in the body
    body.entry.forEach((entry: any) => {
      console.log("Processing entry:", {
        id: entry.id,
        uid: entry.uid,
        time: entry.time,
      });

      // Process each change in the entry
      entry.changes.forEach((change: any) => {
        console.log("Change detected:", change);

        // Handle specific field changes
        if (change.field === "photos") {
          console.log("Photo change:", {
            verb: change.value.verb,
            object_id: change.value.object_id,
          });
          // Handle photo updates here
        }

        // Here you can handle other change types, e.g., save to database, send notifications, etc.
      });
    });

    // Respond with '200 OK' to acknowledge receipt of the event
    res.status(200).send("EVENT_RECEIVED");
  } else {
    console.log("Received event for unsupported object type:");
    // Respond with '404 Not Found' if the object is not a page or user
    res.status(404).send("Not Found");
  }
});

// Function to validate Facebook webhook payload signature
// function validateSignature(payload: string, signature: string): boolean {
//   if (!signature) {
//     console.log("No signature provided");
//     return false;
//   }

//   // Remove 'sha256=' prefix from signature
//   const expectedSignature = signature.startsWith("sha256=")
//     ? signature.slice(7)
//     : signature;

//   // Generate SHA256 HMAC using the payload and app secret
//   const actualSignature = crypto
//     .createHmac("sha256", APP_SECRET)
//     .update(payload)
//     .digest("hex");

//   // Compare signatures using a constant-time comparison to prevent timing attacks
//   const expectedBuffer = Buffer.from(expectedSignature, "hex");
//   const actualBuffer = Buffer.from(actualSignature, "hex");

//   if (expectedBuffer.length !== actualBuffer.length) {
//     console.log("Signature length mismatch");
//     return false;
//   }

//   const isValid = crypto.timingSafeEqual(expectedBuffer, actualBuffer);

//   if (isValid) {
//     console.log("Payload signature validated successfully");
//   } else {
//     console.log("Payload signature validation failed");
//   }

//   return isValid;
// }

// Function to validate Facebook webhook payload signature
function validateSignature(payload: Buffer, signature: string): boolean {
  if (!signature) {
    console.log("No signature provided");
    return false;
  }

  const expectedSignature = signature.startsWith("sha256=")
    ? signature.slice(7)
    : signature;

  const hmac = crypto.createHmac("sha256", APP_SECRET);
  // Update HMAC with the buffer directly
  hmac.update(payload);
  const actualSignature = hmac.digest("hex");

  // ... (the rest of your validation logic is correct)
  const expectedBuffer = Buffer.from(expectedSignature, "hex");
  const actualBuffer = Buffer.from(actualSignature, "hex");

  if (expectedBuffer.length !== actualBuffer.length) {
    console.log("Signature length mismatch");
    return false;
  }

  const isValid = crypto.timingSafeEqual(expectedBuffer, actualBuffer);

  if (isValid) {
    console.log("Payload signature validated successfully");
  } else {
    console.log("Payload signature validation failed");
  }

  return isValid;
}

// Start the server
// app.listen(port, () => {
//   console.log(`[server]: Server is running at http://localhost:${port}`);
// });

export default app;
