import * as config from "../config.json";
import cookieParser from "cookie-parser";
import express, { Request, Response } from "express";
import proxy from "express-http-proxy";
import fs from "fs/promises";
import path from "path";

const app = express();
app.use(cookieParser());

app.use("/cdn", proxy(config.CDN_ENDPOINT));

async function failMasqr(req: Request, res: Response) {
  res.send(
    await fs.readFile(path.join(__dirname, config.FAILURE_FILE), "utf8")
  );
}

app.use(async (req, res, next) => {
  if (req.headers.host && config.WHITELIST.includes(req.headers.host)) {
    next();
    return;
  }

  if (/^\/cdn\//.test(req.url)) {
    next();
    return;
  }

  if (req.cookies["authcheck"]) {
    next();
    return;
  }

  if (req.cookies["refreshcheck"] != "true") {
    res.cookie("refreshcheck", "true", { maxAge: 10000 });
    failMasqr(req, res);
    return;
  }

  const authheader = req.headers.authorization;

  if (!authheader) {
    res.setHeader("WWW-Authenticate", "Basic");
    res.status(401);
    failMasqr(req, res);
    return;
  }

  const auth = Buffer.from(authheader.split(" ")[1], "base64")
    .toString()
    .split(":");
  const pass = auth[1];

  const authCheck = await fetch(
    config.LICENSE_SERVER_URL + pass + "&host=" + req.headers.host
  );

  const authResponse = await authCheck.json();

  console.log(authResponse);

  const licenseCheck = authResponse["status"];

  if (licenseCheck == "License valid") {
    res.cookie("authcheck", "true", {
      expires: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
    });
    res.send("<script>window.location.href=window.location.href</script>");
    return;
  }

  failMasqr(req, res);
});

app.use(express.static(config.STATIC_PATH));

app.listen(config.PORT, () => {
  console.log(`Backend is running on port ${config.PORT}`);
});
