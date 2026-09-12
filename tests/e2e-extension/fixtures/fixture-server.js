/**
 * Static fixture-page server on an ephemeral port.
 *
 * Serves files from fixtures/pages/ over plain HTTP. The hostname in tests is
 * always "localhost:<port>" — never 127.0.0.1 — because the extension's IP
 * heuristic (f17) boosts hostnames that look like raw IPs, and the service
 * worker's ip_rule path only fires for public IPv4 literals. "localhost"
 * scores clean on both, keeping ML output the only nondeterministic input.
 */
const http = require("http");
const fs = require("fs");
const path = require("path");

const PAGES_DIR = path.join(__dirname, "pages");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".png": "image/png",
  ".json": "application/json",
};

function startFixtureServer() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      // Strip query string; default to index of the fixture set.
      const urlPath = decodeURIComponent(req.url.split("?")[0]);
      const rel = urlPath === "/" ? "benign.html" : urlPath.replace(/^\/+/, "");
      const filePath = path.normalize(path.join(PAGES_DIR, rel));

      // Path-traversal guard: everything must resolve inside pages/
      if (!filePath.startsWith(PAGES_DIR)) {
        res.writeHead(403).end("Forbidden");
        return;
      }

      fs.readFile(filePath, (err, data) => {
        if (err) {
          res.writeHead(404).end("Not found");
          return;
        }
        const ext = path.extname(filePath).toLowerCase();
        res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream" });
        res.end(data);
      });
    });

    // Port 0 → OS-assigned ephemeral port
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      resolve({
        port,
        url: `http://localhost:${port}`,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

module.exports = { startFixtureServer };
