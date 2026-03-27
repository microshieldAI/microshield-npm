const http = require("http");

let calls = 0;

const server = http.createServer((req, res) => {
  if (req.method === "POST" && req.url === "/predict") {
    calls += 1;
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      console.log("AI_CALL", calls);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ score: 0.92, risk: "high" }));
    });
    return;
  }

  if (req.method === "GET" && req.url === "/stats") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ calls }));
    return;
  }

  res.writeHead(404);
  res.end();
});

server.listen(8000, () => {
  console.log("MOCK_AI_READY");
});
