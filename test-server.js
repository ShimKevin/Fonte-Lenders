const http = require('http');
http.createServer((req, res) => {
  res.end('Test server working');
}).listen(3000, '0.0.0.0', () => {
  console.log('Test server running on port 3000');
});