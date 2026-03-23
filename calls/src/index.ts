import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { Command } from 'commander'
import fs from 'fs'
import path from 'path'
import https from 'https'
import chokidar, { FSWatcher } from 'chokidar'
import { createRequire } from 'module'

// Dynamic tool registry
import { initializeTools, getToolSchemas, getToolHandler } from "./tool-registry.js";

// local utils
import { runLocalServer, runSSELocalServer, runHTTPStreamableServer } from './servers.js'
import { checkTokenExpiration, generateToken } from './token/utils.js'
import { logger, logError, setLogLevel, setLogTransport } from './logger.js'
import * as utils from "./utils.js";

// Types
interface VoipnowConfig {
  voipnowUrl: string;
  voipnowToken: string;
  agent?: https.Agent;
}

interface MCPConfig {
  logLevel: string;
  voipnowHost: string;
  voipnowTokenFile: string;
  [key: string]: any;
}

// Configuration Manager Class
class ConfigurationManager {
  private mcpConfig: MCPConfig;
  private voipnowConfig: VoipnowConfig;
  private configPath: string;
  private watcher?: FSWatcher;

  constructor(configPath: string) {
    this.configPath = configPath;
    this.mcpConfig = this.loadConfig();
    // VoipNow config will be initialized asynchronously
    this.voipnowConfig = { voipnowUrl: '', voipnowToken: '' };
  }

  /**
   * Initialize VoipNow configuration asynchronously
   */
  async initialize(): Promise<void> {
    this.voipnowConfig = await this.createVoipnowConfig();
  }

  private loadConfig(): MCPConfig {
    if (!fs.existsSync(this.configPath)) {
      throw new Error(`Config file ${this.configPath} does not exist`);
    }
    const config = JSON.parse(fs.readFileSync(this.configPath, 'utf8'));

    // Normalize insecure flag to boolean
    if (config.insecure !== undefined) {
      config.insecure = config.insecure === true || config.insecure === 'true';
    }

    // Set default token file path if not specified
    if (!config.voipnowTokenFile) {
      config.voipnowTokenFile = path.join(path.dirname(this.configPath), '.access_token');
    }

    return config;
  }

  private extractTokenFromFile(tokenFile: string): string {
    try {
      const tokenData = fs.readFileSync(tokenFile, 'utf8').trim();

      // Handle empty or incomplete token file
      if (!tokenData) {
        throw new Error('Token file is empty');
      }

      const parts = tokenData.split(':');
      if (parts.length !== 3) {
        throw new Error(`Invalid token format: expected exactly 3 parts, got ${parts.length}`);
      }

      const [createdStr, expiresStr, token] = parts;

      // Validate timestamps are numeric
      const created = parseInt(createdStr, 10);
      const expires = parseInt(expiresStr, 10);

      if (isNaN(created) || isNaN(expires)) {
        throw new Error('Invalid timestamp format in token file');
      }

      if (created > expires) {
        throw new Error('Token created timestamp is after expiry timestamp');
      }

      if (expires < Date.now()) {
        throw new Error('Token has expired');
      }

      // Validate token is not empty and has reasonable length
      if (!token || token.length < 10) {
        throw new Error('Token is invalid or too short');
      }

      // Basic format validation - tokens should be alphanumeric with some special chars
      if (!/^[A-Za-z0-9_\-\.]+$/.test(token)) {
        throw new Error('Token contains invalid characters');
      }

      return token;
    } catch (error: any) {
      throw new Error(`Failed to extract token from file: ${error.message}`);
    }
  }

  private async createVoipnowConfig(): Promise<VoipnowConfig> {
    // Check if token file exists, if not generate it
    if (!fs.existsSync(this.mcpConfig.voipnowTokenFile)) {
      logger.info('Token file not found. Generating new token...');
      await generateToken(this.mcpConfig);
    }

    // Create HTTPS agent if insecure mode is enabled
    let agent: https.Agent | undefined;
    if (this.mcpConfig.insecure === true) {
      logger.warning('INSECURE MODE: SSL certificate verification is DISABLED. This is NOT RECOMMENDED for production!');
      agent = new https.Agent({
        rejectUnauthorized: false
      });
    }

    try {
      const token = this.extractTokenFromFile(this.mcpConfig.voipnowTokenFile);
      return {
        voipnowUrl: this.mcpConfig.voipnowHost,
        voipnowToken: token,
        agent,
      };
    } catch (error: any) {
      // If token extraction fails, try to regenerate and retry once
      logger.warning(`Failed to extract token (${error.message}), regenerating...`);
      await generateToken(this.mcpConfig);

      // Retry extraction after regeneration
      const token = this.extractTokenFromFile(this.mcpConfig.voipnowTokenFile);
      return {
        voipnowUrl: this.mcpConfig.voipnowHost,
        voipnowToken: token,
        agent,
      };
    }
  }

  async reload(): Promise<void> {
    logger.info('Reloading configuration...');
    const previousConfig = { ...this.mcpConfig };
    const previousVoipnowConfig = { ...this.voipnowConfig };
    
    try {
        this.mcpConfig = this.loadConfig();
        setLogLevel(this.mcpConfig.logLevel || 'info');
        await initializeTools("tools", logger);
        this.voipnowConfig = await this.createVoipnowConfig();
        logger.info('Configuration reloaded successfully.');
    } catch (error) {
        logger.error('Failed to reload configuration, reverting to previous:', error);
        this.mcpConfig = previousConfig;
        this.voipnowConfig = previousVoipnowConfig;
        setLogLevel(previousConfig.logLevel || 'info');
        throw error;
    }
  }

  private lastReloadTime: { [path: string]: number } = {};

  startWatching(onReload?: () => void): void {
    const filesToWatch = [this.mcpConfig.voipnowTokenFile, this.configPath];
    this.watcher = chokidar.watch(filesToWatch, { persistent: true });
    
    this.watcher.on('change', async (path: string) => {
      // Debounce rapid successive reloads (1 second)
      const currentTime = Date.now();
      if (this.lastReloadTime[path] && currentTime - this.lastReloadTime[path] < 1000) {
        return;
      }
      this.lastReloadTime[path] = currentTime;
      
      // Small delay to ensure file write is complete
      setTimeout(async () => {
        logger.info('Config or token file changed, reloading...');
        try {
          await this.reload();
          if (onReload) onReload();
        } catch (error: any) {
          // If token file is corrupted, try to regenerate it
          if (error.message.toLowerCase().includes('token')) {
            try {
              logger.warning(`Token error detected (${error.message}), attempting to regenerate token...`);
              await generateToken(this.mcpConfig);
              await this.reload();
              if (onReload) onReload();
              logger.info('Token regenerated and configuration reloaded successfully.');
              return;
            } catch (regenerateError: any) {
              logger.error(`Failed to regenerate token: ${regenerateError.message}`);
            }
          }
          
          logger.error(`Error reloading config, continuing with previous configuration: ${error.message}`);
        }
      }, 100);
    });
  }

  stopWatching(): void {
    if (this.watcher) {
      this.watcher.close();
    }
  }

  getMCPConfig(): MCPConfig {
    return this.mcpConfig;
  }

  getVoipnowConfig(): VoipnowConfig {
    return this.voipnowConfig;
  }
}

// Server Manager Class
class ServerManager {
  private server: Server;
  private userAgent: string;
  private configManager: ConfigurationManager;

  constructor(configManager: ConfigurationManager) {
    this.configManager = configManager;
    // Read version from package.json dynamically
    const require = createRequire(import.meta.url);
    const packageJson = require('../package.json');
    this.userAgent = `VoipNow Calls MCP/${packageJson.version}`;
    this.server = this.createServer();
    this.setupHandlers();
  }

  private createServer(): Server {
    return new Server(
      {
        name: "voipnow-calls",
        version: "5.7.0",
      },
      {
        capabilities: {
          tools: {},
        },
      },
    );
  }

  private setupHandlers(): void {
    // List tools handler
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: getToolSchemas(),
    }));

    // Call tool handler
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        const handler = getToolHandler(name);
        return await handler(args, this.userAgent, this.configManager.getVoipnowConfig(), logger);
      } catch (error) {
        if (error instanceof Error && error.message.includes('not found in registry')) {
          throw new Error(`Unknown tool: ${name}`);
        }
        throw error;
      }
    });
  }

  // Create and setup a new server instance (for multi-session support)
  createAndSetupServer(): Server {
    const newServer = this.createServer();
    // Setup handlers on the new server instance
    newServer.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: getToolSchemas(),
    }));

    newServer.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        const handler = getToolHandler(name);
        return await handler(args, this.userAgent, this.configManager.getVoipnowConfig(), logger);
      } catch (error) {
        if (error instanceof Error && error.message.includes('not found in registry')) {
          throw new Error(`Unknown tool: ${name}`);
        }
        throw error;
      }
    });

    return newServer;
  }

  async startServer(transport: string, port: string, address: string, secure: boolean, config: string): Promise<void> {
    if (transport === 'sse') {
      if (await this.checkPortAvailability(parseInt(port), address)) {
        await runSSELocalServer(this.server, { port, address, secure, config }, logger);
      }
    } else if (transport === 'streamable-http') {
      if (await this.checkPortAvailability(parseInt(port), address)) {
        // Pass server factory for multi-session support
        await runHTTPStreamableServer(() => this.createAndSetupServer(), { port, address, secure, config }, logger);
      }
    } else if (transport === 'stdio') {
      await runLocalServer(this.server, logger);
    } else {
      throw new Error('Invalid transport type. Use "sse", "streamable-http", or "stdio".');
    }
  }

  private async checkPortAvailability(port: number, address: string): Promise<boolean> {
    try {
      const isAvailable = await utils.checkPort(port, address);
      if (!isAvailable) {
        logError(`Port ${port} is already in use on address ${address}.`, "");
        return false;
      }
      return true;
    } catch (error) {
      logError(`Error checking port ${port} on address ${address}: ${error}`, "");
      return false;
    }
  }

  getServer(): Server {
    return this.server;
  }
}

// Validate and sanitize config file path
function validateConfigPath(configPath: string): string {
  // Normalize the input path to remove any unusual characters or patterns
  const normalizedPath = path.normalize(configPath);

  // Resolve to absolute path
  const absolutePath = path.resolve(normalizedPath);

  // Get the real path (resolving symlinks) and validate it's within allowed scope
  try {
    const realPath = fs.realpathSync(absolutePath);

    // Ensure the resolved path doesn't escape to parent directories unexpectedly
    // Allow configs from cwd or from a dedicated configs directory
    const allowedDirs = [
      path.resolve(process.cwd()),
      path.resolve(process.cwd(), 'configs'),
      path.resolve(process.cwd(), 'config'),
      path.resolve('/etc/mcp-voipnow-calls')  // System-wide config location
    ];

    const isWithinAllowedDir = allowedDirs.some(allowedDir => {
      // Check if realPath starts with one of the allowed directories
      return realPath.startsWith(allowedDir + path.sep) || realPath === allowedDir;
    });

    if (!isWithinAllowedDir) {
      throw new Error(`Config file must be within allowed directories: ${allowedDirs.join(', ')}`);
    }

    // Ensure file exists and is a regular file (not symlink, device, etc.)
    const stats = fs.lstatSync(realPath);
    if (!stats.isFile()) {
      throw new Error('Config path must be a regular file');
    }

    // Check file size (max 10MB)
    if (stats.size > 10 * 1024 * 1024) {
      throw new Error('Config file too large (max 10MB)');
    }

    // Verify file extension
    if (!realPath.endsWith('.json')) {
      logger.warning('Config file does not have .json extension');
    }

    return realPath;
  } catch (error: any) {
    throw new Error(`Invalid config file: ${error.message}`);
  }
}

// Command Line Interface
function parseCommandLine(): any {
  const program = new Command();
  program
    .option('-t, --transport <type>', 'Transport type (sse, streamable-http or stdio)', 'stdio')
    .option('-p, --port <number>', 'Port number for SSE transport', '3000')
    .option('-a, --address <string>', 'Address to listen on', 'localhost')
    .option('-s, --secure', 'Enable authentication', false)
    .option('-c, --config <path>', 'Path to configuration file')
    .option('-l, --log_transport <log_transport>', 'Type of log transport (console, syslog)', 'console')
    .parse(process.argv);
  
  const options = program.opts();

  if (!options.config) {
    console.error('Missing required option: --config <path> or -c <path> must be set');
    process.exit(1);
  }

  options.config = validateConfigPath(options.config);

  return options;
}

// Signal handling setup
function setupSignalHandlers(configManager: ConfigurationManager): void {
  if (process.platform !== 'win32') {
    process.on('SIGHUP', () => {
      logger.info('Received SIGHUP signal. Reloading configuration...');
      configManager.reload().catch(error => {
        logError('Error reloading configuration on SIGHUP:', error);
      });
    });
  }
}

// Main application function
async function main(): Promise<void> {
  try {
    // Parse command line arguments
    const options = parseCommandLine();
    process.stderr.write(`[DEBUG] Options parsed: transport=${options.transport}, port=${options.port}, address=${options.address}\n`);

    // Set log transport early
    setLogTransport(options.log_transport);

    // Initialize configuration manager
    const configManager = new ConfigurationManager(options.config);
    await configManager.initialize();
    const mcpConfig = configManager.getMCPConfig();
    process.stderr.write(`[DEBUG] Config loaded, tokenFile=${mcpConfig.voipnowTokenFile}\n`);

    // Set log level from config
    setLogLevel(mcpConfig.logLevel);

    // Perform configuration checks
    process.stderr.write(`[DEBUG] Running checks...\n`);
    await utils.checks(options, mcpConfig);
    process.stderr.write(`[DEBUG] Checks passed\n`);

    // Initialize dynamic tool registry
    process.stderr.write(`[DEBUG] Initializing tools...\n`);
    await initializeTools("tools", logger);
    process.stderr.write(`[DEBUG] Tools initialized\n`);

    // Create and setup server manager
    const serverManager = new ServerManager(configManager);

    // Start file watching for configuration changes
    configManager.startWatching();

    // Setup signal handlers for graceful reloading
    setupSignalHandlers(configManager);

    // Start token expiration checking (every 5 minutes)
    await checkTokenExpiration(mcpConfig, 300000, () => {
      logger.debug('Token is still valid.');
    });
    process.stderr.write(`[DEBUG] Token expiration check started\n`);

    // Start the MCP server
    process.stderr.write(`[DEBUG] Starting server on ${options.address}:${options.port}...\n`);
    await serverManager.startServer(options.transport, options.port, options.address, options.secure, options.config);

  } catch (error: any) {
    process.stderr.write(`[FATAL] ${error.message}\n${error.stack}\n`);
    logError('Fatal error in main application:', error);
    process.exit(1);
  }
}

// Application entry point
main().catch((error) => {
  logError('Unhandled error in main:', error);
  process.exit(1);
});
