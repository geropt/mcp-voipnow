import { Request, Response, NextFunction } from 'express';
import * as fs from 'fs';
import { Logger } from 'winston';

/**
 * Authentication module for MCP VoipNow Calls server.
 *
 * SECURITY NOTES:
 * - Tokens are stored in memory as plain text for performance
 * - In a production environment with high security requirements, consider:
 *   1. Using a secure vault service (HashiCorp Vault, AWS Secrets Manager)
 *   2. Implementing memory encryption for sensitive data
 *   3. Ensuring tokens have short TTL and are rotated frequently
 * - Never log authentication tokens
 * - Config files containing tokens should have restrictive permissions (0600)
 */

// Authentication constants
const AUTH_CONFIG = {
  TYPE: 'bearer',
  SCHEME_LENGTHS: {
    basic: 6,
    bearer: 7,
  },
} as const;

// HTTP response constants
const HTTP_STATUS = {
  UNAUTHORIZED: 401,
} as const;

// Error messages
const ERROR_MESSAGES = {
  MISSING_HEADER: 'Authorization header is missing',
  INVALID_HEADER: 'Invalid Authorization header',
  EMPTY_TOKEN: 'Token is empty',
  INVALID_TOKEN: 'Invalid token',
  TOKEN_NOT_FOUND: 'AUTH Token not found in .config file',
  UNAUTHORIZED_RESPONSE: 'Unauthorized',
} as const;

// Cache for config file to avoid reading on every request
interface ConfigCache {
  token: string;
  path: string;
  mtime: number;
}

let configCache: ConfigCache | null = null;

// Rate limiting for failed authentication attempts
interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const failedAttempts = new Map<string, RateLimitEntry>();
const RATE_LIMIT_MAX_ATTEMPTS = 5;
const RATE_LIMIT_WINDOW_MS = 300000; // 5 minutes

function getStoredToken(logger: Logger, configMCPPath: string): string {
    try {
        // Check if cache is valid
        const stats = fs.statSync(configMCPPath);
        const currentMtime = stats.mtimeMs;

        if (configCache && configCache.path === configMCPPath && configCache.mtime === currentMtime) {
            return configCache.token;
        }

        // Read and cache (env var takes precedence over config file)
        const configMCP = JSON.parse(fs.readFileSync(configMCPPath, 'utf-8'));
        const authToken = process.env.VOIPNOW_AUTH_TOKEN || configMCP.authTokenMCP;
        if (!authToken) {
            logger.error(ERROR_MESSAGES.TOKEN_NOT_FOUND);
            throw new Error(ERROR_MESSAGES.TOKEN_NOT_FOUND);
        }

        configCache = {
            token: authToken,
            path: configMCPPath,
            mtime: currentMtime
        };

        return authToken;
    } catch (error: any) {
        // Clear cache on error
        configCache = null;
        throw error;
    }
}

/**
 * User-defined function to validate the token
 * @param token - The token extracted from the Authorization header
 * @returns boolean - True if valid, false otherwise
 */
function isValidToken(token: string, logger: Logger, configMCPPath: string): boolean {
    if (token === getStoredToken(logger, configMCPPath)) {
        return true;
    }
    logger.error(ERROR_MESSAGES.INVALID_TOKEN);
    return false;
}

/**
 * Basic authentication middleware with rate limiting
 */
export const createBasicAuth = (logger: Logger, configMCPPath: string) => {
    return (req: Request, res: Response, next: NextFunction): void => {
        // Get client identifier (IP address)
        const clientId = req.ip || req.socket.remoteAddress || 'unknown';
        const now = Date.now();

        // Check rate limit
        const attempts = failedAttempts.get(clientId);
        if (attempts) {
            if (now < attempts.resetAt) {
                if (attempts.count >= RATE_LIMIT_MAX_ATTEMPTS) {
                    logger.warning(`Rate limit exceeded for ${clientId}`);
                    res.status(429).send('Too many authentication attempts. Please try again later.');
                    return;
                }
            } else {
                // Reset window expired, remove entry
                failedAttempts.delete(clientId);
            }
        }

        const authHeader = req.headers.authorization;

        // Check if Authorization header is missing
        if (!authHeader) {
            logger.error(ERROR_MESSAGES.MISSING_HEADER);
            res.status(HTTP_STATUS.UNAUTHORIZED).send(ERROR_MESSAGES.UNAUTHORIZED_RESPONSE);
            return;
        }

        const authHeaderLower = authHeader.toLowerCase();
        const requiredLength = AUTH_CONFIG.SCHEME_LENGTHS[AUTH_CONFIG.TYPE];

        // Validate scheme is "Bearer" (case-insensitive)
        if (authHeaderLower.length < requiredLength || authHeaderLower.substring(0, requiredLength) !== `${AUTH_CONFIG.TYPE} `) {
            logger.error(ERROR_MESSAGES.INVALID_HEADER);
            res.status(HTTP_STATUS.UNAUTHORIZED).send(ERROR_MESSAGES.UNAUTHORIZED_RESPONSE);
            return;
        }

        // Extract the token part after "Bearer "
        const token = authHeader.substring(requiredLength).trim();

        // Ensure token is not empty
        if (!token) {
            logger.error(ERROR_MESSAGES.EMPTY_TOKEN);
            res.status(HTTP_STATUS.UNAUTHORIZED).send(ERROR_MESSAGES.UNAUTHORIZED_RESPONSE);
            return;
        }

        // Validate the token
        if (isValidToken(token, logger, configMCPPath)) {
            // Clear failed attempts on success
            failedAttempts.delete(clientId);
            logger.debug('Authentication successful');
            next();
        } else {
            // Record failed attempt
            const current = failedAttempts.get(clientId) || {
                count: 0,
                resetAt: now + RATE_LIMIT_WINDOW_MS
            };
            current.count++;
            failedAttempts.set(clientId, current);

            // Log error without exposing token value
            logger.error(ERROR_MESSAGES.INVALID_TOKEN);
            res.status(HTTP_STATUS.UNAUTHORIZED).send(ERROR_MESSAGES.UNAUTHORIZED_RESPONSE);
        }
    };
};