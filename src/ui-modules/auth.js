import { existsSync } from 'fs';
import { promises as fs } from 'fs';
import path from 'path';
import crypto from 'crypto';

// Token存储到本地文件中
const TOKEN_STORE_FILE = path.join(process.cwd(), 'configs', 'token-store.json');

/**
 * 默认密码（当pwd文件不存在时使用）
 */
const DEFAULT_PASSWORD = 'admin123';

/**
 * 读取密码文件内容
 * 优先顺序:
 * 1. 环境变量 REQUIRED_API_KEY
 * 2. configs/pwd 文件内容
 * 3. 默认密码 'admin123'
 */
export async function readPasswordFile() {
    // 1. Check Environment Variable
    if (process.env.REQUIRED_API_KEY) {
        // console.log('[Auth] Using password from environment variable REQUIRED_API_KEY');
        return process.env.REQUIRED_API_KEY;
    }

    // 2. Check File
    const pwdFilePath = path.join(process.cwd(), 'configs', 'pwd');
    try {
        const password = await fs.readFile(pwdFilePath, 'utf8');
        const trimmedPassword = password.trim();
        if (trimmedPassword) {
            // console.log('[Auth] Using password from file');
            return trimmedPassword;
        }
    } catch (error) {
        // Ignore file read errors
    }

    // 3. Fallback
    console.log('[Auth] No password configured, using default: ' + DEFAULT_PASSWORD);
    return DEFAULT_PASSWORD;
}

/**
 * 验证登录凭据
 */
export async function validateCredentials(password) {
    const storedPassword = await readPasswordFile();
    const isValid = storedPassword && password === storedPassword;
    if (!isValid) {
        console.warn('[Auth] Login failed: Invalid password');
    }
    return isValid;
}

/**
 * 解析请求体JSON
 */
function parseRequestBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            try {
                if (!body.trim()) {
                    resolve({});
                } else {
                    resolve(JSON.parse(body));
                }
            } catch (error) {
                reject(new Error('Invalid JSON format'));
            }
        });
        req.on('error', reject);
    });
}

/**
 * 生成简单的token
 */
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

/**
 * 生成token过期时间
 */
function getExpiryTime() {
    const now = Date.now();
    const expiry = 60 * 60 * 1000; // 1小时
    return now + expiry;
}

/**
 * 读取token存储文件
 */
async function readTokenStore() {
    try {
        if (existsSync(TOKEN_STORE_FILE)) {
            const content = await fs.readFile(TOKEN_STORE_FILE, 'utf8');
            return JSON.parse(content);
        } else {
            // 如果文件不存在，创建一个默认的token store
            await writeTokenStore({ tokens: {} });
            return { tokens: {} };
        }
    } catch (error) {
        console.error('[Token Store] Failed to read token store file:', error);
        return { tokens: {} };
    }
}

/**
 * 写入token存储文件
 */
async function writeTokenStore(tokenStore) {
    try {
        await fs.writeFile(TOKEN_STORE_FILE, JSON.stringify(tokenStore, null, 2), 'utf8');
    } catch (error) {
        console.error('[Token Store] Failed to write token store file:', error);
    }
}

/**
 * 验证简单token
 */
export async function verifyToken(token) {
    const tokenStore = await readTokenStore();
    const tokenInfo = tokenStore.tokens[token];
    if (!tokenInfo) {
        return null;
    }

    // 检查是否过期
    if (Date.now() > tokenInfo.expiryTime) {
        await deleteToken(token);
        return null;
    }

    return tokenInfo;
}

/**
 * 保存token到本地文件
 */
async function saveToken(token, tokenInfo) {
    const tokenStore = await readTokenStore();
    tokenStore.tokens[token] = tokenInfo;
    await writeTokenStore(tokenStore);
}

/**
 * 删除token
 */
async function deleteToken(token) {
    const tokenStore = await readTokenStore();
    if (tokenStore.tokens[token]) {
        delete tokenStore.tokens[token];
        await writeTokenStore(tokenStore);
    }
}

/**
 * 清理过期的token
 */
export async function cleanupExpiredTokens() {
    const tokenStore = await readTokenStore();
    const now = Date.now();
    let hasChanges = false;

    for (const token in tokenStore.tokens) {
        if (now > tokenStore.tokens[token].expiryTime) {
            delete tokenStore.tokens[token];
            hasChanges = true;
        }
    }

    if (hasChanges) {
        await writeTokenStore(tokenStore);
    }
}

/**
 * 检查token验证
 */
export async function checkAuth(req) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // console.warn('[Auth] debug: Missing or invalid Authorization header');
        return false;
    }

    const token = authHeader.substring(7);
    const tokenInfo = await verifyToken(token);

    if (tokenInfo === null) {
        console.warn(`[Auth] Token validation failed. Token=${token.substring(0, 6)}...`);
    }

    return tokenInfo !== null;
}

/**
 * 处理登录请求
 */
export async function handleLoginRequest(req, res) {
    if (req.method !== 'POST') {
        res.writeHead(405, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, message: 'Only POST requests are supported' }));
        return true;
    }

    try {
        const requestData = await parseRequestBody(req);
        const { password } = requestData;

        if (!password) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Password cannot be empty' }));
            return true;
        }

        const isValid = await validateCredentials(password);

        if (isValid) {
            // Generate simple token
            const token = generateToken();
            const expiryTime = getExpiryTime();

            // Store token info to local file
            await saveToken(token, {
                username: 'admin',
                loginTime: Date.now(),
                expiryTime
            });

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                message: 'Login successful',
                token,
                expiresIn: '1 hour'
            }));
        } else {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: false,
                message: 'Incorrect password, please try again'
            }));
        }
    } catch (error) {
        console.error('[Auth] Login processing error:', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            success: false,
            message: error.message || 'Server error'
        }));
    }
    return true;
}

// 定时清理过期token
setInterval(cleanupExpiredTokens, 5 * 60 * 1000); // 每5分钟清理一次