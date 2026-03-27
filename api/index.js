import { neon } from '@neondatabase/serverless';
import { createHmac } from 'crypto';

const sql = neon(process.env.DATABASE_URL);

function sign(device_id, is_banned) {
    const secret = process.env.SIGN_KEY;
    return createHmac('sha256', secret)
        .update(device_id + '|' + is_banned)
        .digest('hex');
}

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-admin-key');

    if (req.method === 'OPTIONS') return res.status(200).end();

    res.setHeader('Content-Type', 'application/json');

    const action       = req.method === 'POST' ? req.body?.action    : req.query?.action;
    const device_id    = req.method === 'POST' ? req.body?.device_id : req.query?.device_id;
    const install_time = req.body?.install_time ?? null;

    if (!device_id && !['admin_list', 'stats'].includes(action)) {
        return res.status(400).json({ status: 'error', msg: 'missing device_id' });
    }

    try {
        if (action === 'register') {
            await sql`
                INSERT INTO users (device_id, install_time)
                VALUES (${device_id}, ${install_time})
                ON CONFLICT (device_id) DO NOTHING
            `;
            // 更新最后活跃时间
            await sql`
                UPDATE users SET last_seen = NOW() WHERE device_id = ${device_id}
            `;
            const rows = await sql`
                SELECT is_banned, ban_reason FROM users WHERE device_id = ${device_id}
            `;
            const user = rows[0];
            return res.json({
                status:     'ok',
                is_banned:  user.is_banned,
                ban_reason: user.ban_reason ?? '',
                sign:       sign(device_id, user.is_banned)
            });

        } else if (action === 'check') {
            // 每次check都更新最后活跃时间（用于在线统计）
            await sql`
                UPDATE users SET last_seen = NOW() WHERE device_id = ${device_id}
            `;
            const rows = await sql`
                SELECT is_banned, ban_reason FROM users WHERE device_id = ${device_id}
            `;
            if (rows.length === 0) return res.json({ status: 'not_found' });
            const user = rows[0];
            return res.json({
                status:     'ok',
                is_banned:  user.is_banned,
                ban_reason: user.ban_reason ?? '',
                sign:       sign(device_id, user.is_banned)
            });

        } else if (action === 'heartbeat') {
            // App定期心跳，保持在线状态
            await sql`
                UPDATE users SET last_seen = NOW() WHERE device_id = ${device_id}
            `;
            return res.json({ status: 'ok' });

        } else if (action === 'stats') {
            // 统计数据，无需管理员权限
            const total  = await sql`SELECT COUNT(*) as c FROM users WHERE is_banned = false`;
            // 5分钟内有心跳视为在线
            const online = await sql`
                SELECT COUNT(*) as c FROM users 
                WHERE last_seen > NOW() - INTERVAL '5 minutes' AND is_banned = false
            `;
            return res.json({
                status:       'ok',
                total_users:  parseInt(total[0].c),
                online_users: parseInt(online[0].c)
            });

        } else if (action === 'admin_list') {
            const key = req.headers['x-admin-key'];
            if (key !== process.env.ADMIN_KEY) return res.status(403).json({ status: 'forbidden' });
            const rows = await sql`SELECT * FROM users ORDER BY first_seen DESC`;
            const total  = await sql`SELECT COUNT(*) as c FROM users WHERE is_banned = false`;
            const online = await sql`
                SELECT COUNT(*) as c FROM users 
                WHERE last_seen > NOW() - INTERVAL '5 minutes' AND is_banned = false
            `;
            return res.json({
                status:       'ok',
                users:        rows,
                total_users:  parseInt(total[0].c),
                online_users: parseInt(online[0].c)
            });

        } else if (action === 'ban' || action === 'unban') {
            const key = req.headers['x-admin-key'];
            if (key !== process.env.ADMIN_KEY) return res.status(403).json({ status: 'forbidden' });
            const reason = req.body?.reason ?? null;
            if (action === 'ban') {
                await sql`UPDATE users SET is_banned=true, ban_reason=${reason} WHERE device_id=${device_id}`;
            } else {
                await sql`UPDATE users SET is_banned=false, ban_reason=null WHERE device_id=${device_id}`;
            }
            return res.json({ status: 'ok' });

        } else {
            return res.status(400).json({ status: 'error', msg: 'unknown action' });
        }

    } catch (e) {
        return res.status(500).json({ status: 'error', msg: e.message });
    }
}
